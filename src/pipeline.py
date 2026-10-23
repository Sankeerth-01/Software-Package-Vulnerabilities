"""Validate, profile, clean, sample and analyze with one documented entry point."""
import argparse
import importlib.metadata
import logging
import os
import platform
import shutil
import sys
import threading
import time
from pathlib import Path

import duckdb
import psutil
import yaml

from .data_access import SOURCE_COLUMNS,file_manifest,portable_path,sql_literal,write_json
from .data_cleaning import clean
from .data_sampling import create_sample

def rows(connection,query):
    cursor=connection.execute(query)
    return [dict(zip([item[0] for item in cursor.description],record)) for record in cursor.fetchall()]

def profile(connection):
    total=connection.execute('SELECT count(*) FROM raw_rows').fetchone()[0]
    columns={}
    for column in SOURCE_COLUMNS:
        value=connection.execute(f"""SELECT count(DISTINCT {column}),count(*) FILTER(WHERE {column} IS NULL),
          count(*) FILTER(WHERE {column} IS NOT NULL AND trim({column})=''),min(length({column})),
          quantile_cont(length({column}),.5),max(length({column})),
          count(*) FILTER(WHERE contains({column},chr(65533))) FROM raw_rows""").fetchone()
        columns[column]=dict(zip(['exact_distinct_nonnull','null_rows','whitespace_only_rows','min_characters',
          'median_characters','max_characters','unicode_replacement_character_rows'],value))
        columns[column].update({'storage_type':'VARCHAR','missing_rate_denominator':total,
          'subgroup_missingness':rows(connection,f"SELECT package_manager,count(*) AS row_count,count(*) FILTER(WHERE {column} IS NULL OR trim({column})='') missing FROM raw_rows GROUP BY 1 ORDER BY 1")})
    columns['vuln_impact']['numeric_parse_failures_nonmissing']=connection.execute("SELECT count(*) FROM raw_rows WHERE nullif(trim(vuln_impact),'') IS NOT NULL AND try_cast(vuln_impact AS DOUBLE) IS NULL").fetchone()[0]
    return {'rows':total,'parse_errors':0,'parse_method':'Strict DuckDB CSV reader; ignore_errors=false, malformed rows abort the run',
      'cardinality_method':'exact COUNT(DISTINCT), disk-based DuckDB with bounded memory; no approximate estimates',
      'columns':columns,'ecosystems':rows(connection,'SELECT package_manager,count(*) AS row_count FROM raw_rows GROUP BY 1 ORDER BY 1'),
      'raw_payload_distinct':connection.execute('SELECT count(*) FROM (SELECT DISTINCT '+','.join(SOURCE_COLUMNS)+' FROM raw_rows)').fetchone()[0]}

def failed_strategies(connection,results):
    prefix=dict(connection.execute('SELECT lower(trim(package_manager)),count(*) FROM (SELECT * FROM raw_rows ORDER BY source_row LIMIT 250000) GROUP BY 1').fetchall())
    full=dict(connection.execute('SELECT lower(trim(package_manager)),count(*) FROM raw_rows GROUP BY 1').fetchall())
    deviations={key:{'full_share':value/sum(full.values()),'prefix_share':prefix.get(key,0)/sum(prefix.values()),
      'absolute_percentage_point_difference':100*abs(value/sum(full.values())-prefix.get(key,0)/sum(prefix.values()))} for key,value in full.items()}
    conflicts=connection.execute('SELECT count(*) FROM (SELECT association_key_hash FROM associations GROUP BY 1 HAVING count(*)>1)').fetchone()[0]
    repeat=connection.execute('SELECT count(*) FROM (SELECT package_manager,package_name,version_name,vuln_id,count(*) n FROM raw_rows GROUP BY 1,2,3,4 HAVING n>1)').fetchone()[0]
    result=[{'id':'D1','approach':'Use first 250000 source records as representative coverage',
      'actual_attempt':'SQL prefix sample and full-export ecosystem shares computed','evidence':deviations,
      'outcome':'rejected' if max(v['absolute_percentage_point_difference'] for v in deviations.values())>1 else 'not rejected by ecosystem comparison; not a demonstrated dead end',
      'lesson':'Source ordering can concentrate ecosystems. Use whole-population stratification or full-data analysis.'},
      {'id':'D2','approach':'Use one advisory ID as one independent association row',
      'actual_attempt':'Compare raw rows with exact advisory cardinality; count advisories spanning multiple versions',
      'raw_rows':connection.execute('SELECT count(*) FROM raw_rows').fetchone()[0],
      'distinct_advisory_ids':connection.execute('SELECT count(DISTINCT vuln_id) FROM raw_rows').fetchone()[0],
      'advisories_affecting_multiple_versions':connection.execute('SELECT count(*) FROM (SELECT vuln_id FROM associations GROUP BY 1 HAVING count(DISTINCT version_key_hash)>1)').fetchone()[0],
      'outcome':'rejected','lesson':'Advisory-only deduplication discards legitimate affected-version relationships; separate entity and association summaries.'},
      {'id':'key_diagnostic','approach':'Assume ecosystem/package/version/advisory is payload-unique',
      'repeated_raw_key_groups':repeat,'conflicting_clean_key_groups':conflicts,
      'outcome':'rejected' if conflicts else 'No conflicting payload observed; repeated exact records still reconciled'}]
    write_json(results/'attempted_strategies.json',result)

def run(config_path):
    started=time.perf_counter()
    root=Path(__file__).resolve().parents[1]
    config=yaml.safe_load(Path(config_path).resolve().read_text(encoding='utf-8'))
    resolve=lambda key:(root/config[key]).resolve()
    output,results,sample=resolve('output_dir'),resolve('results_dir'),resolve('sample_dir')
    for path in (output,results,sample):
        if path.is_file() and path.stat().st_size<=10: path.unlink()
        path.mkdir(parents=True,exist_ok=True)
    write_json(results/'runtime.json',{'completed':False,'status':'running','note':'A previous successful run is not evidence that this invocation completed.'})
    logging.basicConfig(level=logging.INFO,format='%(asctime)s %(levelname)s %(message)s',
      handlers=[logging.StreamHandler(),logging.FileHandler(results/'pipeline.log',mode='w',encoding='utf-8')])
    usage=psutil.virtual_memory()
    disk=shutil.disk_usage(root)
    process=psutil.Process()
    peak=[process.memory_info().rss]
    stop=threading.Event()
    def monitor():
        while not stop.wait(.1): peak[0]=max(peak[0],process.memory_info().rss)
    watcher=threading.Thread(target=monitor,daemon=True); watcher.start()
    stages={}
    source=resolve('input_csv')
    manifest=file_manifest(source)
    manifest.update({'source':'Zenodo 10.5281/zenodo.15432733, user-supplied extracted CSV',
      'source_relative_to_repository':portable_path(source,root),
      'source_path_convention':'Relative inside the repository; absolute for external inputs, including other Windows drives.',
      'archive_size_bytes':None,
      'archive_size_status':'Original compressed archive absent; no measured archive-size claim'})
    write_json(results/'input_manifest.json',manifest)
    logging.info('Validated input %s bytes; SHA256 %s',manifest['bytes'],manifest['sha256'])
    con=duckdb.connect(str(resolve('database')))
    con.execute(f"SET memory_limit={sql_literal(config.get('memory_limit','768MB'))}")
    con.execute(f"SET threads={int(config.get('threads',2))}")
    con.execute('SET preserve_insertion_order=false')
    temp=output/'duckdb_spill'; temp.mkdir(exist_ok=True)
    con.execute(f'SET temp_directory={sql_literal(temp)}')
    stage=time.perf_counter()
    con.execute(f"CREATE OR REPLACE TABLE raw_rows AS SELECT row_number() OVER() source_row,* FROM read_csv({sql_literal(source)},header=true,all_varchar=true,parallel=false,strict_mode=true,ignore_errors=false)")
    actual=[row[0] for row in con.execute('DESCRIBE raw_rows').fetchall()][1:]
    if actual!=SOURCE_COLUMNS: raise ValueError(f'Expected {SOURCE_COLUMNS}; observed {actual}')
    stages['load_seconds']=time.perf_counter()-stage
    stage=time.perf_counter(); write_json(results/'profiling.json',profile(con)); stages['profile_seconds']=time.perf_counter()-stage
    logging.info('Exact profile complete')
    stage=time.perf_counter(); write_json(results/'cleaning.json',clean(con,output)); stages['clean_seconds']=time.perf_counter()-stage
    stage=time.perf_counter()
    write_json(results/'sampling.json',create_sample(con,sample/'exploration_sample.parquet',int(config.get('sample_size',250000)),int(config.get('seed',5872026))))
    stages['sample_seconds']=time.perf_counter()-stage
    failed_strategies(con,results)
    write_json(output/'schema.json',{'schema_version':1,
      'grain':'Distinct normalized full payload; ecosystem/package/version/advisory repeats only when payload_conflict is flagged',
      'source_sha256':manifest['sha256'],
      'columns':rows(con,"SELECT column_name,data_type FROM information_schema.columns WHERE table_name='associations' ORDER BY ordinal_position"),
      'severity':'Zero retained separately; 0<score<4 Low;4<=score<7 Medium;7<=score<9 High;9<=score<=10 Critical. Descriptive bins do not validate CVSS version/source.',
      'keys':'SHA256 of JSON structs; original components retained for transparent joins; aliases unresolved'})
    reload_count=con.execute(f"SELECT count(*) FROM read_parquet({sql_literal(output/'associations.parquet')})").fetchone()[0]
    expected=con.execute('SELECT count(*) FROM associations').fetchone()[0]
    assert reload_count==expected
    con.execute('CHECKPOINT'); con.close()
    if config.get('run_analytics',True):
        stage=time.perf_counter()
        from .analytics import run_analytics
        figure_output=(root/config.get('figures_dir','figures')).resolve()
        run_analytics(root,output/'associations.parquet',results_dir=results,figures_dir=figure_output)
        stages['analytics_seconds']=time.perf_counter()-stage
    stop.set(); watcher.join()
    runtime={'completed':True,'elapsed_wall_seconds':time.perf_counter()-started,'stages_seconds':stages,
      'peak_process_rss_bytes_sampled_100ms':peak[0],'memory_limit':config.get('memory_limit','768MB'),
      'total_ram_bytes':usage.total,'available_ram_at_start_bytes':usage.available,'logical_cpus':os.cpu_count(),
      'disk_free_at_start_bytes':disk.free,'platform':platform.platform(),'python':sys.version,
      'versions':{name:importlib.metadata.version(name) for name in ['duckdb','PyYAML','psutil']},
      'processed_reload_row_count':reload_count,'processed_reload_pass':reload_count==expected,
      'outputs':[{'path':portable_path(path,root),'bytes':path.stat().st_size,'sha256':file_manifest(path)['sha256']}
        for path in [output/'associations.parquet',output/'quarantine.parquet',sample/'exploration_sample.parquet']],
      'memory_measurement_note':'Process RSS sampled every100ms; excludes other processes, can miss shorter peaks. DuckDB memory_limit is not a total-process memory cap.'}
    write_json(results/'runtime.json',runtime)
    logging.info('Pipeline complete in %.2fs; sampled peak RSS %.1fMiB',runtime['elapsed_wall_seconds'],peak[0]/1024**2)
    return runtime

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config',type=Path,default=Path('config/phase2.yaml'))
    args=parser.parse_args()
    try: run(args.config)
    except Exception:
        logging.exception('Pipeline failed; check input path, free disk and configured memory. No success statement was written for this run.')
        raise

if __name__=='__main__': main()
