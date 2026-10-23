"""Deterministic whole-population stratification for secondary exploration."""
from .data_access import sql_literal

def create_sample(connection,output_path,size=250000,seed=5872026):
    counts=dict(connection.execute('SELECT package_manager,count(*) FROM associations GROUP BY 1 ORDER BY 1').fetchall())
    target=min(size,sum(counts.values()))
    quotas={key:0 for key in counts}
    remaining=target
    while remaining:
        eligible=[key for key in counts if quotas[key]<counts[key]]
        share=max(1,remaining//len(eligible))
        for key in eligible:
            add=min(share,counts[key]-quotas[key],remaining)
            quotas[key]+=add
            remaining-=add
            if not remaining: break
    connection.execute('CREATE OR REPLACE TEMP TABLE sample_quotas(package_manager VARCHAR,population_count BIGINT,sample_count BIGINT)')
    connection.executemany('INSERT INTO sample_quotas VALUES (?,?,?)',[(key,counts[key],quotas[key]) for key in counts])
    connection.execute(f"""CREATE OR REPLACE TABLE exploration_sample AS
      SELECT a.*,q.sample_count::DOUBLE/q.population_count inclusion_probability,
        q.population_count::DOUBLE/q.sample_count sampling_weight
      FROM (SELECT *,row_number() OVER(PARTITION BY package_manager
        ORDER BY sha256(concat(representative_raw_record_hash,{sql_literal(seed)})),representative_raw_record_hash) sample_rank
        FROM associations) a JOIN sample_quotas q USING(package_manager)
      WHERE a.sample_rank<=q.sample_count""")
    connection.execute(f"COPY exploration_sample TO {sql_literal(output_path)} (FORMAT PARQUET,COMPRESSION ZSTD)")
    fingerprint=connection.execute("SELECT sha256(string_agg(representative_raw_record_hash,'' ORDER BY representative_raw_record_hash)) FROM exploration_sample").fetchone()[0]
    return {'seed':seed,'method':'whole-population stable SHA256 ranking by ecosystem; balanced allocation with small strata censused',
      'population':'full cleaned normalized payload rows','sample_rows':target,'counts':counts,'quotas':quotas,'fingerprint':fingerprint,
      'used_for_primary_results':False,'warning':'Balanced sample is not self-weighting. Use sampling_weight for association-population estimates.'}
