from .data_access import sql_literal

IDENTIFIER_COLUMNS=['package_name','package_manager','version_name','vuln_id']

def prepare_clean_input(connection):
    connection.execute("""
    CREATE OR REPLACE TABLE normalized AS
    WITH trimmed AS (
      SELECT source_row,trim(package_name) package_name,lower(trim(package_manager)) package_manager,
        trim(version_name) version_name,trim(vuln_id) vuln_id,vuln_impact vuln_impact_raw,
        replace(replace(vuln_description,chr(13)||chr(10),chr(10)),chr(13),chr(10)) vuln_description,
        try_cast(nullif(trim(vuln_impact),'') AS DOUBLE) parsed_score,
        sha256(to_json(struct_pack(package_name:=package_name,package_manager:=package_manager,
          version_name:=version_name,vuln_id:=vuln_id,vuln_impact:=vuln_impact,
          vuln_description:=vuln_description))) raw_record_hash
      FROM raw_rows
    ), classified AS (
      SELECT *, CASE WHEN vuln_impact_raw IS NULL OR trim(vuln_impact_raw)='' THEN 'missing'
        WHEN parsed_score IS NULL OR NOT isfinite(parsed_score) THEN 'invalid_numeric'
        WHEN parsed_score<0 OR parsed_score>10 THEN 'out_of_range'
        WHEN parsed_score=0 THEN 'zero_recorded' ELSE 'valid_recorded' END score_status,
        CASE WHEN package_name IS NULL OR package_name='' THEN 'missing_package_name'
        WHEN version_name IS NULL OR version_name='' THEN 'missing_version_name'
        WHEN vuln_id IS NULL OR vuln_id='' THEN 'missing_vuln_id'
        WHEN package_manager IS NULL OR package_manager NOT IN ('npm','pypi','cargo','rubygems')
          THEN 'unsupported_or_missing_ecosystem' ELSE NULL END quarantine_reason
      FROM trimmed
    )
    SELECT *,CASE WHEN score_status IN ('valid_recorded','zero_recorded') THEN parsed_score END severity_score,
      CASE WHEN score_status='missing' THEN 'Missing'
        WHEN score_status IN ('invalid_numeric','out_of_range') THEN 'Invalid'
        WHEN parsed_score=0 THEN 'Zero recorded' WHEN parsed_score<4 THEN 'Low'
        WHEN parsed_score<7 THEN 'Medium' WHEN parsed_score<9 THEN 'High' ELSE 'Critical' END severity_band,
      sha256(to_json(struct_pack(ecosystem:=package_manager,package:=package_name,version:=version_name,advisory:=vuln_id))) association_key_hash,
      sha256(to_json(struct_pack(ecosystem:=package_manager,package:=package_name))) package_key_hash,
      sha256(to_json(struct_pack(ecosystem:=package_manager,package:=package_name,version:=version_name))) version_key_hash
    FROM classified
    """)

def clean(connection,output_dir):
    prepare_clean_input(connection)
    connection.execute('CREATE OR REPLACE TABLE quarantined AS SELECT * FROM normalized WHERE quarantine_reason IS NOT NULL')
    connection.execute("""
    CREATE OR REPLACE TABLE associations AS
    WITH unique_payloads AS (
      SELECT package_name,package_manager,version_name,vuln_id,vuln_impact_raw,vuln_description,
        score_status,severity_score,severity_band,association_key_hash,package_key_hash,version_key_hash,
        min(source_row) first_source_row,min(raw_record_hash) representative_raw_record_hash,count(*) source_multiplicity
      FROM normalized WHERE quarantine_reason IS NULL GROUP BY ALL
    )
    SELECT *,count(*) OVER(PARTITION BY package_manager,package_name,version_name,vuln_id)>1 payload_conflict
    FROM unique_payloads
    """)
    connection.execute(f"COPY associations TO {sql_literal(output_dir/'associations.parquet')} (FORMAT PARQUET,COMPRESSION ZSTD)")
    connection.execute(f"COPY quarantined TO {sql_literal(output_dir/'quarantine.parquet')} (FORMAT PARQUET,COMPRESSION ZSTD)")
    raw_count=connection.execute('SELECT count(*) FROM raw_rows').fetchone()[0]
    quarantine=connection.execute('SELECT count(*) FROM quarantined').fetchone()[0]
    clean_count,represented=connection.execute('SELECT count(*),coalesce(sum(source_multiplicity),0) FROM associations').fetchone()
    assert raw_count==represented+quarantine
    return {'raw_rows':raw_count,'quarantined_rows':quarantine,'clean_payload_rows':clean_count,
      'exact_normalized_duplicates_removed':represented-clean_count,'valid_rows_represented':represented,
      'conflicting_key_groups':connection.execute('SELECT count(*) FROM (SELECT association_key_hash FROM associations WHERE payload_conflict GROUP BY 1)').fetchone()[0],
      'row_reconciliation_pass':raw_count==represented+quarantine,
      'identifier_changes':{column:connection.execute(f'SELECT count(*) FROM raw_rows WHERE {column} IS DISTINCT FROM trim({column})').fetchone()[0] for column in IDENTIFIER_COLUMNS},
      'description_newline_changes':connection.execute('SELECT count(*) FROM raw_rows WHERE contains(vuln_description,chr(13))').fetchone()[0],
      'score_status':dict(connection.execute('SELECT score_status,count(*) FROM associations GROUP BY 1').fetchall()),
      'decisions':['Identifiers remain strings; surrounding whitespace only is trimmed.',
        'Only ecosystem labels are lowercased; package names, advisory IDs and versions retain case.',
        'Full normalized payload duplicates are reconciled globally; conflicting association-key payloads are retained and flagged.',
        'No severity imputation. Recorded zero is retained separately and does not prove safety.',
        'Valid score extremes and heavy package/advisory counts are retained; resistant summaries and log axes handle skew.',
        'Description CRLF/CR becomes LF; Unicode content and advisory aliases are otherwise preserved.']}
