// In all queries change the word ‘Package’ to ‘NPMPackage’, ‘PyPIPackage’, ‘RubyGemsPackage’, or ‘CargoPackage’.
// Queries with NPM packages can take considerably longer than others, due to the size of the graph.

// Number of versions:
// -------------------------------------------------------------
MATCH (p:Package)-[:Have]->(v:Version)
RETURN count(v)
// -------------------------------------------------------------

// Number of vulnerable versions:
// -------------------------------------------------------------
MATCH (p:Package)-[:Have]->(v:Version)
WHERE size(v.vulnerabilities) > 0
RETURN count(v)
// -------------------------------------------------------------

// Number of packages with the latest vulnerable version:
// -------------------------------------------------------------
MATCH (p:Package)
CALL {
  WITH p
  MATCH (p)-[:Have]->(v:Version)
  RETURN v
  ORDER BY v.count DESC
  LIMIT 1
} 
WITH v
WHERE size(v.vulnerabilities) > 0
RETURN count(v)
// -------------------------------------------------------------

// Number of vulnerabilities by package name (write the package name):
// -------------------------------------------------------------
MATCH (p:Package)-[:Have]->(v:Version)
WHERE p.name = "PackageName" AND size(v.vulnerabilities) > 0
UNWIND v.vulnerabilities AS vuln
RETURN count(vuln) AS total_vulnerabilities
// -------------------------------------------------------------

// Number of versions directly requiring a package with vulnerable versions:
// -------------------------------------------------------------
MATCH (v1:Version)-[:Requires]->(p:Package)
WHERE EXISTS {
  MATCH (p)-[:Have]->(v2:Version)
  WHERE v2.vulnerabilities <> []
}
RETURN count(DISTINCT v1)
// -------------------------------------------------------------
