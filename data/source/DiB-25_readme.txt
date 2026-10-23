This dataset provides a comprehensive overview of software packages, their versions, and associated vulnerabilities across four major ecosystems: PyPI (Python), RubyGems (Ruby), Cargo Crates (Rust), and NPM (JavaScript). It includes detailed metadata for over 4,437,679 million unique packages and 60,950,846 versions and identifies vulnerable dependencies using 270,430 known vulnerabilities indexed in Open Source Vulnerabilities (OSV). The dataset covers both direct and transitive vulnerabilities, along with severity classifications. For each ecosystem, the versions of each package are flagged and annotated with vulnerability data, enabling risk analysis and supply chain security assessments. This resource supports research and tool development in software vulnerability management, dependency analysis, and security automation. The content of this folder is divided into raw and data folders

1. The raw folder contains a docker-compose.yml file that together with the command ‘docker compose up --build’ if run inside this folder, raises two containers.
   One with a MongoDB database and one with a Neo4J database, containing all the data extracted from the vunerabilities and package managers respectively.

2. The data folder contains all the accumulated content of the databases in a csv extension file.

3. In the file querys.cypher are shown Neo4J querys that can be used to extract information about packages and vulnerabilities.
