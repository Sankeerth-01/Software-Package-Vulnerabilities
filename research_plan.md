**Phase 1 Research Plan: Vulnerabilities affecting dependencies in software package managers**

**EAS 587 — Fall 2026**

Created By	: Manik Kashikar, Praveen Kumar, Sankeerth Reddy

Version	1.0

Target Community of Interest : Software supply-chain researchers, software security practitioners, package maintainers, and researchers studying dependency risk

Date Created :	September 17, 2026

Last Updated	: September 17, 2026

GitHub Repository : 	https://github.com/Sankeerth-01/Software-Package-Vulnerabilities.git

**1. Research Goal:**

The increasing reliance on third-party dependencies in software development introduces significant security risk challenges. Node Package Manager (NPM), Python Package Index (PyPI), Cargo Crates and RubyGems are major software package managers, there are multiple software vulnerabilities that affect the large software supply chain ecosystem exposing it to unwanted vulnerabilities. The dataset describes the lack of overall vulnerability information at the package level and vulnerabilities are difficult to identify. Modern software is often built using code written by people called dependencies or packages. If one of those packages has a security vulnerability, then the software that depends on it can also be vulnerable. Expected result would be to produce a scalable comparison of vulnerability patterns across all package ecosystems. This project will focus on descriptive patterns and data structure rather causal claims.

We aim to answer, How can we efficiently analyze millions of software-package versions to identify and characterize vulnerable dependencies across NPM, PyPI, Cargo, and RubyGems?

**Supporting Questions:**

1.⁠ ⁠How are vulnerabilities distributed across package managers, versions, and severity/impact levels?

2.⁠ ⁠Do the most recent versions of packages still carry a disproportionate share of known vulnerabilities, or are vulnerabilities concentrated in older versions?


3.⁠ ⁠What data quality and structural issues must be handled to compare the four ecosystems consistently?

4.⁠ ⁠How much of an ecosystem's overall vulnerability exposure is attributable to transitive dependencies rather than direct ones?

**2. Background and Motivation**

Now a days software’s are mostly built by using third party packages from NPM, PypI, Cargo and RubyGems, and if there’s a one vulnerability in any of them can be affected or impact thousands of projects.  

Major problem is that most package managers do not provide information about which versions are vulnerable and a pace ago they used to catch at one ecosystem at a time. And the dataset we selected has over 4.4 million packages, 61 million versions and 2.7 lakh vulnerabilities. Collecting the data isn’t the problem, get to analyze it and the data is so huge the local machine cannot handle this amount of data. 

Our project focuses on using this dataset by building a structured pipeline. We will study vulnerabilities exposure at huge scale and study the risk of concentration and direct or indirect dependence risk among all ecosystems. The main contribution is to build a scalable way to understand and vary vulnerabilities patterns among ecosystems at large scale.

**3. Research Objectives and Scope**

Objectives

•	Create representative samples/chunks from the raw dataset and perform documented analysis on per ecosystem vulnerabilities. Its helps us achieve self-understanding of the dataset’s real scale.

•	Use package_manager and vuln_impact to compare how many vulnerability records exist per ecosystem, and how severity (CVSS) is distributed within each. Outcome will be Per ecosystem summary statistics and charts enables a direct, like for like comparison across npm, PyPI, RubyGems, and Cargo.

•	Using package_name and version_name, counting the number of distinct versions of a particular package are vulnerable and find high-impact vulnerabilities affect few or more versions.

•	Build a processing pipeline that takes in chunks of dataset and produce a pipeline for spark-based aggregation for scale. This helps produce summarise of phase 1 data to get ready for phase 2 EDA.
In Scope

•	The four ecosystems included in the dataset: NPM, PyPI, Cargo, RubyGems.

•	Analysis using the provided CSV aggregate, and the underlying Neo4j (dependency graph) and MongoDB (vulnerability) databases where scale requires it.

•	Comparative, descriptive, and exploratory analysis of vulnerability exposure and severity.

•	Cross-ecosystem comparison of vulnerability volume and severity distribution. 

•	Package-level analysis of how many versions of a package remain flagged as vulnerable. 

•	Designing and documenting a sampling/chunked-processing strategy appropriate for a dataset this size.
Out of Scope

•	Extending the dataset with additional package managers (e.g., Maven Central) is not already included.

•	Live or continuously updated vulnerability monitoring, the dataset is a static snapshot, not a real time feed.

**4. Prior Research and References**

1.⁠ ⁠Márquez et al. (2024) — SMT vulnerability impact analysis

Published in Computers & Security, vol. 139, article 103669. Confirmed via DBLP (indexed under all five co-authors) and the publisher DOI resolves correctly.

A. G. Márquez, Á. J. Varela-Vaca, M. T. Gómez-López, J. A. Galindo, and D. Benavides, "Vulnerability impact analysis in software project dependencies based on Satisfiability Modulo Theories (SMT)," Computers & Security, vol. 139, p. 103669, 2024, doi: 10.1016/j.cose.2023.103669.

This reference is actually a research that work on the level of a single software project, it builds a dependency graph for one project. That graph model is a formal Satisfiability Modulo Theories (SMT) problem. It uses a solver to answer of there is any way to satisfy the version constraints without involving any vulnerable version. It is a per project reasoning tool.
Out project is not about a single project, it envelops whole ecosystem, measure the vulnerability volume, severity patthers across npm, PyPI, Rubygems and cargo using descriptive statistics.

2.⁠ ⁠Zerouali, Mens, Decan & De Roover (2022)

Published in Empirical Software Engineering, vol. 27, no. 5, article 107. Confirmed via arXiv (v1 2021, v2 2022) and the journal DOI cited consistently across multiple other papers' reference lists.

A. Zerouali, T. Mens, A. Decan, and C. De Roover, "On the impact of security vulnerabilities in the npm and RubyGems dependency networks," Empirical Software Engineering, vol. 27, no. 5, p. 107, 2022, doi: 10.1007/s10664-022-10154-1.

Studies how packages in npm and RubyGems behave once a vulnerability is discovered and then fixed specifically how often a fix becomes available in a later release within the same major version, rather than requiring a breaking upgrade. 

Their focus is fix-timing behavior across two ecosystems. Our project covers four ecosystems (adding PyPI and Cargo) but deliberately does not attempt fix-timing analysis.

3.⁠ ⁠Decan, Mens & Grosjean (2019)

Published in Empirical Software Engineering, vol. 24, no. 1, pp. 381–416. Confirmed via DBLP, arXiv preprint, and the authors' institutional repository (ORBi UMONS).

A. Decan, T. Mens, and P. Grosjean, "An empirical comparison of dependency network evolution in seven software packaging ecosystems," Empirical Software Engineering, vol. 24, no. 1, pp. 381–416, 2019, doi: 10.1007/s10664-017-9589-y.

The reference Used the libraries.io dataset to comparatively study seven ecosystems (Cargo, CPAN, CRAN, npm, NuGet, Packagist, RubyGems), introducing structural metrics — growth, fragility, reusability to describe how dependency networks evolve over time.

This is like "compare ecosystems side-by-side," but their metrics describe dependency-graph topology (who depends on whom), not security. Our project borrows the comparative multi-ecosystem framing but applies it to vulnerability volume and severity instead, working from the package_manager and vuln_impact fields rather than graph structure.

4.⁠ ⁠Rahman, Zahan, Magill, Enck & Williams (2024)

arXiv preprint, cited by multiple follow-up papers from the same NCSU research group. Confirmed authorship and abstract directly from the arXiv page.

I. Rahman, N. Zahan, S. Magill, W. Enck, and L. Williams, "Characterizing dependency update practice of NPM, PyPI and Cargo packages," arXiv:2403.17382, 2024.
Proposes two new metrics — Time-Out-Of-Date (TOOD) and Post-Fix-Exposure-Time (PFET) computed across ~2.9M packages and 66.8M versions in npm, PyPI, and Cargo (2004–2023), measuring how quickly packages update and how long they stay exposed to a vulnerable dependency after a fix exists.

Their metrics require full version-history/timestamp data to compute "time exposed." This project's snapshot only CSV can't replicate that, so instead it measures a snapshot based on how many distinct versions of a given package are currently flagged vulnerable a persistence signal that doesn't require temporal data.

5.⁠ ⁠Alfadel, Costa & Shihab (2021)

Published at IEEE SANER 2021, pp. 446–457 (a later journal version also exists in Empirical Software Engineering, 2023). Confirmed via DBLP author page and multiple citing papers.

M. Alfadel, D. E. Costa, and E. Shihab, "Empirical analysis of security vulnerabilities in Python packages," in 2021 IEEE Int'l Conf. on Software Analysis, Evolution and Reengineering (SANER), 2021, pp. 446–457, doi: 10.1109/SANER50967.2021.00048.

This is a focused empirical study of security vulnerabilities specific to the PyPI ecosystem.
Single-ecosystem (PyPI only) versus this project's four-ecosystem comparative design this project can situate PyPI's severity/volume profile relative to three other ecosystems rather than studying it in isolation.

**5. Supporting Data and Resources**

Item	Description

Dataset	: Data in Brief Material for Experimental Reproducibility

Dataset paper	: A dataset on vulnerabilities affecting dependencies in software package managers

Authoritative source	: Zenodo

DOI	: 10.5281/zenodo.15432733

Package managers	: NPM, PyPI, Cargo, RubyGems

Unique packages	: 4,437,679

Package versions	: 60,950,846

Known vulnerabilities	: 270,430

Main CSV	: data/data.csv

CSV schema	: package_name, package_manager, version_name, vuln_id, vuln_impact, vuln_description

Other data	: MongoDB vulnerability dump; Neo4j dependency-graph dump; query and setup files

Archive size	: Approximately 50GB based on the downloaded Zenodo archive

Access

We found this dataset in Google Scholar.

• We checked it and the topic + course requirements matched. Data in Brief Material for Experimental Reproducibility

• Downloaded directly from Zenodo.

Sampling/Subsetting Strategy

 The dataset is huge and around 50 gb after unarchiving, The data.csv contains about 9+ lakh rows and six columns and we will be using it as a direct vulnerability, ecosystem analysis. We will load and process data in chunks rather than loading the full csv at once. So, the laptop doesn’t crash.


For smaller iterative tasks, we will create a random sample of about 5 lakh records, and all four ecosystems should be represented in the sample. Where practical, smaller ecosystems can also be covered, So they are not missed in the tasks.  We will keep a separate sample of all critical severity rows for analysis. We store sample weights so our estimates should be unbiased. And the sample will store selection weights when needed. The steps cleaning, deduplication and aggregation will be doing in chunk so that we never keep multiple copies of data in memory. If needed, We will use Apache spark for distributed processing to keep everything reproducible.

**6. Risks, Constraints, Assumptions, and Open Questions**

Issue	Potential Impact	Mitigation

Dataset size	Processing might be slow and it will have an impact on RAM and storage	Sample, chunk, and later use distributed processing

Ecosystem differences	Naming/version conventions may complicate comparisons	Profile and standardize fields before cross-ecosystem analysis

Package-manager coverage	Results do not automatically generalize to other ecosystems	Limit conclusions to the four included ecosystems

Data relationships	Versions and vulnerabilities can connect many ways and aggregate if had wrong counting	Keep all identifiers and check cardinality before aggregation

Raw/processed formats	Managing different formats can make the workflow more difficult.	Keep a clear document after each step

Sampling	A local sample may not represent the full dataset	Use stratified sampling by package_manager and vuln_impact, and check the sample against full data totals.

Hardware limits	Neo4j + MongoDB containers need more RAM/disk than normal local machines	Choose sample and chunk size based on actual hardware.

Assumptions

•	During the project the Zenodo will be still accessible.

•	Will keep the representative sample of 250,000 records from dataset.

Open Questions

1. Which Sample and chunk size provides the representative sample the fastest execution?

2. Which fields contain missing values or inconsistent types?

3. What type of  analyses are done locally and what benefits from distributed processing?

**7. Research Approach Tasks and Timeline**


Week(s)	Dates	Tasks	Deliverable

Week 1	Sept 4–10	We checked few datasets and finally selected the dataset from Zenodo and also confirmed that it is downloadable or not.	Dataset finalized

Week 2	Sept 11–17	Prepared this research plan, discussed and finalized the research questions and set up the GitHub repo.	report and PPT Presentation

Week 3	Sept 18–24	Downloading the complete dataset and trying to set up Neo4j and MongoDB locally using their docker-compose file, then running the seeder scripts. This is the part we are most tense about if the containers give problem, it will push the Week 4 work also.	Local database setup working properly

Week 4	Sept 25–Oct 1	Taking a stratified sample from data.csv andtargeting minimum 250,000 rows as per course requirement. Also starting data_access.py and data_sampling.py scripts, and pushing a small sample to 
data/samples/ folder.	Sample committed to repo, initial scripts

Weeks 5–8 (Phase 2)	Oct 2–29	Cleaning the sampled data, checking vulnerability counts by ecosystem and severity, and trying to understand how much of the exposure is direct versus transitive using Cypher queries on the graph. We are following Tukey's EDA approach roughly letting the data guide us instead of forcing any particular hypothesis too early.	EDA results ready for Phase 2 presentation

Weeks 9–12 (Phase 3)	Oct 30–Dec 7	Trying to scale up the working analysis beyond the sample, most probably using Spark. Remaining weeks will go into fixing whatever gaps we find, and preparing the final presentation.	Final presentation.

Project Pipeline

Source → Acquire → Sample/Store → Process → Analyze

•	Source: Zenodo dataset

•	Acquire: download the selected archive and preserve metadata/version information





