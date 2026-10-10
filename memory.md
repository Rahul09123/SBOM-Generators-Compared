# Project Memory Log

## Execution log — 2026-10-10

The student confirmed they are carrying out the project alone. The execution plan is therefore a single-person workflow: one owner handles the corpus/tooling, ground truth, analysis, and writing in sequential milestones; the original three role areas remain useful as task buckets but are not parallel assignments.

### Step 1: reproducible pilot environment and corpus

- Installed Syft 1.54.1 and Trivy 0.75.0 using Homebrew.
- Pinned cdxgen 13.0.0 as a repository-local npm dependency in `.tools/cdxgen/` with a lockfile.
- Docker Desktop/Engine used: 29.4.2, linux/arm64.
- Added `.gitignore`, `SETUP.md`, `data/images.csv`, `data/tools.csv`, and scripts for image pinning, SBOM generation, ground-truth collection, and comparison.
- Resolved and pinned six linux/arm64 images by digest: Alpine 3.22, Debian Bookworm slim, Python 3.12 slim Bookworm, Node 22 Bookworm slim, Eclipse Temurin 21 JRE Jammy, and OWASP Juice Shop (source release still needs to be tied to its image digest).
- Generated one CycloneDX JSON per each of the three tools for each image: 18 successful pilot SBOMs. Raw outputs and run manifests are under ignored `artifacts/`.

### Step 2: independent truth and exploratory comparison

- Added `scripts/collect_ground_truth.py`. It reads dpkg/apk package databases from exported image filesystems and reads installed npm package metadata from `node_modules`; it does not use Syft, Trivy, or cdxgen as the answer key.
- Collected 1,329 rows across five image ecosystems/datasets: 440 OS package records plus npm metadata (counts can include repeated package names/versions across distinct images). Juice Shop has no supported OS database found by the initial collector, but its installed npm packages were recorded.
- Added scope filtering to the comparator so component accuracy is calculated only for package ecosystems represented in that image's independent truth. Ungrounded file records are not mislabeled as false positives.
- Exploratory installed-component results were generated under ignored `artifacts/reports/`. For OS-package baselines, Syft and Trivy matched the collected binary-package set in the initial run; cdxgen included names not found as binary package identities. The later source-metadata audit below established exact-version source-package mappings for most such names. The initial npm comparison was affected by a scoped-package normalization defect and is superseded by the audit recorded below. All results remain preliminary single-run observations, not final claims.
- Important limitations: npm package metadata is evidence of installed/present, not declared or used; independently validate package metadata completeness and parser behavior. The OS/npm truth has not undergone manual audit. Image architecture is ARM64. Only one run per tool/image exists. Accuracy currently covers component-set matching only; dependency-edge correctness, field accuracy, repeatability, runtime, and vulnerability impact remain future work.

### Immediate next steps

1. Audit collector records and mismatches; manually spot-check package identities and versions against extracted source metadata.
2. Resolve and record Juice Shop source release/commit corresponding to the pinned image digest; decide whether to retain it in the final corpus.
3. Add controlled application images with known lockfiles and declared-vs-installed distinctions. Add Java JAR and Python package ground truth before claiming ecosystem-wide coverage.
4. Improve PURL normalization and distinguish duplicate/ambiguous identities.
5. Run repeats after protocol freeze; measure time/resources, dependency edges, field completeness, then vulnerability scanning as a separate same-scanner/database experiment.
6. Update the research question and novelty statement based on audited results; keep pilot claims separate from final results.

Changes are local and uncommitted/unpushed as of this log entry.

### Follow-up execution — mismatch audit and controlled Node fixture

- Audited the first comparison report and found a normalization defect: Trivy and cdxgen can encode scoped npm package names as `group` + `name` (for example, `@isaacs` + `cliui`) while the independent inventory stores `@isaacs/cliui`. Updated identity normalization to join the fields before matching.
- Found repeated copies of the same ecosystem/name/version at different nested `node_modules` paths. Updated the component-set metric to deduplicate by that identity; raw SBOMs and all ground-truth evidence rows remain unchanged. This reports unique component identities, not installation occurrences.
- Regenerated the comparison outputs. The initial npm comparison results in the previous log entry are superseded: after scope normalization and deduplication, the installed npm inventory is substantially better aligned across tools. The new results still require manual mismatch review.
- Added `fixtures/node-controlled/`: a small Express app using Lodash, with Express 4.21.2 and Lodash 4.17.21 declared directly and locked in `package-lock.json`. It builds on the pinned Node 22 Bookworm digest. The local built image is pinned in the corpus using its immutable repository digest: `sbom-study/node-controlled@sha256:ce2a1aab30152c65c5a4f5c2be292aacbc26495e7a5df264c4dbdd85c8c90e94` (`linux/arm64`).
- Extended the collector to distinguish direct npm dependencies in a root `package.json` from other packages present under `node_modules`. For this fixture, Express and Lodash are marked direct; installed metadata alone is not considered evidence of runtime use.
- Generated all three SBOMs successfully for the controlled image and added its ground truth. The image contains 355 evidence rows (88 dpkg rows and 267 npm metadata rows; comparison deduplicates identities). In the current installed-component comparison, unique truth identities total 342: Syft TP=342/FP=2/FN=0, Trivy TP=342/FP=2/FN=0, cdxgen TP=342/FP=40/FN=0. Treat these only as exploratory; the unmatched cdxgen set is largely OS-package identities absent from dpkg status and must be adjudicated before labeling as false positives.
- Improved `scripts/run_experiment.py` with an `--images` selector for focused runs, and fixed tool-version parsing so new manifests record plain semantic versions.
- README, SETUP, PROJECT_PLAN, and this log now describe the seven-image corpus and controlled fixture. Latest ground-truth file contains 1,684 rows after adding the controlled image.

### Next actions after this audit

1. Add a small Python controlled fixture and improve ground-truth collection from Python metadata/lockfiles.
2. Add Java JAR-ground-truth before making ecosystem-wide claims.
3. Add field/dependency-edge measures, then repeat scans under the frozen protocol and run a separate same-scanner vulnerability-impact experiment.

### Follow-up mismatch triage — 2026-10-10

- Verified the dominant cdxgen OS-package mismatch class directly against `dpkg-query` in the Debian image. For example, installed `gcc-12-base` reports source package `gcc-12` at the same version; installed `libacl1` reports source `acl`; `libgnutls30` reports source `gnutls28`. The Debian status database's `Source` field therefore explains these cdxgen names as source-package identities rather than arbitrary detections. The same source-name metadata is now captured from dpkg; Alpine's apk `o:` origin is recorded similarly.
- The comparison keeps strict binary/package-name precision and recall unchanged, but separately classifies source-name identities with exact source-version evidence. Across the pilot there are 221 such cdxgen aliases. They should be reported as representation/granularity differences, not silently merged with binary package names.
- Improved npm inventory semantics: Yarn under `/opt/yarn-v1.22.22` is captured as installed; application root manifests (Juice Shop, frontend, and the controlled app) are marked present but not installed dependencies; nested test fixtures and subpath `package.json` files are present but not treated as installed packages. Unversioned identities remain visible for presence analysis and are separately counted.
- Ground truth is now 1,695 rows and includes `source_name`/`source_version`. CSV writers use LF line endings to pass Git whitespace checks. Comparison output is separated by truth state in `artifacts/reports/installed/` and `artifacts/reports/present/`.
- In present-state Juice Shop comparison, Syft has two missing package identities (`portscanner`, `toposort-class`); Trivy has five missing metadata identities, including one hashids subpath and four test-fixture manifests; cdxgen matches all identities in this current inventory. In installed-state comparison, the fixture manifests are excluded, while app-root package identities are not treated as installed dependencies. These are single-image, single-run observations and require review before publication.
- The controlled Node image's strict installed-state comparison now has Syft and Trivy each at TP=343, FP=1, FN=0; cdxgen TP=343, FP=39, FN=0, of which 38 are source-package aliases. The remaining one is not yet adjudicated. For present-state, all three match the inventoried component identities except the cdxgen source aliases.

## Project context

- Project elective period: August–December 2026.
- Institution: IIIT Bangalore, Department of Computer Science and Engineering.
- Faculty: Prof. B. Thangaraju.
- Project theme: Supply-chain security and DevSecOps.
- Project identifier/title: **P16 — SBOM Generators Compared: Coverage and Accuracy of Syft vs Trivy vs cdxgen**.
- Study type: Comparative measurement study.
- Team size: Three members.

## Interpretation of the attached documents

The attached images were treated as project context and handout material, not as additional user instructions.

The project handout states that different SBOM tools may produce different component lists for the same container image, while their completeness and accuracy are rarely compared.

The planned work includes:

- Assemble a corpus of container images across Java, Node.js, Python, and operating-system-package ecosystems.
- Generate SBOMs using Syft, Trivy, and cdxgen.
- Compare component coverage, completeness, and format/field accuracy against ground truth where available.
- Characterize which components each tool misses.
- Produce a comparative coverage/accuracy evaluation and a practitioner guide.

The common milestone plan is:

- **August:** Define the research question, related-work/search protocol, and dataset or small testbed.
- **September–October:** Execute experiments or extract and code the literature; complete the mid-semester checkpoint.
- **November:** Analyze results or synthesize findings; complete the first full draft.
- **December:** Revise, document threats to validity, finalize, and submit to the target venue.

The stated target venues are reasonable Scopus-indexed security/DevSecOps conferences, IEEE Access, or a reputable practitioner magazine. Venue indexing should be rechecked at submission time.

## Current literature-survey request

The immediate task is to identify approximately 15 research papers related to SBOM generation, SBOM quality, component coverage, completeness, correctness, container-image analysis, software supply-chain security, and DevSecOps. Preference was given to ACM, IEEE, USENIX, Springer, Scientific Reports, and other established venues. Direct paper or DOI links were provided where available.

## Recommended papers

### Directly related to SBOM-generator comparison

1. **On the Correctness of Metadata-Based SBOM Generation: A Differential Analysis Approach** — IEEE/IFIP DSN 2024. Compares Trivy, Syft, Microsoft SBOM Tool, and GitHub Dependency Graph; studies omissions, inconsistencies, correctness, and differential analysis.
   - https://escholarship.org/uc/item/8606f22r
   - https://cs.ucr.edu/~heng/pubs/sbom-dsn24.pdf

2. **SBOM Generation Tools Under Microscope: A Focus on the npm Ecosystem** — ACM SAC 2024. Compares ORT, cdxgen, Syft, and another tool on 50 open-source npm projects using component and version-identification metrics.
   - https://doi.org/10.1145/3605098.3635927
   - https://www.researchgate.net/publication/380779250_SBOM_Generation_Tools_Under_Microscope_A_Focus_on_the_NPM_Ecosystem

3. **Claim vs. Capability: A Comparative Analysis of the SBOM Generation Tools for Rust Projects** — ACM SAC 2025. Evaluates seven tools on 50 Rust projects, including component names, versions, dependencies, and CycloneDX versus SPDX output.
   - https://doi.org/10.1145/3672608.3707940

4. **SBOM Generation Tools in the Python Ecosystem: An In-Detail Analysis** — IEEE TrustCom 2024. Studies completeness and correctness problems involving optional dependencies, metadata files, remote dependencies, and package-manager differences.
   - https://doi.org/10.1109/TrustCom63319.2024.00077
   - https://serenacofano.github.io/files/SBOM_Generation_Tools_in_the_Python_Ecosystem_an_In-Detail_Analysis.pdf

5. **The Impact of SBOM Generators on Vulnerability Assessment in Python: A Comparison and a Novel Approach** — 2024 research preprint. Studies how different SBOM generators affect downstream vulnerability detection, precision, recall, and false positives.
   - https://arxiv.org/abs/2409.06390

6. **More than Meets the Eye: On Evaluating SBOM Tools in Java** — ACM Transactions on Software Engineering and Methodology, 2026. Evaluates Java SBOM tools and component-identification challenges arising from different import and dependency scenarios.
   - https://doi.org/10.1145/3766073

7. **An Empirical Study on the Comparability and Interpretation of Container Image SBOMs** — Transactions of the Korea Information Processing Society, 2026. Directly compares Trivy and Syft on container images and studies PURL normalization, OS packages, shared libraries, and reference baselines.
   - https://tkips.kips.or.kr/digital-library/107813

8. **SBOM Generation Based on Code-Level External Component Trees** — Scientific Reports, 2025. Compares a source-code-based SBOM approach with existing tools, focusing on bloated and missing dependencies.
   - https://doi.org/10.1038/s41598-025-29762-0

### Surveys, frameworks, and supporting supply-chain research

9. **SoK: A Framework for and Analysis of Software Bill of Materials Tools** — Idaho National Laboratory Technical Report, 2022. Surveys and categorizes 83 SBOM tools; useful for tool taxonomy and evaluation dimensions.
   - https://doi.org/10.2172/2204407
   - https://inldigitallibrary.inl.gov/sites/STI/STI/Sort_63474.pdf

10. **A Taxonomy and Survey of Software Bill of Materials Generation Approaches** — Springer CCIS, 2024. Surveys SBOM-generation techniques and automated generation in CI/CD systems.
    - https://doi.org/10.1007/978-3-031-50815-8_3

11. **An Empirical Study on Software Bill of Materials: Where We Stand and the Road Ahead** — 2023 research paper. Provides broad background on SBOM adoption, tooling, standards, and open research gaps.
    - https://arxiv.org/abs/2301.05362

12. **A Landscape Study of Open Source and Proprietary Tools for Software Bill of Materials** — 2024 research paper. Surveys SBOM tools and capabilities across generation, analysis, formats, and supply-chain-security use cases.
    - https://arxiv.org/abs/2402.11151

13. **Software Bill of Materials in Software Supply Chain Security: A Systematic Literature Review** — 2025 systematic literature review. Synthesizes 40 peer-reviewed studies and identifies problems involving incomplete generation, hidden packages, format issues, false positives, and maintenance.
    - https://arxiv.org/abs/2506.03507

14. **Assessing Security Risks of Software Supply Chains Using Software Bill of Materials** — IEEE SANER Companion 2024. Analyzes 1,151 SBOMs using Trivy and Grype to study vulnerabilities and the practical security value of SBOM data.
    - https://doi.org/10.1109/SANER-C62648.2024.00023

15. **BOMs Away! Inside the Minds of Stakeholders: A Comprehensive Study of Bills of Materials for Software Systems** — IEEE/ACM ICSE 2024. Studies practitioner perceptions, adoption barriers, usability, creation, and interpretation of SBOMs.
    - https://doi.org/10.1145/3597503.3623347
    - https://www.twstalnaker.com/resources/icse24.pdf

## Papers to read first

The first six priority readings are:

1. On the Correctness of Metadata-Based SBOM Generation.
2. SBOM Generation Tools Under Microscope.
3. Claim vs. Capability.
4. SBOM Generation Tools in the Python Ecosystem.
5. An Empirical Study on the Comparability and Interpretation of Container Image SBOMs.
6. SoK: A Framework for and Analysis of SBOM Tools.

These papers are expected to be most useful for designing the experimental corpus, ground-truth methodology, accuracy metrics, and tool-comparison protocol.

## Proposed research gap

Existing studies commonly focus on one programming ecosystem or on source/project-level SBOM generation. A potentially novel contribution is a reproducible, three-way comparison of **Syft, Trivy, and cdxgen** on the same container images across Java, Node.js, Python, and operating-system packages, using a defined ground-truth methodology.

No claim is made that this combination has never been studied; this should be verified through a systematic search before writing the final novelty statement.

## Proposed evaluation dimensions

- Component coverage.
- Completeness/recall against a ground-truth component set.
- Precision and false-positive rate.
- Version-identification accuracy.
- Dependency-edge accuracy.
- OS-package, language-package, native-library, and application-binary coverage.
- CycloneDX/SPDX format validity and field completeness.
- PURL normalization and identifier consistency.
- Reproducibility across repeated runs.
- Tool failures, execution time, and resource consumption.
- Categories of missed components and the likely cause of each miss.

## Important methodological note

The project should define “ground truth” carefully. Possible sources include package-manager lockfiles, image package databases, build manifests, Dockerfile instructions, image-layer contents, and manually verified component inventories. A consensus SBOM from multiple tools should not automatically be treated as ground truth because all tools may share the same blind spots.

## Project-start methodology

### Recommended sequence

1. Freeze the research question and hypotheses.
2. Freeze tool versions, container-image digests, SBOM format, scan configuration, and vulnerability-database date.
3. Build a small pilot corpus and test the complete pipeline.
4. Build the full container corpus across OS, Python, Node.js, and Java categories.
5. Define an independent ground-truth inventory for every image.
6. Generate SBOMs from all images with Syft, Trivy, and cdxgen.
7. Normalize SBOMs before comparison, especially PURLs, namespaces, package names, versions, and ecosystems.
8. Calculate coverage, precision, recall, F1-score, version accuracy, dependency-edge accuracy, field completeness, and tool runtime/resource use.
9. Perform error analysis on missed, extra, and incorrectly identified components.
10. Repeat selected scans to test reproducibility and run statistical analysis across image categories.
11. Write the paper around the research questions, results, threats to validity, and practitioner recommendations.

### Suggested research questions

- **RQ1:** How do Syft, Trivy, and cdxgen differ in component coverage for the same container image?
- **RQ2:** How accurately does each tool identify component names, versions, ecosystems, and package identifiers?
- **RQ3:** How accurately does each tool represent dependency relationships?
- **RQ4:** Which component classes are most frequently missed by each tool?
- **RQ5:** How much do SBOM-format and identifier differences affect measured comparison results?
- **RQ6:** How stable are the results across repeated scans and image categories?

### Experimental controls

- Use immutable image digests rather than only mutable tags.
- Record image digest, architecture, OS distribution, tool version, command options, scan timestamp, and database versions.
- Use the same output format for the main comparison, preferably CycloneDX JSON, and optionally repeat using SPDX JSON.
- Do not compare vulnerability counts as a substitute for SBOM accuracy; vulnerability databases and matching policies can differ.
- Keep a separate experiment for vulnerability impact, where each generated SBOM is passed to the same vulnerability scanner and database snapshot.
- Normalize PURLs and package names before computing matching metrics.
- Store raw SBOMs unchanged and keep normalized datasets separately.

### Tool workflow

Syft supports container images and can emit CycloneDX and SPDX outputs. Trivy supports SBOM generation in CycloneDX and SPDX formats and can also scan SBOM files. cdxgen supports container-image input with the Docker target type and generates CycloneDX SBOMs. Tool capabilities and commands should be checked against the exact versions used.

Illustrative commands are:

```bash
syft "$IMAGE" -o cyclonedx-json=results/syft.cdx.json
trivy image --format cyclonedx --output results/trivy.cdx.json "$IMAGE"
cdxgen "$IMAGE" -t docker -o results/cdxgen.cdx.json
```

These commands are starting points, not the final locked protocol. They must be recorded along with tool versions and configuration.

## Shortlisted container-image test corpus

The recommended design is a two-tier corpus: controlled images for ground-truth experiments and real-world application images for external validity.

### Tier 1: controlled baseline images

Use pinned digests for the actual experiment. Suggested image families are:

- `alpine` — APK-based minimal Linux image.
- `debian:bookworm-slim` — Debian/DPKG package ecosystem.
- `ubuntu:24.04` — Ubuntu/DPKG package ecosystem.
- `python:3.12-slim-bookworm` — Python packages plus Debian packages.
- `node:22-bookworm-slim` — npm packages plus Debian packages.
- `eclipse-temurin:21-jre-jammy` — Java/JAR packages plus Ubuntu packages.

For the controlled application images, build small Dockerfiles with known locked dependencies:

- Python image with Flask or FastAPI, `requests`, `numpy`, and one optional dependency.
- Node.js image with Express, Axios, Lodash, and a package-lock file.
- Java image with a small Maven Spring Boot application and a fixed `pom.xml`/Maven lock-equivalent dependency set.
- A native-library image containing explicitly installed shared libraries and a dynamically loaded module.

These images make it possible to know what was declared, installed, copied into the image, and intentionally used.

### Tier 2: real-world application images

Shortlisted projects/images are:

- **OWASP Juice Shop** — Node.js application with a realistic npm dependency tree.
- **Spring Petclinic** — Java/Spring/Maven application with transitive JAR dependencies.
- **A small Django or FastAPI service** — Python application with pip dependencies.
- **Nginx** — native application plus OS libraries and configuration files.
- **Redis** — native application with OS-level dependencies.
- **PostgreSQL** — database image with a larger OS/package footprint.

The final study should not use every possible image. A practical first version is 12 images: six controlled baseline images and six application images. The corpus can later be expanded to 18–24 images if the pipeline is stable.

### Ground-truth sources by component class

- OS packages: image package database such as `dpkg`/`apt` or `apk`, verified against extracted image contents.
- Python: installed distributions from the image, lock files, package metadata, and manually verified package versions.
- Node.js: `package-lock.json` plus installed `node_modules` package metadata.
- Java: Maven/Gradle dependency output plus JAR manifests and files physically present in the final image.
- Native libraries: filesystem inventory, package ownership queries, ELF/shared-library inspection, and manual verification.

The ground-truth inventory should label each item as declared, installed, physically present, or actually used. These labels should not be collapsed into one number.

## Current shortlist decision

Start with the 12-image corpus above. Run a pilot on one image from each major class—Alpine, Debian/Python, Node.js, Java, Nginx, and one application image—before committing to the full corpus. Expand only after the normalization and ground-truth process produces stable results.

## Full project execution plan

### Working title

**A Comparative Evaluation of SBOM Generators for Container Images: Syft, Trivy, and cdxgen**

### Project objective

Measure and explain how Syft, Trivy, and cdxgen differ when identifying the software components inside identical container images. The study will evaluate coverage, completeness, identification accuracy, dependency accuracy, SBOM-field quality, reproducibility, and the practical effect of SBOM differences on vulnerability detection.

### Scope boundaries

In scope:

- Container images and their extracted filesystems.
- OS packages, Python packages, npm packages, Java/JAR packages, native libraries, and application files.
- Syft, Trivy, and cdxgen.
- CycloneDX JSON as the primary common format; SPDX JSON as an optional secondary comparison.
- Component-level and dependency-edge-level comparison.
- Independent ground-truth construction.

Out of scope for the first version:

- Full Kubernetes or cloud-infrastructure scanning.
- Performance benchmarking on very large production registries.
- Treating vulnerability counts alone as evidence of SBOM accuracy.
- Claiming universal superiority of one tool.

### Research questions

- **RQ1:** How different are the component inventories produced by Syft, Trivy, and cdxgen for the same container image?
- **RQ2:** Which tool provides the highest component precision, recall, coverage, and F1-score?
- **RQ3:** How accurately does each tool identify component names, versions, ecosystems, PURLs, and other metadata?
- **RQ4:** How accurately does each tool represent dependency relationships?
- **RQ5:** Which component classes and image characteristics cause the most omissions or false positives?
- **RQ6:** How much do identifier and format differences affect measured tool comparisons?
- **RQ7:** Do differences in generated SBOMs lead to different vulnerability results when passed to the same scanner?
- **RQ8:** Are the results stable across repeated scans and different image categories?

### Optional hypotheses

- **H1:** Tool outputs will differ significantly even for identical images.
- **H2:** Tool performance will vary by component ecosystem.
- **H3:** Identifier normalization will improve agreement between tool outputs.
- **H4:** Package-manager-centric scans will miss some file-level native libraries and dynamically loaded components.
- **H5:** Differences in SBOM composition will produce differences in downstream vulnerability findings.

## Work packages

### WP1 — Literature and protocol design

Tasks:

- Read the eight priority papers and extract their datasets, metrics, matching rules, and limitations.
- Search ACM, IEEE Xplore, Springer, Scopus, Google Scholar, and arXiv using combinations of `SBOM`, `software bill of materials`, `container image`, `SBOM generator`, `Syft`, `Trivy`, `cdxgen`, `completeness`, `accuracy`, and `differential analysis`.
- Build a literature matrix with columns for paper, ecosystem, tools, dataset size, ground truth, metrics, findings, and limitations.
- Freeze the research questions and experimental protocol before full data collection.

Outputs:

- Literature matrix.
- Search and inclusion/exclusion protocol.
- Final research questions.
- Initial methodology document.

### WP2 — Test-corpus construction

Tasks:

- Select the final images from the baseline and real-world shortlists.
- Prefer official images or official project repositories.
- Build controlled Python, Node.js, Java, and native-library images with locked dependencies.
- Pull every image by digest and record architecture, tag, digest, size, base OS, and retrieval date.
- Exclude images that cannot be reproduced or independently inspected.

Target corpus:

- Six controlled baseline images.
- Four controlled application images.
- Six real-world application images.
- Minimum pilot corpus: six images.

Outputs:

- `images.csv`.
- Dockerfiles and build instructions for controlled images.
- Image manifest and digest record.
- Reproducible corpus README.

### WP3 — Ground-truth construction

Tasks:

- Extract each image filesystem without modifying it.
- Record OS package databases and installed package versions.
- Record Python distributions and package metadata.
- Record Node.js package metadata and lockfile contents.
- Record Java dependency trees, JAR names, manifests, and final-image contents.
- Record native binaries and shared libraries.
- Manually verify ambiguous names and versions.
- Assign each component the labels declared, installed, physically present, and actually used.

Outputs:

- Ground-truth inventory per image.
- Evidence file or command output supporting every ground-truth component.
- Ambiguity and adjudication log.

### WP4 — Tool setup and SBOM generation

Tasks:

- Install fixed versions of Syft, Trivy, and cdxgen.
- Record checksums or release identifiers for the tool binaries or containers.
- Freeze tool configuration and output format.
- Generate CycloneDX JSON from every image with every tool.
- Generate SPDX JSON for a selected subset if time permits.
- Run each tool twice on the pilot corpus.
- Save raw output without editing.

Outputs:

- Raw SBOM files.
- Tool-version manifest.
- Command log.
- Execution-time and resource-use log.
- Failure log.

### WP5 — Normalization and comparison engine

Tasks:

- Parse Syft, Trivy, and cdxgen SBOMs into a common internal schema.
- Normalize package names, versions, ecosystems, namespaces, qualifiers, and PURLs.
- Deduplicate components while preserving the original records.
- Match components using exact PURL, normalized identity, and weaker fallback rules.
- Match dependency edges using normalized component identities.
- Keep raw-match and normalized-match results separately.

Outputs:

- Normalization specification.
- Matching algorithm.
- Unit tests for package-identity cases.
- Normalized component and dependency datasets.

### WP6 — Metrics and statistical analysis

Component metrics:

- True positives, false positives, and false negatives.
- Precision, recall/coverage, and F1-score.
- Component-name accuracy.
- Version accuracy.
- Ecosystem accuracy.
- PURL accuracy.

Dependency metrics:

- Dependency-edge precision, recall, and F1-score.
- Missing-edge rate.
- Extra-edge rate.

SBOM-quality metrics:

- Required-field completeness.
- Duplicate rate.
- Unversioned-component rate.
- Invalid-identifier rate.
- Format-validation success rate.

Operational metrics:

- Runtime.
- Peak memory use where practical.
- Scan failure rate.
- Repeated-run agreement.

Statistical analysis:

- Report per-image and per-ecosystem results.
- Report medians and interquartile ranges when distributions are skewed.
- Use paired comparisons because all tools scan the same image.
- Use bootstrap confidence intervals for aggregate precision, recall, and F1-score.
- Use an appropriate paired non-parametric test for tool comparisons if sample size permits.
- Treat statistical significance and practical significance separately.

Outputs:

- `component_metrics.csv`.
- `dependency_metrics.csv`.
- `field_metrics.csv`.
- Per-ecosystem tables.
- Figures showing coverage, precision, recall, F1-score, and error categories.

### WP7 — Error analysis

Classify every important mismatch as one or more of:

- Unsupported package ecosystem.
- Missing or inconsistent metadata.
- Optional dependency.
- Dynamic dependency.
- Incorrect version inference.
- PURL or namespace mismatch.
- Native library or shared-object omission.
- File copied manually into the image.
- Layer or filesystem-analysis limitation.
- Architecture-specific behavior.
- Tool configuration or version limitation.

Outputs:

- Error taxonomy.
- Representative examples.
- Tool-specific strengths and weaknesses.
- Practitioner recommendations.

### WP8 — Vulnerability-impact experiment

Tasks:

- Generate one SBOM per tool for the same image.
- Pass all SBOMs to the same vulnerability scanner.
- Use the same vulnerability database snapshot and scanner version.
- Compare vulnerability matches caused by missing, extra, or incorrectly identified components.
- Do not use vulnerability totals as a replacement for ground-truth SBOM metrics.

Outputs:

- Vulnerability-difference table.
- Examples of vulnerabilities missed because a component was absent or misidentified.
- Discussion of SBOM quality versus scanner behavior.

### WP9 — Threats to validity and reproducibility

Document:

- Limited number of images.
- Bias toward selected ecosystems and official images.
- Imperfect or ambiguous ground truth.
- Changes in package repositories.
- Changes in vulnerability databases.
- Architecture-specific behavior.
- Tool-version changes.
- Differences between declared, installed, present, and used components.
- Possible shared blind spots among ground-truth methods.

Publish or preserve:

- Image digest list.
- Dockerfiles.
- Tool versions.
- Commands.
- Raw SBOMs.
- Normalization code.
- Ground-truth evidence.
- Analysis scripts.

## Month-wise schedule

### August — Definition and pilot preparation

- Finalize title, objective, research questions, hypotheses, and scope.
- Complete the literature matrix for the priority papers.
- Define inclusion/exclusion criteria for images.
- Select the six-image pilot corpus.
- Install tools and verify basic scans.
- Define the ground-truth schema.

Milestone: approved research protocol and runnable pilot pipeline.

### September — Corpus and ground truth

- Build the controlled application images.
- Pull and pin baseline images.
- Record image metadata.
- Extract filesystems and package inventories.
- Create ground truth for the pilot images.
- Resolve initial identity and version ambiguities.

Milestone: pilot corpus and ground truth complete.

### October — Full data collection

- Expand to the full 12–16 image corpus.
- Generate Syft, Trivy, and cdxgen SBOMs.
- Repeat scans for stability checks.
- Generate optional SPDX outputs.
- Store raw SBOMs and execution logs.

Milestone: raw experimental dataset complete; mid-semester review.

### November — Analysis and first draft

- Normalize all SBOMs.
- Run component and dependency matching.
- Calculate metrics.
- Perform error classification.
- Run the vulnerability-impact experiment.
- Prepare tables and figures.
- Write the first complete paper draft.

Milestone: complete results and first full draft.

### December — Validation and finalization

- Re-run selected experiments from a clean environment.
- Review threats to validity.
- Verify all citations, tables, and figures.
- Improve the practitioner guide.
- Incorporate faculty feedback.
- Finalize paper, code, data documentation, and presentation.

Milestone: final submission-ready project package.

## Team allocation

### Member 1 — Testbed and implementation

- Corpus construction.
- Dockerfiles and reproducible builds.
- Tool installation.
- SBOM generation.
- Runtime and failure logging.

### Member 2 — Measurement and analysis

- Ground-truth inventories.
- SBOM parser and normalization.
- Component/dependency matching.
- Metric computation.
- Statistical analysis.

### Member 3 — Related work and writing

- Literature matrix.
- Background and related-work sections.
- Error taxonomy documentation.
- Figures and tables.
- Threats to validity and practitioner guide.

All members should review the protocol, ground truth, results, and final paper.

## Acceptance criteria

The project is complete when:

- At least 12 pinned container images have been evaluated.
- All three tools have been run using documented versions and commands.
- Raw SBOMs are preserved.
- An independent ground-truth inventory exists for every image.
- Component and dependency matching rules are documented.
- Precision, recall, F1-score, coverage, and field-quality results are reported.
- Missed-component causes are categorized.
- Reproducibility checks have been performed.
- Threats to validity are documented.
- The final paper and practitioner guide are complete.

## Implementation progress — 2026-10-10

Started converting the plan into a runnable repository scaffold:

- Added SETUP.md with tool prerequisites, corpus pinning, scan, and analysis workflow.
- Added .gitignore for generated reports, image archives, local Python environments, and editor files.
- Added data/images.csv with six proposed pilot entries, candidate tags, a target platform, and disabled-by-default status.
- Added data/tools.csv to record exact tool/runtime versions.
- Added data/ground_truth.csv with declared, installed, present, and used labels plus evidence and reviewer fields.
- Added scripts/pin_images.py to pull candidate references for the target platform and write immutable RepoDigest references to the image manifest without enabling scans.
- Added scripts/run_experiment.py to enforce digest references, record tool versions and commands, generate CycloneDX JSON SBOMs, retain per-scan results, and write a run manifest.
- Added scripts/compare_sboms.py to match generated CycloneDX components against selected ground-truth state and output per-image metrics, mismatch records, and pairwise Jaccard agreement.
- Updated README.md with the research workflow and quick start.

The first analysis implementation covers component-set comparison. Dependency-edge accuracy, detailed metadata-field accuracy, ecosystem-stratified aggregation, and statistical testing remain planned enhancements. No experimental scans have been run yet; images remain disabled until digests are resolved and reviewed.
