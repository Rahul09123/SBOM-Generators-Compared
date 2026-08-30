# SBOM Generators Compared — Full Project Plan

## 1. Project overview

**Title:** A Comparative Evaluation of SBOM Generators for Container Images: Syft, Trivy, and cdxgen

**Theme:** Software supply-chain security and DevSecOps

**Study type:** Comparative measurement study

**Duration:** August–December 2026

## 2. Objective

Measure and explain how Syft, Trivy, and cdxgen differ when identifying software components inside identical container images.

The study will evaluate:

- Component coverage and completeness
- Component-name and version accuracy
- Ecosystem and PURL accuracy
- Dependency-relationship accuracy
- SBOM-field completeness and format validity
- Reproducibility
- Practical impact on vulnerability detection

## 3. Research questions

- **RQ1:** How different are the component inventories produced by Syft, Trivy, and cdxgen for the same container image?
- **RQ2:** Which tool provides the highest precision, recall, coverage, and F1-score?
- **RQ3:** How accurately does each tool identify component names, versions, ecosystems, PURLs, and metadata?
- **RQ4:** How accurately does each tool represent dependency relationships?
- **RQ5:** Which component classes and image characteristics cause the most omissions or false positives?
- **RQ6:** How much do identifier and SBOM-format differences affect comparison results?
- **RQ7:** Do differences in generated SBOMs lead to different vulnerability results when passed to the same scanner?
- **RQ8:** Are the results stable across repeated scans and image categories?

## 4. Scope

### Included

- Container images and extracted image filesystems
- Syft, Trivy, and cdxgen
- CycloneDX JSON as the primary common format
- SPDX JSON as an optional secondary format
- OS packages, Python packages, npm packages, Java/JAR packages, native libraries, and application files
- Component-level and dependency-edge-level comparison
- Independent ground-truth construction

### Excluded from the first version

- Full Kubernetes or cloud-infrastructure scanning
- Very large production-registry benchmarking
- Using vulnerability totals as a replacement for SBOM-accuracy measurement
- Claiming universal superiority of one tool

## 5. Test corpus

### 5.1 Controlled baseline images

Use pinned image digests in the final experiment.

| Category | Candidate image | Main purpose |
|---|---|---|
| Minimal Linux | Alpine | APK packages and minimal filesystem |
| Debian Linux | `debian:bookworm-slim` | DPKG packages and shared libraries |
| Ubuntu Linux | `ubuntu:24.04` | Ubuntu package detection |
| Python | `python:3.12-slim-bookworm` | pip and Debian packages |
| Node.js | `node:22-bookworm-slim` | npm and Debian packages |
| Java | `eclipse-temurin:21-jre-jammy` | JAR and Ubuntu packages |

### 5.2 Controlled application images

Build these images using locked dependencies:

1. Python application with FastAPI or Flask, `requests`, `numpy`, and an optional dependency.
2. Node.js application with Express, Axios, Lodash, and `package-lock.json`.
3. Java Spring Boot application with direct and transitive Maven dependencies.
4. Native-library image containing explicitly installed `.so` files and a dynamically loaded library.

### 5.3 Real-world application images

Recommended projects:

- [OWASP Juice Shop](https://github.com/juice-shop/juice-shop) — Node.js and npm dependency tree.
- [Spring Petclinic](https://github.com/spring-projects/spring-petclinic) — Java/Spring/Maven dependencies.
- A small FastAPI or Django service — Python dependencies.
- Nginx — native binary, shared libraries, and OS packages.
- Redis — native application and OS dependencies.
- PostgreSQL — database image with a larger package footprint.

### 5.4 Corpus size

- Minimum pilot: 6 images
- Recommended final corpus: 12–16 images
- Suggested composition: 6 baseline, 4 controlled application, and 6 real-world images

## 6. Ground-truth methodology

Ground truth must be constructed independently. Do not automatically treat the output of one SBOM tool, or the union of all tools, as ground truth.

### OS packages

- Inspect `dpkg` databases for Debian/Ubuntu.
- Inspect `apk` databases for Alpine.
- Verify package ownership and installed versions.

### Python packages

- Inspect `pip list`, `pip show`, and `importlib.metadata`.
- Compare with `requirements.txt`, `pyproject.toml`, `poetry.lock`, or `uv.lock`.

### Node.js packages

- Inspect `package-lock.json`.
- Inspect installed `node_modules` and each package’s `package.json`.
- Separate direct and transitive dependencies.

### Java packages

- Inspect Maven or Gradle dependency trees.
- Inspect JAR filenames and manifests.
- Record libraries physically present in the final image.

### Native libraries

- Inventory `.so` files and ELF metadata.
- Inspect package ownership and dynamic linker dependencies.
- Manually verify dynamically loaded libraries.

Each ground-truth component receives four labels:

| Label | Meaning |
|---|---|
| Declared | Listed in a manifest or lockfile |
| Installed | Installed by a package manager |
| Present | Physically present in the image |
| Used | Referenced or loaded by the application |

## 7. Experimental protocol

### Step 1 — Freeze the environment

Record:

- Tool versions
- Docker/Podman version
- Host operating system and architecture
- Image tag and immutable digest
- Image architecture and base OS
- SBOM format and specification version
- Scan commands and options
- Scan timestamp
- Vulnerability-database version and date

### Step 2 — Generate SBOMs

Illustrative commands:

```bash
IMAGE="python:3.12-slim-bookworm"
mkdir -p results

syft "$IMAGE" \
  -o cyclonedx-json=results/syft.cdx.json

trivy image \
  --format cyclonedx \
  --output results/trivy.cdx.json \
  "$IMAGE"

cdxgen "$IMAGE" \
  -t docker \
  -o results/cdxgen.cdx.json
```

For the final run, replace the tag with a pinned digest. Preserve raw output without editing.

### Step 3 — Repeat selected scans

Run each tool twice on selected images to measure repeatability. Repeat all scans after any tool or configuration change.

### Step 4 — Normalize SBOMs

Normalize:

- Package names
- Versions
- Ecosystems
- Namespaces/groups
- PURLs and qualifiers
- Architecture
- Duplicate components
- Case and version formatting

Maintain separate raw and normalized datasets.

### Step 5 — Match components

Use this priority:

1. Exact PURL match
2. Normalized ecosystem + name + version match
3. Package name + version match
4. Name-only match, reported separately as a weak match

Match dependency edges using normalized component identities.

## 8. Metrics

### Component metrics

- True positives
- False positives
- False negatives
- Precision: `TP / (TP + FP)`
- Recall/coverage: `TP / (TP + FN)`
- F1-score
- Component-name accuracy
- Version accuracy
- Ecosystem accuracy
- PURL accuracy

### Dependency metrics

- Dependency-edge precision
- Dependency-edge recall
- Dependency-edge F1-score
- Missing-edge rate
- Extra-edge rate

### SBOM-quality metrics

- Required-field completeness
- Duplicate-component rate
- Unversioned-component rate
- Invalid-identifier rate
- Format-validation success rate

### Operational metrics

- Execution time
- Peak memory use where practical
- Scan failure rate
- Repeated-run agreement

Report results per image, per ecosystem, per component class, and overall.

## 9. Error analysis

Classify each important mismatch as:

- Unsupported package ecosystem
- Missing or inconsistent metadata
- Optional dependency
- Dynamic dependency
- Incorrect version inference
- PURL or namespace mismatch
- Native-library omission
- Manually copied file
- Layer or filesystem-analysis limitation
- Architecture-specific behavior
- Tool configuration or version limitation

For each category, include representative examples and explain which tool behavior caused the mismatch.

## 10. Vulnerability-impact experiment

This is a secondary experiment.

1. Generate one SBOM per tool for the same image.
2. Pass all SBOMs to the same vulnerability scanner.
3. Use the same scanner version and vulnerability-database snapshot.
4. Compare vulnerabilities caused by missing, extra, or incorrectly identified components.
5. Clearly separate scanner differences from SBOM-generator differences.

Do not use vulnerability totals as the primary accuracy metric.

## 11. Statistical analysis

- Report per-image and per-ecosystem results.
- Use medians and interquartile ranges for skewed measurements.
- Use paired comparisons because every tool scans the same image.
- Use bootstrap confidence intervals for aggregate precision, recall, and F1-score.
- Use an appropriate paired non-parametric test if the sample size supports it.
- Report both statistical significance and practical significance.

## 12. Team allocation

### Member 1 — Testbed and implementation

- Build and collect images.
- Pin image digests.
- Install and run the three tools.
- Store raw SBOMs.
- Record runtime, failures, and environment metadata.

### Member 2 — Measurement and analysis

- Build ground-truth inventories.
- Implement parsing and normalization.
- Implement component and dependency matching.
- Calculate metrics and statistical results.

### Member 3 — Related work and writing

- Maintain the literature matrix.
- Write background and related work.
- Document the error taxonomy.
- Prepare figures, tables, threats to validity, and practitioner guidance.

All members should review the protocol, ground truth, results, and final paper.

## 13. Month-wise schedule

### August — Definition and pilot

- Finalize title, scope, research questions, and hypotheses.
- Complete the literature matrix.
- Define inclusion/exclusion criteria for images.
- Select the six-image pilot corpus.
- Install the tools.
- Define the ground-truth schema.

**Milestone:** Approved research protocol and runnable pilot pipeline.

### September — Corpus and ground truth

- Build controlled application images.
- Pull and pin baseline images.
- Record image metadata.
- Extract filesystems and package inventories.
- Complete ground truth for pilot images.

**Milestone:** Pilot corpus and ground truth complete.

### October — Full data collection

- Expand to the complete 12–16 image corpus.
- Generate Syft, Trivy, and cdxgen SBOMs.
- Run repeatability checks.
- Generate optional SPDX outputs.
- Preserve raw SBOMs and logs.

**Milestone:** Raw experimental dataset complete and mid-semester review finished.

### November — Analysis and first draft

- Normalize all SBOMs.
- Match components and dependency edges.
- Calculate all metrics.
- Complete error analysis.
- Run the vulnerability-impact experiment.
- Prepare tables and figures.
- Write the first complete paper draft.

**Milestone:** Results complete and first full draft ready.

### December — Validation and finalization

- Re-run selected experiments in a clean environment.
- Review threats to validity.
- Verify citations, tables, and figures.
- Improve the practitioner guide.
- Incorporate faculty feedback.
- Finalize paper, data, code, and presentation.

**Milestone:** Submission-ready project package.

## 14. Repository structure

```text
SBOM-Generators-Compared/
├── README.md
├── PROJECT_PLAN.md
├── memory.md
├── images.csv
├── tools.csv
├── commands/
├── dockerfiles/
├── raw_sboms/
│   ├── syft/
│   ├── trivy/
│   └── cdxgen/
├── normalized_sboms/
├── ground_truth/
├── metadata/
├── scripts/
├── results/
│   ├── component_metrics.csv
│   ├── dependency_metrics.csv
│   ├── field_metrics.csv
│   └── error_categories.csv
└── paper/
```

## 15. Threats to validity

Document the following limitations:

- Limited number of images
- Bias toward selected ecosystems and official images
- Imperfect or ambiguous ground truth
- Changes in package repositories
- Changes in vulnerability databases
- Architecture-specific behavior
- Tool-version changes
- Differences between declared, installed, present, and used components
- Possible shared blind spots in ground-truth methods

## 16. Completion criteria

The project is complete when:

- At least 12 pinned container images have been evaluated.
- All three tools have been run using documented versions and commands.
- Raw SBOMs are preserved.
- Independent ground truth exists for every image.
- Matching and normalization rules are documented.
- Precision, recall, F1-score, coverage, and field-quality results are reported.
- Missed-component causes are categorized.
- Reproducibility checks have been performed.
- Threats to validity are documented.
- The final paper and practitioner guide are complete.
