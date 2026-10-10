# SBOM-Generators-Compared

Comparative evaluation of Syft, Trivy, and cdxgen for container-image SBOM coverage and accuracy.

See [memory.md](memory.md) for the project plan, literature log, methodology, test corpus, metrics, and decisions.

## Current status

The repository contains a reproducible seven-image pilot workflow, including a controlled Node.js application image. See [SETUP.md](SETUP.md) for setup and commands, [PROJECT_PLAN.md](PROJECT_PLAN.md) for the study design, and [memory.md](memory.md) for decisions and the execution log.

Quick start:

1. Install Docker, Python 3, Syft, and Trivy; install the pinned cdxgen dependency with `npm ci --prefix .tools/cdxgen`.
2. Review the enabled, digest-pinned pilot corpus in `data/images.csv`.
3. Run `python3 scripts/run_experiment.py` to generate raw CycloneDX SBOMs and a run manifest.
4. Run `python3 scripts/collect_ground_truth.py` to collect supported package metadata independently of the evaluated tools; audit and extend `data/ground_truth.csv`.
5. Run `python3 scripts/compare_sboms.py --truth-state installed` to produce exploratory accuracy and tool-disagreement reports.

The runner refuses enabled images without immutable `@sha256:` references. Raw results are kept under `artifacts/raw/`; generated run metadata and reports are kept under `artifacts/`. These outputs are ignored by Git so image-specific results can be reviewed before sharing. Current results are a single-run pilot; they are not final claims.
