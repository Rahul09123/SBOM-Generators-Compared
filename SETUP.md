# Research Environment Setup

## Required tools

- Git
- Docker Engine or Docker Desktop, with the daemon running
- Python 3.10 or newer (analysis scripts use only the standard library)
- Syft
- Trivy
- cdxgen

Install tools from their official documentation and record exact versions in data/tools.csv. Avoid unpinned latest tags in the final experiment.

- [Docker Desktop installation](https://docs.docker.com/desktop/setup/install/)
- [Syft installation and usage](https://github.com/anchore/syft)
- [Trivy installation](https://trivy.dev/docs/latest/getting-started/installation/)
- [cdxgen documentation](https://github.com/CycloneDX/cdxgen)

The repository pins cdxgen 13.0.0 as a local npm tool. Install its locked dependencies with:

    npm ci --prefix .tools/cdxgen

The installed node_modules directory is ignored by Git; package.json and package-lock.json keep the version reproducible.

## Prepare the repository

    git clone https://github.com/Rahul09123/SBOM-Generators-Compared.git
    cd SBOM-Generators-Compared
    docker version
    python3 --version
    syft version
    trivy --version
    ./.tools/cdxgen/node_modules/.bin/cdxgen --version

## Pin pilot images

data/images.csv contains the pinned pilot corpus, including the locally built controlled Node.js image. Re-resolve public candidate tags only if intentionally refreshing the dataset:

    python3 scripts/pin_images.py

The helper pulls each candidate and stores its immutable digest reference. Inspect the resulting CSV, verify the selected release and platform, and record retrieval date and source details in notes. The runner rejects enabled images that only have mutable tags.

## Generate SBOMs

    python3 scripts/run_experiment.py

The runner records tool versions, commands, timestamps, return codes, and component counts. It stores original CycloneDX JSON under artifacts/raw/<tool>/<image_id>/ and writes a run manifest under artifacts/runs/. A failure for one scan does not delete other results.

Run only a selected pilot image with `--images node-controlled`. The controlled fixture at `fixtures/node-controlled/` uses a pinned Node base-image digest and a committed npm lockfile. Express and Lodash are its two direct dependencies; the container installs the production dependency tree with `npm ci --omit=dev`.

## Ground truth and comparison

Populate data/ground_truth.csv using independent evidence from image package databases, installed metadata, manifests, JARs, and shared libraries. Label each component as declared, installed, present, and/or used; include evidence and reviewer initials.

The collector extracts the image filesystem and records dpkg/apk binary names plus source-package metadata, installed npm package metadata, standalone Yarn metadata, and application manifests without consulting the evaluated generators. It distinguishes package metadata in `node_modules` from test fixtures/subpath manifests, and marks app manifests as present rather than installed dependencies. For an image with a root `package.json`, it marks direct npm dependencies; this does not establish runtime use.

    python3 scripts/collect_ground_truth.py

    python3 scripts/compare_sboms.py --truth-state present

Reports are written under artifacts/reports/: accuracy by image and tool, component mismatches, and pairwise tool agreement. Matching prioritizes exact PURL, then normalized ecosystem/name/version. Name-only matches are reported as weak matches and do not count as true positives. The initial script calculates component-set metrics; dependency-edge and field-accuracy analysis are follow-up implementation tasks.

Reports are separated by truth state under `artifacts/reports/installed/` and `artifacts/reports/present/`. The comparison filters predictions to ecosystems represented in the independent truth, combines npm `group` and `name` for scoped packages, and counts unique ecosystem/name/version identities (nested duplicate copies do not add another component). It retains strict package-name metrics while separately labeling exact-version Debian/Alpine source-name aliases in `source_aliases` and the mismatch report; aliases are not silently converted into binary-package matches. Unversioned matches are counted separately because they support presence, not version accuracy. This is a pilot scope, not a claim that file records or ungrounded component classes are incorrect. “Present” does not mean “executed/used.”

## Team workflow

- Agree on tool versions and platform before collecting data.
- Keep raw SBOMs unchanged.
- Record evidence for every ground-truth component.
- Preserve previous run manifests when the protocol changes.
- Do not commit image layers, caches, or credentials.
