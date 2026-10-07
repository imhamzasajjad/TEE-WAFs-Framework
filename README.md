# TEE-WAFs-Framework

Docker-based research framework for analyzing payload datasets and comparing a
rule-based WAF with an ML-based WAF under original and fuzzed traffic.

## Overview

The framework provides a reproducible workflow with two connected stages:

1. Assess the internal quality of the input dataset before an experiment.
2. Send sampled and fuzzed payloads through both WAFs and compare their decisions.

The dataset stage checks completeness, label consistency, redundancy, balance,
entropy, and available attack-family coverage. The benchmark stage records whether
the rule-based and ML-based WAFs classified each request correctly.

## Research Context

Machine-learning WAF performance may be influenced by dataset and evaluation bias.
A model can appear effective when its dataset contains duplicates, contradictory
labels, limited attack families, unrealistic class distributions, or leakage
between training and evaluation data.

This project supports experiments across three related dimensions:

- Dataset diversity and internal quality
- Training validity
- Evaluation robustness under fuzzed inputs

WAF-Brain is used as the ML-WAF case study, while a ModSecurity/Apache container
provides the rule-based comparison.

## Components

- `client`: analyzes the dataset, samples payloads, generates fuzzed variants,
  sends requests, and records benchmark results
- `server`: accepts client requests and coordinates both WAF decisions
- `ml_waf`: selectable ML service; WAF-Brain is the default provider
- `rb_waf`: ModSecurity/Apache rule-based WAF

## Architecture and Workflow

```mermaid
flowchart LR
   D[(payloads.csv)] --> A[Dataset quality analysis]
   A --> Q[(Dataset Analysis reports)]
   A --> C[Sampling and SQL/XSS fuzzing]
   C --> S[server :5000]
   S --> W[rb_waf]
   S --> M[ml_waf :8000]
   C --> R[(Benchmark results and logs)]
```

Execution order:

1. The client reads `payloads.csv` and validates its schema.
2. If enabled, it analyzes the complete dataset and prints a quality report.
3. It saves detailed JSON and CSV analysis artifacts.
4. It randomly selects the configured number of original payloads.
5. It sends each original payload and its generated fuzzed variants to the server.
6. The server obtains decisions from `rb_waf` and `ml_waf`.
7. The client writes individual outcomes, confusion counts, and a combined matrix.
8. Docker Compose stops the stack after the client finishes when run with the
   recommended command below.

## Prerequisites

- Docker Desktop, including Docker Compose
- Git
- Optional: Python 3.9+ for local development

Verify Docker before starting:

```powershell
docker --version
docker compose version
```

## Quick Start

Clone the repository:

```powershell
git clone --recurse-submodules https://github.com/imhamzasajjad/TEE-WAFs-Framework
cd TEE-WAFs-Framework
```

Build and run the complete experiment:

```powershell
docker compose up --build --abort-on-container-exit --exit-code-from client
```

If `ANALYZE_DATASET` is enabled, the client first prints the dataset report, then
sends the configured original and fuzzed payloads. After the final combined result, Compose stops the remaining
services and returns the client's exit code.

For subsequent runs that do not contain source changes:

```powershell
docker compose up --abort-on-container-exit --exit-code-from client
```

Stop and remove the stack manually if required:

```powershell
docker compose down
```

## Client Configuration

Client settings are read from the project `.env` file. Compose passes them to the
client container using the variable defaults in
[`docker-compose.yml`](docker-compose.yml):

```yaml
services:
  client:
    environment:
      - ANALYZE_DATASET=yes
      - NUM_SAMPLES=1
      - NUM_FUZZING_ROUNDS=1
      - PAYLOAD_SCOPE=malicious_only
```

| Variable | Purpose |
|---|---|
| `ANALYZE_DATASET` | `yes` runs analysis; `no` skips it during repeated experiments. |
| `PAYLOADS_FILE` | Dataset path; supports `payload/status code` and `Payloads/Class` formats. |
| `NUM_SAMPLES` | Number of original rows randomly selected from the dataset. |
| `NUM_FUZZING_ROUNDS` | Number of fuzzed variants generated per selected row. |
| `PAYLOAD_SCOPE` | `malicious_only` fuzzes only rows labelled 403 for adversarial-evasion testing; `both` includes malicious and benign rows. |
| `MAX_MUTATED_LENGTH` | Maximum XSS mutation length; defaults to 2048 characters. |
| `FUZZER_TYPE` | Fuzzing family: `sql`, `xss`, `html`, or `javascript`. |
| `DATASET_ANALYSIS_DIR` | Report directory; defaults to `Dataset Analysis`. |
| `ML_WAF_PROVIDER` | ML provider: `wafbrain` (default), `ml_based_waf`, or `xss_waf`. |

### Selecting the ML provider

The client/server contract stays unchanged when the model changes. Select the
provider in a `.env` file next to `docker-compose.yml`:

```env
ML_WAF_PROVIDER=wafbrain
```

WAF-Brain is currently installed and is the default. The `ml_based_waf` and
`xss_waf` providers are loaded through adapters that preserve the same HTTP
contract. Their model artifacts and preprocessing are third-party research
code, so benchmark reports should record the pinned commit and model files.

Provider sources:

- [`BBVA/waf-brain`](https://github.com/BBVA/waf-brain) — default SQL-focused model
- [`vladan-stojnic/ML-based-WAF`](https://github.com/vladan-stojnic/ML-based-WAF) — SQLi/XSS research candidate
- [`Jeff-Rowell/XSS-WAF`](https://github.com/Jeff-Rowell/XSS-WAF) — lightweight XSS/SQLi research baseline

The provider layout and pinned model commits are documented in
[`ml_waf/PROVIDERS.md`](ml_waf/PROVIDERS.md). The external model folders are
kept directly under `ml_waf/` so each provider can be inspected or replaced
independently.

### Fuzzing modes

The client supports two payload mutation families. `FUZZER_TYPE=sql` uses the
SQL mutator in [`client/sqlfuzzer.py`](client/sqlfuzzer.py), including comment,
whitespace, case, tautology, numeric-representation, and operator rewrites.
`FUZZER_TYPE=xss` uses [`client/xssfuzzer.py`](client/xssfuzzer.py) and applies
HTML/JavaScript mutations such as tag-case changes, HTML comment insertion and
rewriting, wrapper tags, JavaScript comment insertion, function-argument
rewriting, function aliases, and attribute-context variants (`onerror`,
`onload`, and `javascript:` URL attributes). Both modes use the
same sampling, request, result, and logging pipeline. Select the intended family
explicitly in `.env` for each experiment.

### Adversarial-evasion mode

For WAF-bypass experiments, use:

```env
FUZZER_TYPE=xss
PAYLOAD_SCOPE=malicious_only
```

The client selects only source rows labelled `403`, keeps that malicious label as
the expected result for every mutation, and treats a `200` response as a possible
evasion (false negative). This prevents benign text that is wrapped in XSS syntax
from being incorrectly counted as an adversarial result. Set
`PAYLOAD_SCOPE=both` when a mixed malicious/benign evaluation is required.

Fuzzing rounds are cumulative: each round mutates the result of the previous
round in the legacy implementation. The current XSS fuzzer instead starts each
round from the original payload, selects one non-repeating operator, enforces
`MAX_MUTATED_LENGTH`, and records the operator and validation result. SQL
fuzzing behavior is unchanged.

The client automatically normalizes common labels: `Malicious`/`Attack`/`1`
become HTTP status `403`, while `Benign`/`Normal`/`0` become `200`. This allows
the original SQL dataset and the Mereani/Howe XSS dataset to be tested without
editing the downloaded source files.

Enabled values for `ANALYZE_DATASET` are `yes`, `true`, `on`, and `1`, ignoring
case. Other values disable analysis. When disabled, payload testing runs normally
and existing analysis reports remain unchanged.

## Dataset Quality Analysis

### Input format

The default input is [`client/Dataset/payloadshttp.csv`](client/Dataset/payloadshttp.csv).
It must contain a payload column and a label or HTTP-status column. The client
also accepts the downloaded XSS format with `Payloads,Class` columns:

```csv
payload,status code
"normal search query",200
"' OR 1=1 --",403
```

The analyzer recognizes common alternatives including `request`, `text`, `input`,
`query`, `label`, `class`, and `target`. If an `attack category`, `attack type`,
`category`, or `family` column exists, attack-family coverage is also reported.

### What is measured

| Dimension | Measurements | Why it matters |
|---|---|---|
| Integrity | Valid rows, missing payloads/labels, conflicting labels | Broken or contradictory records weaken training and evaluation. |
| Payload diversity | Canonical uniqueness and character vocabulary | Indicates whether the input contains varied payloads. |
| Redundancy | Exact and normalized duplicates | Repetition can inflate results and overrepresent patterns. |
| Label balance | Counts and normalized Shannon entropy | Imbalance can bias a classifier toward the majority class. |
| Payload complexity | Per-payload character entropy and length statistics | Describes internal payload structure and variation. |
| File structure | Whole-file and 256-byte chunk entropy | Exposes repetitive or compositionally different file regions. |
| Attack coverage | Category counts when metadata is available | Shows which attack families are represented. |

Canonical comparison URL-decodes payloads, converts them to lowercase, collapses
whitespace, and trims surrounding whitespace. This catches records that differ in
formatting but represent the same normalized payload.

Whole-file and chunk entropy are diagnostic evidence, not direct score inputs. CSV
formatting, encoding, row order, repeated labels, compression, and random noise can
change byte entropy without making the dataset more useful.

### Score and verdict

The internal quality score combines four components:

- Integrity: 30%
- Payload diversity: 30%
- Low redundancy: 20%
- Label balance: 20%

| Score | Verdict | Interpretation |
|---:|---|---|
| 80-100 | Suitable | Strong internal structure for an experiment. |
| 60-79.99 | Usable with caution | Review warnings before using the dataset. |
| 40-59.99 | High risk | Important quality problems may affect results. |
| 0-39.99 | Unsuitable | Correct the dataset before testing. |

Critical conditions—including an empty or very small dataset or excessive label
conflicts—cap the verdict at `Unsuitable`. The thresholds are transparent research
defaults and may need calibration for another domain.

The verdict describes **internal dataset quality**. It is not proof that a dataset:

- Represents real production traffic
- Covers every attack family
- Is free from collection or source bias
- Has no train/test leakage
- Is suitable for every ML-WAF architecture

Leakage analysis requires split membership or separate training and test files.
Semantic coverage requires category metadata or a trusted reference dataset.

### Console output

When enabled, analysis is printed before any payload is sent:

```text
================================================================
DATASET ANALYSIS
================================================================
Verdict                  : Suitable
Overall score            : 99.32/100
Total / valid rows       : 19275 / 19275
Label distribution       : 200: 7953, 403: 11322
Exact duplicate rows     : 76
Canonical duplicate rows : 94
Conflicting labels       : 2
Mean character entropy   : 3.2497 bits
Whole-file byte entropy  : 4.5277 bits/byte
Chunk entropy mean/range : 4.1147 (3.0968-5.0178) bits/byte
Attack categories        : unavailable (no category column)
================================================================
```

### Generated reports

The client creates `client/Dataset Analysis/` automatically. Its Compose volume
keeps these files on the host:

- `dataset_analysis.json`: complete machine-readable evidence, verdict, critical
  findings, thresholds, and limitations
- `dataset_analysis.csv`: compact table of scored quality components
- `chunk_entropy.csv`: entropy measurement for each 256-byte file region

Generated report files are intentionally ignored by Git because each run can
replace them. The directory itself is retained in the repository.

The current payload data originates from the
[HTTP Params Dataset](https://www.kaggle.com/datasets/evg3n1j/httpparamsdataset).

## Benchmark Results

For every original and fuzzed payload, the client records:

- Expected/original status
- Rule-based WAF status
- ML-WAF status
- Whether each WAF was correct
- Whether both systems agreed or disagreed

Each `client_logs.csv` begins with an **Experiment Configuration** section that
records the dataset, fuzzer, ML provider, RB firewall, sample count, fuzzing
rounds, and payload scope used for that run. This makes the results traceable to
the actual container configuration.

In `malicious_only` mode, report baseline errors separately from mutation
evasions. For example, an original malicious payload classified as `200` is a
baseline false negative; a fuzzed malicious payload classified as `200` is a
mutation-induced evasion.

It also calculates TP, TN, FP, and FN totals and prints a combined 2x2 comparison:

```text
Combined Results (2x2 Matrix):
               RB Correct     RB Incorrect
ML Correct     2              0
ML Incorrect   0              0
```

## Output Locations

- `client/Dataset Analysis/`: dataset score, evidence, and chunk entropy
- `client/logs/`: request-level client results and aggregate metrics
- `client/Results/`: stored experiment results
- `server/logs/`: server-side request decisions
- `rb_waf/logs/`: rule-based WAF logs, when available

## Testing the Analyzer

The analyzer uses the Python standard library and has focused unit tests:

```powershell
cd client
python -m unittest discover -s tests -v
```

## Troubleshooting

If updated client functionality does not appear, rebuild only the client image:

```powershell
docker compose down
docker compose build --no-cache client
docker compose up --abort-on-container-exit --exit-code-from client
```

Inspect individual service logs:

```powershell
docker compose logs client
docker compose logs server
docker compose logs ml_waf
docker compose logs rb_waf
```

If ports are busy, check local services using ports `5000` and `8000`. Ensure Docker
Desktop has sufficient CPU and memory if builds or services stop unexpectedly.

## Additional Documentation

- ML module: [`ml_waf/README.rst`](ml_waf/README.rst)
- ML contribution guide: [`ml_waf/CONTRIBUTING.md`](ml_waf/CONTRIBUTING.md)
