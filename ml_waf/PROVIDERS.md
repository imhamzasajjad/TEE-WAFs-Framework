# ML provider adapters

Each external model must be exposed through the existing ML-WAF HTTP contract.

## Providers

| Name | Source | Status |
|---|---|---|
| `wafbrain` | [BBVA/waf-brain](https://github.com/BBVA/waf-brain) | Installed and default; SQL-focused model |
| `ml_based_waf` | [vladan-stojnic/ML-based-WAF](https://github.com/vladan-stojnic/ML-based-WAF) | Installed through the common adapter; SQLi/XSS research model; commit `9911b1f` |
| `xss_waf` | [Jeff-Rowell/XSS-WAF](https://github.com/Jeff-Rowell/XSS-WAF) | Installed through the common adapter; lightweight research baseline; commit `6e33221` |

The external repositories are independent research projects. Before using
their results in a paper, record the exact commit, model artifact, training
data, preprocessing, and license. A repository name alone is not enough to
guarantee that a serialized model is reproducible or compatible with this
container.

## HTTP contract

- `GET /?q=<payload>`
- HTTP `200` means the payload was accepted
- HTTP `403` means the payload was classified as malicious

The provider name is selected with `ML_WAF_PROVIDER` in `docker-compose.yml`.
`wafbrain` remains the default. The two external repositories are git
submodules pinned at the commits used by this checkout and loaded only when
selected. Clone with `--recurse-submodules`, or run
`git submodule update --init` in an existing checkout.

When adding a provider, keep its implementation isolated here and preserve
the HTTP contract so the client and experiment results do not change when the
model changes.
