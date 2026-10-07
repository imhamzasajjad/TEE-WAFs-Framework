#!/bin/sh
set -eu

provider="${ML_WAF_PROVIDER:-wafbrain}"

case "$provider" in
  wafbrain)
    echo "ML WAF provider: wafbrain"
    exec /app/myenv/bin/python -m waf_brain -T \
      --dump-file logs.txt \
      -l 0.0.0.0 \
      -A 0.0.0.0:8000
    ;;
  ml_based_waf|xss_waf)
    echo "ML WAF provider: $provider"
    exec /app/myenv/bin/python /app/provider_server.py
    ;;
  *)
    echo "Unknown ML_WAF_PROVIDER '$provider'. Use: wafbrain, ml_based_waf, or xss_waf." >&2
    exit 64
    ;;
esac
