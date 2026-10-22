#!/bin/bash
# Usage: bash /root/hack/airlock/dev.sh [pytest args | python args after --py]
cd /root/hack/airlock
source .venv/bin/activate
if [ "$1" = "--py" ]; then shift; exec python "$@"; fi
exec python -m pytest -q "$@"
