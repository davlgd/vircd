#!/bin/sh
set -eu
adapter_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
: "${VIRCD_BIN:?Set VIRCD_BIN to an absolute vIRCd binary path}"
: "${IRCTEST_SRC:?Set IRCTEST_SRC to the pinned irctest checkout}"
: "${IRCTEST_PYTHON:?Set IRCTEST_PYTHON to the uv virtualenv Python path}"
export PYTHONPATH="$adapter_dir:$IRCTEST_SRC${PYTHONPATH:+:$PYTHONPATH}"
cd "$IRCTEST_SRC"
exec "$IRCTEST_PYTHON" -m pytest --controller vircd_controller "$@"
