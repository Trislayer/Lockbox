#!/bin/sh
# Build the Lockbox desktop app from any folder. Options: --skip-checks, --open.
exec node "$(dirname "$0")/desktop/build-app.js" "$@"
