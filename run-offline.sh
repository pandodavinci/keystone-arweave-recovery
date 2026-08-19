#!/bin/sh
set -eu

exec docker run --rm -it \
  --network none \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  keystone-arweave-checker:verified

