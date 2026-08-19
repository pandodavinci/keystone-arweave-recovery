#!/bin/sh
set -eu
umask 077

export_script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
export_output_dir=${1:-"$export_script_dir/private-output"}
export_filename="arweave-keyfile.json"

if [ ! -d "$export_output_dir" ]; then
  mkdir -m 700 -p "$export_output_dir"
fi
export_output_dir=$(CDPATH= cd -- "$export_output_dir" && pwd -P)

if [ -e "$export_output_dir/$export_filename" ]; then
  echo "ERROR: refusing to overwrite existing private keyfile:" >&2
  echo "$export_output_dir/$export_filename" >&2
  exit 2
fi

echo "PRIVATE-KEY EXPORT: keep Wi-Fi, Ethernet, and Bluetooth disabled."
echo "Output directory: $export_output_dir"

if docker run --rm -it \
  --network none \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --user "$(id -u):$(id -g)" \
  --mount "type=bind,src=$export_output_dir,dst=/output" \
  --entrypoint /usr/local/bin/keystone-arweave-exporter \
  keystone-arweave-checker:verified; then
  chmod 600 "$export_output_dir/$export_filename"
  echo
  echo "Created private keyfile:"
  echo "$export_output_dir/$export_filename"
else
  export_status=$?
  echo "Exporter stopped; check the message above." >&2
  exit "$export_status"
fi
