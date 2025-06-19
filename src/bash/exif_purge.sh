#!/usr/bin/env bash
# exif_purge.sh – Remove EXIF metadata from images in a directory
# Usage: ./exif_purge.sh /path/to/images
# Requires: exiftool (brew install exiftool / apt-get install libimage-exiftool-perl)

if [[ $# -ne 1 ]]; then
  echo "Usage: $0 <image_dir>" >&2
  exit 1
fi

DIR="$1"
if [[ ! -d $DIR ]]; then
  echo "Directory not found: $DIR" >&2
  exit 1
fi

echo "[+] Stripping EXIF metadata under $DIR …"
find "$DIR" -type f -iname '*.jpg' -o -iname '*.jpeg' -o -iname '*.png' | while read -r img; do
  exiftool -overwrite_original -all= "$img"
  echo "Cleaned $img"
done
echo "[+] Done."
