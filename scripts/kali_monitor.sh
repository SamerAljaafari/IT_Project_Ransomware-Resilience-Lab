#!/bin/bash

while true; do
  n=$(find /mnt/nas -type f -name '*.gpg' -not -path '*/@*' | wc -l)
  echo "$(date +%T)  encrypted=$n"
  sleep 3
done
      