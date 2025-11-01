#!/usr/bin/env bash

PRIVATE_KEY="$1"

if [ -z "$PRIVATE_KEY" ]; then
  echo "Usage: $0 <private_key_file>"
  exit 1
fi

chmod 600 "$PRIVATE_KEY"
ssh-keygen -y -f $PRIVATE_KEY | diff -b - "$PRIVATE_KEY.pub"


