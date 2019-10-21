#!/usr/bin/env bash

set -e

echo "*** Start alice's node with Docker ***"

cargo run --target-dir ./target-alice -- \
      --chain=local \
      --alice \
      --node-key 0000000000000000000000000000000000000000000000000000000000000001 \
      --telemetry-url ws://telemetry.polkadot.io:1024 \
      --ws-external \
      --validator
