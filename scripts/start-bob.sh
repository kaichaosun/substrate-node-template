#!/usr/bin/env bash

set -e

echo "*** Start bob's node with Docker ***"

cargo run --target-dir ./target-bob -- \
      --bootnodes /ip4/172.28.0.2/tcp/30333/p2p/QmRpheLN4JWdAnY7HGJfWFNbfkQCb6tFf4vvA6hgjMZKrR \
      --chain=local \
      --bob \
      --telemetry-url ws://telemetry.polkadot.io:1024 \
      --ws-external \
      --validator
