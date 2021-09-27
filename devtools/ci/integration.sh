#!/bin/bash

set -eu

CKB_CLI_DIR="$(pwd)"
BRANCH="${1:-master}"

cp -f Cargo.lock test/Cargo.lock
rm -rf test/target && ln -snf ../target/ test/target

mkdir -p ../ckb-cli-integration
cd ../ckb-cli-integration

# Install ckb-indexer
if [ ! -d "ckb-indexer" ]; then
    git clone --depth 1 --branch v0.3.0 https://github.com/nervosnetwork/ckb-indexer.git
fi
cd ckb-indexer
cargo build --release
CKB_INDEXER_BIN="$(pwd)/target/release/ckb-indexer"
cd ..

if [[ "$BRANCH" == v* ]]; then
    if [ "$(uname)" = Darwin ]; then
        if [ ! -f "ckb_${BRANCH}_x86_64-apple-darwin.zip" ]; then
            curl -L -O "https://github.com/nervosnetwork/ckb/releases/download/${BRANCH}/ckb_${BRANCH}_x86_64-apple-darwin.zip"
            unzip "ckb_${BRANCH}_x86_64-apple-darwin.zip"
        fi
        CKB_BIN="$(pwd)/ckb_${BRANCH}_x86_64-apple-darwin/ckb"
    else
        if [ ! -f "ckb_${BRANCH}_x86_64-unknown-linux-gnu.tar.gz" ]; then
            curl -L -O "https://github.com/nervosnetwork/ckb/releases/download/${BRANCH}/ckb_${BRANCH}_x86_64-unknown-linux-gnu.tar.gz"
            tar -xzf "ckb_${BRANCH}_x86_64-unknown-linux-gnu.tar.gz"
        fi
        CKB_BIN="$(pwd)/ckb_${BRANCH}_x86_64-unknown-linux-gnu/ckb"
    fi
else
    if [ -d "ckb" ]; then
        cd ckb
        echo ">> checkout branch ${BRANCH}"
        git checkout ${BRANCH}
        git pull
    else
        echo ">> clone branch ${BRANCH}"
        git clone --depth 1 --branch ${BRANCH} https://github.com/nervosnetwork/ckb.git
        cd ckb
    fi

    rm -rf target && ln -snf ${CKB_CLI_DIR}/target target
    make prod
    CKB_BIN="$(pwd)/target/release/ckb"
fi

cd ${CKB_CLI_DIR}
make prod
# Build keystore_no_password plugin
cd plugin-protocol && cargo build --example keystore_no_password && cd ..

rm -rf test/target && ln -snf "${CKB_CLI_DIR}/target" test/target
export RUST_LOG=ckb_cli=info,cli_test=info
cd test && cargo run -- \
          --ckb-bin "${CKB_BIN}" \
          --ckb-indexer-bin "${CKB_INDEXER_BIN}" \
          --cli-bin "${CKB_CLI_DIR}/target/release/ckb-cli" \
          --keystore-plugin "${CKB_CLI_DIR}/target/debug/examples/keystore_no_password" && \
    cargo run -- \
             --ckb-bin "${CKB_BIN}" \
             --cli-bin "${CKB_CLI_DIR}/target/release/ckb-cli" \
             --keystore-plugin "${CKB_CLI_DIR}/target/debug/examples/keystore_no_password"

