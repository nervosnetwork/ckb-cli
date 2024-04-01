#!/bin/bash

set -eu

CKB_CLI_DIR="$(pwd)"
BRANCH="${1:-master}"

cp -f Cargo.lock test/Cargo.lock
rm -rf test/target && ln -snf ../target/ test/target

mkdir -p ../ckb-cli-integration
cd ../ckb-cli-integration

cd ${CKB_CLI_DIR}
make prod
cd ../ckb-cli-integration

if [[ "$BRANCH" == v* ]] && [[ "$(uname)" != Darwin ]]
then
    if [ ! -f "ckb_${BRANCH}_x86_64-unknown-linux-gnu.tar.gz" ]; then
        curl -L -O "https://github.com/nervosnetwork/ckb/releases/download/${BRANCH}/ckb_${BRANCH}_x86_64-unknown-linux-gnu.tar.gz"
        tar -xzf "ckb_${BRANCH}_x86_64-unknown-linux-gnu.tar.gz"
    fi
    CKB_BIN="$(pwd)/ckb_${BRANCH}_x86_64-unknown-linux-gnu/ckb"
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
    # make prod_portable
    echo "building portable ckb"
    CKB_BIN="$(pwd)/target/prod/ckb"
    if [ ! -f $CKB_BIN ]; then
        make prod_portable
    fi
fi

cd $CKB_CLI_DIR

# Build keystore_no_password plugin
cd plugin-protocol && cargo build --example keystore_no_password && cd ..

rm -rf test/target && ln -snf "${CKB_CLI_DIR}/target" test/target
export RUST_LOG=ckb_cli=info,cli_test=info

cd test && cargo run -- \
                 --ckb-bin "${CKB_BIN}" \
                 --cli-bin "${CKB_CLI_DIR}/target/release/ckb-cli" \
                 --keystore-plugin "${CKB_CLI_DIR}/target/debug/examples/keystore_no_password"
