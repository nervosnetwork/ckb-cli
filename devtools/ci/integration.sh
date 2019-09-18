CKB_CLI_DIR=`pwd`
BRANCH=$1

cp -f Cargo.lock test/Cargo.lock
rm -rf test/target && ln -snf ../target/ test/target

mkdir -p ../ckb-cli-integration
cd ../ckb-cli-integration
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
CKB_DIR=`pwd`

cd ${CKB_CLI_DIR}
make prod
rm -rf test/target && ln -snf ${CKB_CLI_DIR}/target test/target
cd test && cargo run -- --ckb-bin ${CKB_DIR}/target/release/ckb --cli-bin ${CKB_CLI_DIR}/target/release/ckb-cli
