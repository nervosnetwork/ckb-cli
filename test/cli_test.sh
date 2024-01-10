#!/usr/bin/env bash
set -evxo pipefail

# assert must contains one argument
if [ $# -ne 1 ]; then
	echo "Usage: $0 <ckb-cli-bin>"
	exit 1
fi

CKB_CLI_BIN=$1

function account_import_process_substitution {

	HOME1=$(mktemp -d)
	export CKB_CLI_HOME=${HOME1}
	printf "abc123\nabc123" | ("${CKB_CLI_BIN}" account new)

	LOCK_ARG=$("${CKB_CLI_BIN}" account list --output-format json | jq '.[0].lock_arg' | sed 's/"//g')

	PRIV_PATH=$(mktemp -d)/privkey.text
	printf "abc123" | ("${CKB_CLI_BIN}" account export --lock-arg ${LOCK_ARG} --extended-privkey-path ${PRIV_PATH})

	HOME1=$(mktemp -d)
	export CKB_CLI_HOME=${HOME1}
	printf "ABC123" | "${CKB_CLI_BIN}" account import --privkey-path <(cat "${PRIV_PATH}")

}

account_import_process_substitution
