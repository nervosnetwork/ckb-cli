#!/bin/bash
set -eu

GIT_TAG_NAME="${GIT_TAG_NAME:-"$(git describe)"}"
if [ -z "${REL_PKG:-}" ]; then
  if [ "$(uname)" = Darwin ]; then
    REL_PKG=x86_64-apple-darwin.zip
  else
    REL_PKG=x86_64-unknown-linux-gnu.tar.gz
  fi
fi

PKG_NAME="ckb-cli_${GIT_TAG_NAME}_${REL_PKG%%.*}"
ARCHIVE_NAME="ckb-cli_${GIT_TAG_NAME}_${REL_PKG}"
echo "ARCHIVE_NAME=$ARCHIVE_NAME"

rm -rf releases
mkdir releases

mkdir "releases/$PKG_NAME"
cp "$1" "releases/$PKG_NAME"
cp README.md CHANGELOG.md COPYING "releases/$PKG_NAME"

pushd releases
if [ "${REL_PKG#*.}" = "tar.gz" ]; then
  tar -czf $PKG_NAME.tar.gz $PKG_NAME
else
  zip -r $PKG_NAME.zip $PKG_NAME
fi
if [ -n "${GPG_SIGNER:-}" ]; then
  gpg -u "$GPG_SIGNER" -ab "$ARCHIVE_NAME"
fi
popd
