# -D clippy::fallible_impl_from
CLIPPY_OPTS := -D warnings -D clippy::clone_on_ref_ptr -D clippy::enum_glob_use \
	-A clippy::mutable_key_type -A clippy::upper_case_acronyms

fmt:
	cargo fmt --all -- --check
	cd test && cargo fmt --all -- --check

clippy:
	cargo clippy --all --all-targets --all-features -- ${CLIPPY_OPTS}
	cp -f Cargo.lock test/Cargo.lock && cd test && cargo clippy --all -- ${CLIPPY_OPTS}

test:
	RUST_BACKTRACE=full cargo test --all

ci: fmt clippy test security-audit check-crates check-licenses
	git diff --exit-code Cargo.lock

integration:
	bash devtools/ci/integration.sh v0.106.0

prod: ## Build binary with release profile.
	cargo build --release

security-audit: ## Use cargo-deny to audit Cargo.lock for crates with security vulnerabilities.
	cargo deny check --hide-inclusion-graph --show-stats advisories sources

check-crates: ## Use cargo-deny to check specific crates, detect and handle multiple versions of the same crate and wildcards version requirement.
	cargo deny check --hide-inclusion-graph --show-stats bans

check-licenses: ## Use cargo-deny to check licenses for all dependencies.
	cargo deny check --hide-inclusion-graph --show-stats licenses

.PHONY: test clippy fmt integration ci prod security-audit check-crates check-licenses
