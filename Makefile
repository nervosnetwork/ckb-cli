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

ci: fmt clippy test security-audit
	git diff --exit-code Cargo.lock

integration:
	bash devtools/ci/integration.sh v0.42.0-rc1

prod: ## Build binary with release profile.
	cargo build --release

security-audit: ## Use cargo-audit to audit Cargo.lock for crates with security vulnerabilities.
	@cargo +nightly install cargo-audit
	cargo audit
	# expecting to see "Success No vulnerable packages found"

.PHONY: test clippy fmt integration ci prod security-audit
