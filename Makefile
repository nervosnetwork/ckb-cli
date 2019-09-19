fmt:
	cargo fmt --all -- --check
	cd test && cargo fmt --all -- --check

clippy:
	RUSTFLAGS='-F warnings' cargo clippy --all --tests
	cd test && RUSTFLAGS='-F warnings' cargo clippy --all

test:
	RUSTFLAGS='-F warnings' RUST_BACKTRACE=full cargo test --all

ci: fmt clippy test
	git diff --exit-code Cargo.lock

integration:
	bash devtools/ci/integration.sh rc/v0.20

prod: ## Build binary with release profile.
	cargo build --release
