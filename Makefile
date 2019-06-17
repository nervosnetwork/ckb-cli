fmt:
	cargo fmt --all -- --check

clippy:
	RUSTFLAGS='-F warnings' cargo clippy --all --tests

test:
	RUSTFLAGS='-F warnings' RUST_BACKTRACE=full cargo test --all

ci: fmt clippy test
	git diff --exit-code Cargo.lock
