fmt:
	cargo fmt --all -- --check

test:
	RUSTFLAGS='-F warnings' RUST_BACKTRACE=full cargo test --all

clippy:
	RUSTFLAGS='-F warnings' cargo clippy --all --tests

ci: fmt clippy test
	git diff --exit-code Cargo.lock
