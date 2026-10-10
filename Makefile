.PHONY: check msrv fmt clippy test init-check setup-hooks scrub-tree

# Full pre-commit check suite; CI runs the same target.
check: msrv fmt clippy test init-check

# rust-version claims only the pinned toolchain: it must equal the
# major.minor of rust-toolchain.toml's channel.
msrv:
	@claim=$$(sed -n 's/^rust-version *= *"\(.*\)"/\1/p' Cargo.toml); \
	pin=$$(sed -n 's/^channel *= *"\([0-9]*\.[0-9]*\).*"/\1/p' rust-toolchain.toml); \
	if [ -z "$$claim" ] || [ "$$claim" != "$$pin" ]; then \
		echo "msrv: Cargo.toml rust-version '$$claim' != rust-toolchain.toml channel major.minor '$$pin'" >&2; \
		exit 1; \
	fi

fmt:
	cargo fmt -- --check

clippy:
	cargo clippy --all-targets -- -D warnings

test:
	cargo test --locked

# The repo's own kit, verified by the binary this checkout builds.
init-check:
	cargo run --locked --quiet -- init --check

# The installed hooks exec brenn-scrub from PATH.
setup-hooks:
	cargo run --locked --quiet -- init
	@command -v brenn-scrub >/dev/null 2>&1 || echo "brenn-scrub not on PATH: cargo install --locked --path ."

scrub-tree:
	cargo run --locked --quiet -- tree
