## What and why

<!-- What changes, and what problem it solves. Link the issue if there is one. -->

## Checklist

- [ ] `cargo test` passes
- [ ] `cargo fmt --check` and `cargo clippy --all-targets -- -D warnings` are clean
- [ ] New matching behaviour has a test that fails without the change
- [ ] `src/matcher.rs` still reads no clock (timestamps stay injected)
- [ ] No new inbound network surface, or it was discussed in an issue first
- [ ] Docs updated (`README.md` / `DESIGN.md`) if behaviour or config changed
