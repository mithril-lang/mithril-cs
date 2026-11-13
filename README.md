# Mithril CS

**Continuous Security on Every Deploy.**

Independent CLJC engine for Mithril Agent / [cs.mithril.fund](https://cs.mithril.fund).
Early source development; the hosted autonomous pentesting service is not qualified or available through this repository.

## Initial implementation

[Draft PR #1](https://github.com/mithril-lang/mithril-cs/pull/1) contains the CLJC policy/run/evidence core, bounded read-only source-review CLI, test suites and architecture.

Review or check out branch `codex/bootstrap-2471` to use those files. They have not yet been integrated into main. BB/JVM/CLJS runtime tests remain unexecuted; no passing qualification is claimed.

The implemented slice produces advisory candidates from local authorized source. Active pentesting, exploit confirmation, PR publication, Auto-Fix, scheduling and infrastructure adapters remain future work.

- [Implementation README](https://github.com/mithril-lang/mithril-cs/blob/codex/bootstrap-2471/README.md)
- [Architecture](https://github.com/mithril-lang/mithril-cs/blob/codex/bootstrap-2471/docs/architecture.md)
- [Roadmap](https://github.com/mithril-lang/mithril-cs/blob/codex/bootstrap-2471/docs/roadmap.md)
- [Validation state](https://github.com/mithril-lang/mithril-cs/blob/codex/bootstrap-2471/docs/validation.md)
- [Linear MITHRIL-2471](https://linear.app/kotobalabs/issue/MITHRIL-2471)

Original implementation inspired by the product category of [Strix](https://github.com/usestrix/strix), without copying its engine code or branding. Intended license: Apache-2.0, included in the implementation PR.
