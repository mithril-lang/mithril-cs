# Mithril CS

**Continuous Security on Every Deploy.** The independent engine for Mithril Agent at [cs.mithril.fund](https://cs.mithril.fund).

Early development: the current implementation is a bounded, read-only local source reviewer plus a portable CLJC authorization/run/evidence core. It does **not** yet provide autonomous pentesting, exploit confirmation, hosted continuous scanning or automatic fixes. Source publication is not service availability.

## Run

Requires Babashka 1.12+ or Clojure CLI with Java 17+. No model key, Docker or target dependencies required.

```sh
bb test
bb cs review test/fixtures/demo --authorized
# JVM equivalent
clojure -M:test
clojure -M:run review test/fixtures/demo --authorized
# Portable core + rules on Node/ClojureScript
clojure -M:cljs-test
```

`--authorized` is a local caller acknowledgement that they own or may inspect these files. It is not verified domain, tenant or repository authority. There is no network scanning or target code execution. Output is EDN on stdout; keep reports private and out of Git. Exit 0 = completed configured lexical review, 2 = failed/invalid invocation, 3 = empty/incomplete coverage. Findings remain `needs-review`; a clean report does not establish security. No finding changes exit 0 into a policy block.

Limits: 250 supported files, 256 KiB/file, 4 MiB total, 10,000 entries, depth 32. Limit violations and invalid UTF-8 fail closed; symlinks and unsupported types are listed as excluded. Inspect a quiescent local source folder. Concurrent filesystem mutation is outside this reader's isolation guarantee. No excerpt/source text is included in reports, but paths, hashes and rule metadata can still be sensitive.

## Structure

- `src/mithril/cs/core.cljc`: portable grant checks, revocation, step budgets, lifecycle and evidence bindings.
- `src/mithril/cs/rules.cljc`: four advisory lexical checks, with no source execution.
- `src/mithril/cs/source.clj`, `cli.clj`: bounded filesystem adapter, SHA-256 and CLI.
- `test/`: positive/negative contract and real temporary-filesystem tests; CLJS portability checks.
- [Architecture and integration](docs/architecture.md), [roadmap](docs/roadmap.md), [security](SECURITY.md).

This is an original implementation inspired by the product category of [Strix](https://github.com/usestrix/strix), not a fork or a parity claim. Reference review: upstream revision `928b1ca66ea5a00e7fe83f0fce84c7d557ff8091`, 2026-11-13. No Strix engine code or branding copied. Apache-2.0.

Delivery tracking: [MITHRIL-2471](https://linear.app/kotobalabs/issue/MITHRIL-2471). Existing Mithril Fund security CLI/evidence integration remains under MITHRIL-2203. This repository does not depend on private Fund source.
