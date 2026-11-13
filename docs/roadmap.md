# Delivery map

[MITHRIL-2471](https://linear.app/kotobalabs/issue/MITHRIL-2471): initial repo, CLJC contracts, bounded local lexical review and tests. Source publication and test execution are separate outcomes.

| Product capability | Current implementation | Next owning work |
| --- | --- | --- |
| Autonomous pentesting | Bounded deterministic in-process IDOR reproduction; no live sandbox or model planner | MITHRIL-2467: verified grants, bounded executor, test-identity and reproduction fixtures |
| PR reviews | Local source candidates only; no GitHub permissions, Checks or PR access | MITHRIL-2203 / 2204: exact commit-object acquisition and authenticated translation adapter |
| Auto-Fix | Evidence-bound controlled-fixture patch proposal, review admission and retest | MITHRIL-2468 / 2205: evidence-bound proposals, independent review, trusted PR creation and retest |
| Continuous coverage | No scheduler, event receiver or durable deduplication | MITHRIL-2469: authenticated triggers, transactional deduplication, fencing, recovery |
| Infrastructure | No provider credentials or inventory adapter | MITHRIL-2470: least-privilege read inventory first, scope/egress validation |
| Public UX | Separate Fund candidate PR2482 / Figma Grid dark + Porcelain light | MITHRIL-2466 / 2465; source integration and release remain separate |
| End-to-end service availability | Not qualified | MITHRIL-2208 |

Do not duplicate or mark these parent workstreams Done after the bootstrap. A small source reviewer is not a Strix feature-equivalent engine.

## First integration acceptance

1. Execute BB and JVM tests at the exact public source revision; execute CLJS tests for the portable namespaces.
2. Verify fail-closed limits, denied/revoked/expired grants, scope changes, cancellation, empty scope, invalid source encoding and symlink exclusions.
3. Translate current Fund evidence to/from a versioned public schema without losing source/tenant/coverage binding. Reject stale/tampered/mixed-run evidence.
4. Add a fixture-only executor with deny-default egress and verified test identities before any authorized active target. Separately qualify deadline/cancellation and container failure/unknown outcomes.
5. Add model planning only behind typed proposals and the same policy gate. No model/provider chosen or key required by this bootstrap.
