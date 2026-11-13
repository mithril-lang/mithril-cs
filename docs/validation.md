# Validation state

2026-11-13: VKE execution qualified at source `cf9a3b384a5b079033c8d59b763dc20e81f7c17e`, tree `7b22203e781625f284f9f4399bc237072b50edbe`. This document records source qualification, not hosted service availability. Later integrated-main results belong to MITHRIL-2471 with their actual revision.

## Runtime results

Job `mcs-cf9a3b384a-bc1eb6`, UID `34a76cfc-478d-4c79-9541-1d1079c7eac1`; Pod UID `84733dbc-ecc1-48f3-bc4f-78f74832471f`: Complete, exit0, zero restarts.

| Verification | Observed result |
| --- | --- |
| JVM Clojure1.12.0 / Java21 | 15 tests,82 assertions,0 failures/errors |
| ClojureScript1.11.132 / Node22 | 10 tests,63 assertions,0 failures/errors |
| Babashka | 15 tests,82 assertions,0 failures/errors |
| Source-review and controlled IDOR CLI | Completed |
| Controlled Auto-Fix review, tamper rejection and retest | Included in portable suite |
| Private Kubernetes API egress | Denied from credential-free test Pod |

Full-runtime image: `docker.io/library/clojure@sha256:3bf1f971f18c68352e90e33f15435ed18e2f7ed040f1cd6baa1e8aa87b588593`. Tool image digests, bounded source/blob acquisition, dependency /32 egress, resource admission, terminal observation and lease release are defined in `tools/vke_verify.py`. Logs SHA-256: `627a8bc42367ecc775e4b505de5152fc239c99a0336f16fa9d7bf1160eb65fd3`.

Separate VKE recovery contracts: source `88638f9acb306f99f229f0cd6f04c1874e09d258`, Job `mcs-88638f9acb-d84b8a`, five Python selftests passed. Source `74f80a400bb2c19aec1546ff94ebcff1aef966e9`, Job `mcs-74f80a400b-5aa510`:200 orphan children reaped with zero zombies, exit42 propagated, process-group SIGTERM fixture passed. These are synthetic cases, distinct from actual router recovery.

## Recovery and custody

The resident router was recovered under MITHRIL-2327 with checksum-pinned Tini as PID1, preserving primary state, device identity and logical owner. The old writer was fenced before same-holder lease reconciliation. Native Tailscale authenticated node reads passed; anonymous nodes403 and invalid-token401 were observed. Long-term stability, Cloud-origin reconnect and remaining rotation/restart acceptance remain open.

The original foreign Failed Pod remains UNKNOWN and untouched, reserving4GiB/2CPU. Jun-authorized additional bounded capacity uses existing node headroom, a separate namespace/quota, nonpreempting priority and exclusive operation lease. No new paid node was needed. Local admission remained unavailable.

Generated logs remain in retained VKE Pods; metadata/source/image/hash journals remain in cluster ConfigMaps and Linear. This is not a verified durable R2/catalog archive. Do not delete evidence before approved cloud custody and recovery are verified. No raw logs, generated build outputs or credentials are published in Git.

## Failed attempts retained

An initial PriorityClass admission error did not start a Pod and was reconciled separately. Original strict terminal checks first rejected the foreign Pod; they remain intact. The first full-runtime attempt at `6455e9fe44ba3acf36bde614cfc2b24299a354b9` failed before tests because JVM user.home pointed into the read-only root; the successful source sets it to ephemeral /tmp. No test assertions, cases or timeouts were weakened.

## Open delivery boundaries

Live-target pentesting, model planning, real repository patch/PR publication, hosted continuous scanning, verified target authority, Fund evidence translation and cs.mithril.fund service deployment remain unqualified or unimplemented. See [roadmap](roadmap.md). Source integration does not close those feature issues.
