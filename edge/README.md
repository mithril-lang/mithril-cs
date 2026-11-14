# Mithril CS Cloudflare console

MITHRIL-2206 /2466 /2468. Standalone product host cs.mithril.fund, approved Grid dark / Porcelain light. Public catalog, CSS tokens, locale catalog and original Mithril SVG are pinned copies of Mithril Fund source86cb61cc382ab229c0cb92e295f6959a4be6a892; provenance manifest records input hashes. No external-organization runtime or Kotoba dependency.

The Worker calls existing Mithril Auth and Workspace through fixed service bindings. It forwards only mf_session to fixed endpoints. Every read/write checks the actual session, every write checks exact Origin and session-bound HMAC CSRF, and each asynchronous step rechecks identity/project/target version. Account, project and session fingerprints fence browser response mixing. Personal CS workspace and personally owned existing project documents are supported; shared-organization Project Apps/installation grants remain a separate integration, not inferred from the login.

D1 stores CS targets, scoped run records, triage, evidence-bound fix proposals and audit events; it is not an identity or credential store. No existing state authority is migrated. One active run per owner/target, stable operation UUID, conditional terminal writes, cancellation, expiry reconciliation and source/evidence digests preserve unknown outcomes. No scan/write starts on page load. Logout uses the existing revocation endpoint.

Initial execution is explicitly limited to owner-approved Mithril company root HTTPS URLs, DNS TXT control proof, configured host allowlist and qualified public Cloudflare DNS ranges. One GET, no redirects/cookies/auth headers, 15 seconds, 1 MiB and25second run budget. Arbitrary customer destinations, active probes, browser/authenticated/API discovery and continuous jobs are not enabled. The compiled CLJC edge policy reviews five header controls; it is a separate bounded execution mode, not the93-rule Babashka scanner or a vulnerability certificate.

Fixes are real evidence-bound response-header configuration proposals. Review/approve/reject/export and retesting persist. Exports explicitly say applied=false; they do not publish a GitHub PR or deploy infrastructure. GitHub App authority/PR publication and compatibility-qualified application remain2468 work, with no personal/admin credential projected into the Worker.

## Build and test

- bb test
- clojure -M:test
- clojure -M:cljs-test
- clojure -M:edge-build
- cp /tmp/mithril-edge-engine.mjs edge/engine.mjs
- node --test edge/worker.test.mjs

The owner VKE driver --edge-console runs all existing core checks plus compilation and adapter tests, preserving assertions and admission/lease guards. edge/engine.mjs is a deployment artifact, never Git. The publisher must verify exact admitted source/tree, compiled artifact digest, module read-back and dedicated DB/schema before attaching the domain. No target fetch or test principal bypass is embedded in production. Unit fixtures replace services only in the test process.

Generated reports and compiled artifacts use qualified dedicated private mithril-cs-evidence custody and per-run Catalog indexes, no GitHub artifacts. Invocation logs/traces remain disabled under workspace privacy policy; structured operational evidence is scoped/redacted, source-bound and private. Actual bucket retention and read-back must be verified. Source/configuration and synthetic fixtures remain in Git.

## CI memory accounting review (2206)

Initial admission retains6 GiB free and48 GiB disk. For this edge recipe only, once the exact owned active Pod is observed, available memory plus that Pod's fresh measured working-set bytes must still meet6 GiB. Credit is at most its fixed1 GiB limit, requires the exact owner Pod UID, one metrics row, age<=30 seconds and the unchanged single-container/no-ephemeral boundary. This preserves4 GiB foreign unknown reservation plus1 GiB free margin and the unused portion of the owned1 GiB budget. Before ownership or with foreign/stale/duplicate/over-limit metrics, there is no credit. Existing non-edge recipes are unchanged. Seven pure owner-controller tests and live per-run min/max/sample aggregates qualify this accounting; it is not permission to clear any foreign hold or raise a node limit. Prior failed Job/Pod/journal is retained and its exact owned Lease released only after terminal read-back.
