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

## Feature workspaces (2206, 2026-11-14)

Figma section1030:45068 maps to /app/pentesting, reviews, fixes, coverage,
infrastructure, reports and risk, with original targets/runs routes retained.
Only scoped D1 records populate the displays. Coverage shows recorded execution
dates, not a schedule. Infrastructure reports the actual configured CS service
bindings, not customer cloud discovery or a security verdict. Exported JSON
preserves source, run, evidence and partial coverage. No synthetic example data
is used by production code.

Public PR review is an explicit read of configured company repositories (default
mithril-lang/mithril-cs). Both base and head are rechecked around the files read;
only added patch lines are reviewed with the four existing portable lexical
rules. Missing/omitted patches remain partial. No credentials, installation,
GitHub write, webhook, private source or automatic CI trigger is introduced.
cs_reviews is an additive table with owner/project filtering and source dedupe.
Existing records/authority are not migrated. Full App reporting/PR write and
customer-cloud/scheduled execution remain owning2204/2468/2469/2470 acceptance.

The explicit --edge-memory-mib768 profile reserves4GiB foreign UNKNOWN plus
768MiB owned allocation plus1GiB margin, retaining original CPU/storage,
identity/lease/terminal and complete test/timeouts. Default1024MiB is unchanged.
Previous37-window qualification observed owned credit max298,512,384bytes;
that is sampled usage, not a proved peak. The unchanged448MiB JVM heap plus
320MiB nonheap allowance is the bounded forecast; OOM/failure is a failure,
never a reason to omit tests. Current initial free6,270,373,888bytes falls below
6GiB but above the explicit5.75GiB allocation sum. New full-suite observation
must validate this profile; no new paid node, foreign hold removal or cache
clearing follows from it. Revisit on OOM, stale metrics, memory pressure or
measured peak above allocation. Product/source results and controller monitoring
qualification remain distinct.

### Public PR upstream limits and owner cache

Cloudflare's shared unauthenticated GitHub egress returned403 during actual UI
acceptance. A trusted owner may acquire an explicitly public configured company
PR using tools/github_public_snapshot.py and the existing gh client, without
putting credentials in the Worker or analysis jobs. Verify public repository
identity and base/head around the bounded files acquisition; publish the output
under the dedicated private R2 github-public-snapshots prefix with a content hash
and Catalog entry. Keep a content-addressed original and the exact PR pointer.

Only a GitHub rate-limit denial permits this fallback. The Worker validates the
repository/PR/source identity and rejects snapshots older than30minutes, future,
private, missing or over1MiB. Results explicitly display snapshot time and
current-head-unverified status, bind the displayed SHA and stay partial. Cache
freshness is not a webhook/CI App authority or proof of the current upstream
head. No cache refresh credential, automatic job or arbitrary import endpoint
exists in the public Worker. This is an owner-provisioned public snapshot path,
not general private-repository onboarding.
