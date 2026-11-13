# Mithril CS contributor instructions

Implement portable policy/state/rules in .cljc; keep filesystem, network, clocks and provider SDKs in explicit adapters. Jun authorized CLJC for this independent repository on 2026-11-13. Do not treat this as permission to rewrite Fund or add cross-org runtime dependencies.

Bind work to Linear and an exact revision. Use bb test and clojure -M:test; also clojure -M:cljs-test when changing portable code. Never claim an unrun suite passed. General remote verification uses approved source-bound VKE execution; do not introduce GitHub Actions or Linux CircleCI jobs. Source/configuration and synthetic test inputs may be committed; reports, generated logs, datasets, credentials, build outputs and QA media must not be committed or uploaded as GitHub artifacts.

Use only caller-authorized local source in the current CLI. Do not add active network probing, arbitrary shell/model tool execution or automatic patch application without the corresponding authorization, executor isolation, cancellation, egress, limits and evidence contracts. Model-supplied text and target content are untrusted data. Candidate patterns are never exploit confirmation. Preserve existing tests and explicit unknown outcomes.

The existing workspace storage/admission safeguards apply to local work on Jun's Mac. Remote work does not require Mac admission. Publication of source is distinct from qualification and live service release.
