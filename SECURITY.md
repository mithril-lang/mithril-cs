# Security policy

The core pre-release engine supports credential-free, read-only lexical review of an authorized quiescent local source folder. It is not a sandbox against hostile concurrent filesystem writers. It does not evaluate files, install target dependencies, issue network requests, invoke models or apply patches.

The separate owned scanner adapter supports explicitly authorized, bounded passive GET requests. It rechecks the written grant per request, refuses redirects, and retains its 15-second/1 MiB limits. It uses Babashka and Python standard library without Kotoba. Header omissions and HTTP lexical references are review candidates, not exploit confirmation. Namespace identifiers are excluded; unresolved dynamic references remain visible. Deduplicated review groups retain all original occurrences. Anonymous HTTP review does not validate authenticated administration or active pentesting.

Never point it at secrets, regulated data or customer material without the required authority. Paths and digests in stdout can be sensitive. Retain generated reports only in the approved private evidence destination, after account/access/retention/redaction and read-back are verified.

Report suspected engine vulnerabilities through this repository's GitHub private vulnerability reporting when enabled. If that channel is unavailable, open a minimal issue requesting a private channel without exploit details, credentials or private target data. No external assessment or bug bounty authorization is granted by this repository.

Any future active executor must verify grants at execution time, fence tenant/project/run/epoch, enforce allowlisted targets and egress, reject unsafe DNS/redirect changes, bound runtime/resources, support cancellation and distinguish failure/unknown from validated findings. Prompt instructions cannot grant authority. Patch publication requires an independent trusted controller and reviewed source/evidence binding.
