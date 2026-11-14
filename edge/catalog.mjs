export const features = [
  {
    "slug": "autonomous-pentesting",
    "name": "Autonomous Pentesting",
    "nameJa": "自律ペンテスト",
    "title": "Test the paths an attacker would take.",
    "titleJa": "攻撃者が辿る経路を検証する。",
    "description": "Scope your apps and APIs, validate suspected weaknesses, and keep the evidence attached to every finding.",
    "descriptionJa": "アプリとAPIの検証範囲を定め、疑わしい弱点を検証し、検出結果に根拠を紐づけます。",
    "areas": [
      "Authenticated apps and APIs",
      "Business logic and tenant boundaries",
      "Reproduction and attack-path evidence"
    ],
    "areasJa": [
      "認証付きアプリとAPI",
      "ビジネスロジックとテナント境界",
      "再現手順と攻撃経路の根拠"
    ],
    "steps": [
      "Authorize targets and test identities",
      "Run within explicit scope and limits",
      "Review findings, evidence and untested paths"
    ],
    "stepsJa": [
      "対象とテスト用IDを承認",
      "許可された範囲と上限で検証",
      "検出結果・根拠・未検証範囲を確認"
    ],
    "availability": "Managed autonomous pentesting is in development. Target authorization and runtime validation must be enabled before a test can run.",
    "availabilityJa": "マネージド自律ペンテストは開発中です。実行には対象の承認と検証環境の準備が必要です。",
    "artifact": "Authorized scope",
    "artifactJa": "承認された検証範囲",
    "rows": [
      "Target · staging.example.com",
      "Identity · organization test accounts",
      "Execution · not started"
    ],
    "rowsJa": [
      "対象 · staging.example.com",
      "ID · 組織のテストアカウント",
      "実行 · 未開始"
    ]
  },
  {
    "slug": "pr-reviews",
    "name": "PR Security Reviews",
    "nameJa": "PRセキュリティレビュー",
    "title": "Find risk while it is still a diff.",
    "titleJa": "差分のうちにリスクを見つける。",
    "description": "Keep security review next to the change, with source-bound findings and an explicit policy for incomplete results.",
    "descriptionJa": "変更に寄り添うセキュリティレビュー。ソースに紐づく検出結果と、検証不十分な場合の扱いを明確にします。",
    "areas": [
      "Selected repositories and immutable revisions",
      "Report-only reviews before enforcement",
      "GitHub Actions, CircleCI and generic CI"
    ],
    "areasJa": [
      "選択したリポジトリと不変のリビジョン",
      "強制適用より先にレポートのみで確認",
      "GitHub Actions・CircleCI・汎用CI"
    ],
    "steps": [
      "Preview the additive setup change",
      "Review the exact base and head revision",
      "Triage findings before enabling a merge policy"
    ],
    "stepsJa": [
      "追加される設定変更をプレビュー",
      "正確なbase・headリビジョンを確認",
      "検出結果を判断してからマージ方針を設定"
    ],
    "availability": "The source-review CLI and adapter candidates exist. Managed GitHub installation and hosted reporting are not yet available.",
    "availabilityJa": "ソースレビューCLIとCIアダプターの候補実装があります。マネージドGitHub接続とホスト型レポート配信は未提供です。",
    "artifact": "Pull request review",
    "artifactJa": "プルリクエストレビュー",
    "rows": [
      "Source · base / head bound",
      "Mode · report-only",
      "Outcome · no review has run"
    ],
    "rowsJa": [
      "ソース · base / headを紐づけ",
      "モード · レポートのみ",
      "結果 · レビュー未実行"
    ]
  },
  {
    "slug": "auto-fix",
    "name": "Auto-Fix",
    "nameJa": "自動修正",
    "title": "Turn evidence into a reviewable fix.",
    "titleJa": "検証の根拠を、レビュー可能な修正へ。",
    "description": "Carry the root cause, proposed patch and retest evidence through one review flow. Your team decides what merges.",
    "descriptionJa": "根本原因・修正案・再検証の根拠を、一つのレビューで確認。マージはチームが判断します。",
    "areas": [
      "Patches grounded in the affected code path",
      "Before-and-after validation context",
      "Human-reviewed pull requests"
    ],
    "areasJa": [
      "問題のコード経路に基づく修正",
      "修正前後の検証コンテキスト",
      "人がレビューするプルリクエスト"
    ],
    "steps": [
      "Review a validated finding",
      "Inspect the proposed patch and change scope",
      "Retest the approved revision before closure"
    ],
    "stepsJa": [
      "検証された検出結果を確認",
      "修正案と変更範囲を確認",
      "承認済みリビジョンを再検証して解決を判断"
    ],
    "availability": "Automated patch generation, fix PR creation and source-bound retesting are in development. No automatic merge or deployment is enabled.",
    "availabilityJa": "自動パッチ生成・修正PR作成・ソースに紐づく再検証は開発中です。自動マージやデプロイは行いません。",
    "artifact": "Fix review",
    "artifactJa": "修正レビュー",
    "rows": [
      "Finding · validation required",
      "Patch · not generated",
      "Retest · not run"
    ],
    "rowsJa": [
      "検出結果 · 検証が必要",
      "パッチ · 未生成",
      "再検証 · 未実行"
    ]
  },
  {
    "slug": "continuous-coverage",
    "name": "Continuous Coverage",
    "nameJa": "継続的な検証",
    "title": "Keep security in step with change.",
    "titleJa": "変化に合わせて検証を続ける。",
    "description": "Connect changes, releases and scheduled checks to a coverage history that distinguishes completed tests from unknown outcomes.",
    "descriptionJa": "変更・リリース・定期検証を一つの履歴へ。完了した検証と、結果不明の実行を区別します。",
    "areas": [
      "Pull request, deploy and scheduled triggers",
      "New exposure, regression and relevant CVE review",
      "Coverage and recovery history"
    ],
    "areasJa": [
      "PR・デプロイ・スケジュールによる起動",
      "新たな公開範囲・再発・関連CVEの確認",
      "検証範囲と復旧の履歴"
    ],
    "steps": [
      "Choose authorized triggers and budgets",
      "Recheck the changed scope without duplicate effects",
      "Track coverage gaps, regressions and missed runs"
    ],
    "stepsJa": [
      "許可された起動条件と予算を設定",
      "重複操作を防いで変更範囲を再検証",
      "未検証範囲・再発・実行漏れを追跡"
    ],
    "availability": "Continuous scheduling and deploy-triggered testing are in development. No 24/7 monitoring is currently activated by this page.",
    "availabilityJa": "継続スケジュールとデプロイ連動検証は開発中です。このページで24時間監視は有効になりません。",
    "artifact": "Coverage timeline",
    "artifactJa": "検証タイムライン",
    "rows": [
      "PR trigger · not connected",
      "Deploy trigger · not connected",
      "Scheduled runs · not enabled"
    ],
    "rowsJa": [
      "PR起動 · 未接続",
      "デプロイ起動 · 未接続",
      "定期実行 · 未有効"
    ]
  },
  {
    "slug": "infrastructure",
    "name": "Infrastructure Testing",
    "nameJa": "インフラ検証",
    "title": "Look beyond the application boundary.",
    "titleJa": "アプリの境界を越えてリスクを確認。",
    "description": "Bring cloud configuration, Kubernetes exposure and identity paths into one scoped, evidence-led assessment.",
    "descriptionJa": "クラウド設定・Kubernetesの公開範囲・権限経路を、明示的な範囲と根拠で評価します。",
    "areas": [
      "Cloud configuration and exposed resources",
      "Kubernetes workloads, ingress and service access",
      "Identity permissions and internal reachability"
    ],
    "areasJa": [
      "クラウド設定と公開リソース",
      "Kubernetesワークロード・Ingress・サービス権限",
      "ID権限と内部経路の到達性"
    ],
    "steps": [
      "Authorize a read-only inventory boundary",
      "Review configuration and reachable paths",
      "Approve any active test separately and retain evidence"
    ],
    "stepsJa": [
      "読み取り専用の棚卸し範囲を承認",
      "設定と到達可能な経路を確認",
      "能動的な検証は個別に承認し、根拠を保持"
    ],
    "availability": "Cloud and internal infrastructure connectors are in development. No cloud account is connected and no network test starts here.",
    "availabilityJa": "クラウド・内部インフラ接続は開発中です。クラウドアカウントは未接続で、この画面からネットワーク検証は開始しません。",
    "artifact": "Infrastructure scope",
    "artifactJa": "インフラ検証の範囲",
    "rows": [
      "Cloud accounts · not connected",
      "Kubernetes · not connected",
      "Active tests · not authorized"
    ],
    "rowsJa": [
      "クラウドアカウント · 未接続",
      "Kubernetes · 未接続",
      "能動的検証 · 未承認"
    ]
  }
];
export const locales = ["en","zh-Hans","hi","es","ar","fr","bn","pt","id","ur","ru","de","ja","ko","pcm","arz","mr","jv","su","he","it","ar-MA","pl","fi","zh-TW","vi","tl","ms","ro","hu","bg","el","cs","nl","th","uk"];
export const names = {"en":"English","zh-Hans":"简体中文","hi":"हिन्दी","es":"Español","ar":"العربية","fr":"Français","bn":"বাংলা","pt":"Português","id":"Bahasa Indonesia","ur":"اردو","ru":"Русский","de":"Deutsch","ja":"日本語","ko":"한국어","pcm":"Naijá","arz":"مصري","mr":"मराठी","jv":"Basa Jawa","su":"Basa Sunda","he":"עברית","it":"Italiano","ar-MA":"الدارجة","pl":"Polski","fi":"Suomi","zh-TW":"繁體中文（台灣）","vi":"Tiếng Việt","tl":"Tagalog","ms":"Bahasa Melayu","ro":"Română","hu":"Magyar","bg":"Български","el":"Ελληνικά","cs":"Čeština","nl":"Nederlands","th":"ไทย","uk":"Українська"};
export const articles=[
  {
    "slug": "kubernetes-security-fundamentals",
    "date": "2026-10-31",
    "tags": [
      "cloud-security",
      "container-security"
    ],
    "titleEn": "Kubernetes security: clusters, workloads and shared responsibility",
    "titleJa": "",
    "summaryEn": "Learn what Kubernetes does, how its cluster components fit together, and where to review common security boundaries.",
    "summaryJa": "",
    "metaTitleEn": "Kubernetes Security Fundamentals",
    "tldrEn": [
      "Kubernetes orchestrates containerized workloads; a cluster has a control plane and worker nodes.",
      "Pods group one or more containers, while a Deployment describes a desired state for a set of Pods.",
      "Protect API access, workloads, secrets and networking in layers; the actual controls depend on the cluster and its provider."
    ],
    "bodyEn": [
      "## What is Kubernetes?\n\n**Kubernetes** is an open-source platform for managing containerized workloads and services using declarative configuration and automation. It can help schedule and maintain workloads across a cluster, but it does not make an application secure by itself. An image packages an application and its dependencies; a container is a running instance. A Pod groups one or more containers that share certain resources. Kubernetes and a container runtime have different roles. See the [Kubernetes concepts overview](https://kubernetes.io/docs/concepts/) and its [Pods documentation](https://kubernetes.io/docs/concepts/workloads/pods/).",
      "## Control plane and worker nodes\n\nA cluster includes a control plane, which manages cluster state and exposes the Kubernetes API, and worker nodes, which run workloads. A Deployment declares a desired state for a set of Pods, such as how many replicas to maintain. An operator or automation sends changes through the API; the cluster works toward the declared state. A managed provider may operate some components, but the exact division of duties depends on the service and contract. Review the [cluster architecture](https://kubernetes.io/docs/concepts/architecture/) and [Deployments](https://kubernetes.io/docs/concepts/workloads/controllers/deployment/) for the version you operate.",
      "## Where security controls apply\n\nStart by identifying who and what can reach the API and what each identity may do. Review authentication and role-based access control, protect credentials and restrict unnecessary privileges. Kubernetes Secrets are an API for confidential configuration; check the cluster's encryption-at-rest configuration and access policies rather than assuming every Secret is encrypted in the backing store by default. Apply appropriate Pod security standards, keep images and nodes maintained, and restrict traffic using network policies where the cluster's network implementation supports enforcement. Admission controls and audit logs can add preventative and detective checks. These controls address different boundaries and must be configured and verified for the environment. The [Kubernetes security overview](https://kubernetes.io/docs/concepts/security/) and [Secrets guidance](https://kubernetes.io/docs/concepts/configuration/secret/) describe these mechanisms and limits.",
      "## A bounded review example\n\nFor a team deploying a web service, list the workloads and their service accounts, inspect API and namespace permissions, and check whether externally reachable services match the intended design. Review image provenance, allowed container privileges and policy enforcement with the cluster owner. Record which environment and configuration were actually checked; a single manifest, policy or scan result is not proof that every running workload is protected. See also [cloud workloads and container security](/cloud-workloads-container-security-misconfiguration?lang=en) and [IAM, access control and secrets management](/iam-access-control-secrets-management?lang=en)."
    ],
    "bodyJa": [],
    "i18n": {},
    "englishOnly": true
  },
  {
    "slug": "cloud-workloads-container-security-misconfiguration",
    "date": "2026-10-30",
    "tags": [
      "cloud-security",
      "container-security",
      "misconfiguration"
    ],
    "titleEn": "Cloud workloads, containers and misconfiguration explained",
    "titleJa": "",
    "summaryEn": "Understand cloud workloads, application containers and configuration drift, and learn where security responsibilities and isolation boundaries matter.",
    "summaryJa": "",
    "metaTitleEn": "Cloud Workloads, Container Security and Misconfiguration",
    "tldrEn": [
      "A cloud workload is an application or computing task and the resources it uses in a cloud environment.",
      "A container image is a package used to create a running container; containers often share a host kernel and are not the same isolation boundary as virtual machines.",
      "A misconfiguration is an unsafe or unintended setting; its impact depends on exposure and context, while configuration drift is change away from an intended baseline."
    ],
    "bodyEn": [
      "Cloud services make it possible to provision applications and infrastructure quickly. Security still depends on knowing what is deployed, who can change it and which protections are configured for the workload. The following concepts describe different parts of that work.",
      "## What is a cloud workload?",
      "A cloud workload is an application, service or computing task running in a cloud environment, together with the resources and dependencies needed to run it. Examples include a web application on virtual machines, an event-driven function or a service in containers. Cloud security covers the people, processes and technical controls used to protect cloud data, identities, infrastructure and workloads. The controls needed vary with the service and the data involved.",
      "Cloud providers and customers have different responsibilities. The provider may operate underlying infrastructure, while the customer may control identities, data, application settings and network exposure; the actual division depends on the service and its contract. Verify the provider documentation rather than assuming a single universal split. The [CISA Cloud Security Technical Reference Architecture](https://www.cisa.gov/sites/default/files/publications/CISA%20Cloud%20Security%20Technical%20Reference%20Architecture_Version%201.pdf) discusses cloud architecture and configuration management.",
      "## Images, containers and container security",
      "A container image is a package containing application files and dependencies. A container is a running instance created from an image under a container runtime. Container security addresses risks across image creation and distribution, runtime configuration, the host and the application itself. [NIST SP 800-190](https://www.nist.gov/publications/application-container-security-guide) describes container technologies, security concerns and practical safeguards.",
      "Many containers on a host share its operating-system kernel. Isolation mechanisms restrict what each container can see and do, but a container is not automatically equivalent to a separate virtual machine or a complete security boundary. The actual isolation depends on the runtime, host configuration and workload. Avoid unnecessary privileges, restrict accessible resources, maintain trusted images and host software, and investigate vulnerabilities in context rather than assuming an image scan alone establishes safety.",
      "## What are misconfiguration and configuration drift?",
      "A security misconfiguration is a setting or combination of settings that creates an unintended exposure or weakens a required control. For example, a storage location intended for a small team might be made accessible to everyone by an overly broad access policy. The risk depends on the exposed data, reachability and other controls; a finding does not by itself prove compromise or exploitation.",
      "Configuration drift is a difference between an observed configuration and an intended baseline that arises over time. A deliberate, approved change can also create a difference until the baseline is updated. Monitor meaningful changes, compare them with an approved desired state, investigate exceptions and test corrections. A policy check is evidence about a setting at a point in time; it is not proof that all identities, application code and data flows are safe.",
      "## CSPM and CNAPP: posture and application protection",
      "Cloud security posture management (CSPM) is the continuing work of assessing cloud environments, identifying security risks and supporting their remediation. CSPM capabilities can monitor resources against policies and alert on vulnerabilities or configurations that may create exposure. A finding is a starting point for investigation, not proof of compromise. The [CISA cloud security reference architecture](https://www.cisa.gov/sites/default/files/2023-05/Cloud%20Security%20Technical%20Reference%20Architecture%20v2.pdf) describes CSPM as a continuous process, rather than a one-time scan.",
      "A cloud-native application protection platform (CNAPP) brings together capabilities intended to improve visibility and protection for cloud applications. A CNAPP can include CSPM along with workload or development security capabilities, but products differ in scope and coverage. CSPM and CNAPP are related terms, not synonyms: posture management focuses on assessing and improving the environment, while CNAPP describes a broader platform approach. See the glossary in the [CISA Trusted Internet Connections cloud use case](https://www.cisa.gov/sites/default/files/2023-05/tic_3.0_cloud_use_case_508c.pdf).",
      "For example, a posture check might flag a storage policy that permits public access. An authorized owner should assess the data, reachability and intended policy before changing access; some public resources are intentional. An alert does not prove sensitive data was exposed, and automated remediation needs explicit authorization and safeguards. Neither category guarantees complete detection or replaces ownership, identity controls and recovery testing. Sources for this section reviewed on 2026-11-01.",
      "## A practical starting point",
      "Inventory workloads, owners, accounts and sensitive data; identify exposed entry points and dependencies. Review identity permissions, storage access, network paths and image provenance against the provider's documented controls. Patch supported components, record exceptions and test recovery. Prioritize changes by actual exposure and impact, keep audit logs, and reassess after deployments or ownership changes. See also [firewalls, IDS, IPS and zero trust](https://blog.mithril.fund/firewalls-ids-ips-zero-trust?lang=en) and [software supply chains and SBOMs](https://blog.mithril.fund/software-supply-chain-sbom-dependencies-code-signing?lang=en). Sources reviewed on 2026-10-30."
    ],
    "bodyJa": [],
    "i18n": {},
    "englishOnly": true
  },
  {
    "slug": "cve-cvss-cwe-explained",
    "date": "2026-10-29",
    "tags": [
      "cve",
      "cvss",
      "cwe",
      "vulnerability-management"
    ],
    "titleEn": "CVE, CVSS and CWE: what the security identifiers mean",
    "titleJa": "",
    "summaryEn": "Understand vulnerability identifiers, severity scoring and weakness categories, and how to use them together without confusing severity with risk.",
    "summaryJa": "",
    "metaTitleEn": "CVE vs CVSS vs CWE: Vulnerabilities, Severity and Weaknesses",
    "tldrEn": [
      "CVE identifies a publicly known vulnerability; the identifier itself is not a severity score.",
      "CVSS provides a standardized way to describe vulnerability severity. A base score alone is not an assessment of risk in a particular environment.",
      "CWE categorizes common weaknesses that can contribute to vulnerabilities; it does not identify one specific affected product or incident."
    ],
    "bodyEn": [
      "Security advisories often contain a CVE identifier, a CVSS score and a CWE identifier. These labels answer different questions: which publicly known vulnerability is being discussed, how its technical severity is described, and what kind of underlying weakness may be involved. They complement each other and are not interchangeable.",
      "## CVE: identify a vulnerability",
      "Common Vulnerabilities and Exposures (CVE) provides common identifiers for publicly known cybersecurity vulnerabilities. A CVE identifier helps people connect advisories and other records about the same vulnerability. The identifier is not a patch, a proof of exploitation or a severity score. Its record and references can change as more information becomes available. See the [NIST CVE glossary entry](https://csrc.nist.gov/glossary/term/common_vulnerabilities_and_exposures).",
      "A vulnerability is a weakness that can be exploited to compromise a system's security. A record may name affected products or versions, but the identifier alone does not establish whether a particular installation is vulnerable. Check the current vendor advisory, actual deployed version and configuration before deciding what applies.",
      "## CVSS: describe severity, not complete risk",
      "The Common Vulnerability Scoring System (CVSS) describes technical characteristics of a vulnerability and produces a numerical severity score. A vector records the selected metric values and the version used. CVSS scores do not prove active exploitation, and a high base score alone does not measure risk to a particular organization.",
      "CVSS v4.0 includes Base, Threat, Environmental and Supplemental metric groups. The Base metrics describe intrinsic characteristics; Threat and Environmental metrics can add information about exploit maturity and the particular environment. Supplemental metrics provide context without changing the resulting score. Use the reported version, vector and metric groups when comparing assessments; v3.1 and v4.0 are not interchangeable scales. [FIRST's CVSS v4.0 specification](https://www.first.org/cvss/v4.0/specification-document) explains these distinctions.",
      "## CWE: classify a weakness",
      "Common Weakness Enumeration (CWE) is a community-developed list of software and hardware weaknesses. A weakness is a condition that can contribute to vulnerabilities under certain circumstances. A CWE category describes the type of weakness; it is not itself a CVE record for a specific product. Vulnerability records may include a CWE mapping, but a missing or broad mapping does not prove that no weakness exists. See [MITRE's explanation of CWE](https://cwe.mitre.org/about/index.html).",
      "## A practical triage example",
      "In an illustrative case, a vendor advisory identifies a vulnerability with a CVE ID, supplies affected versions and a fix, and includes a CVSS assessment. A linked weakness category may explain a relevant failure pattern. A response team checks whether the affected component is deployed, whether it is reachable, whether a fix or mitigation applies, and whether trusted sources report exploitation. The team records uncertainties rather than treating a numerical score as proof of its own exposure.",
      "Vulnerability management is the ongoing process of identifying, assessing, prioritizing and addressing vulnerabilities and tracking the result. Use the vendor advisory and relevant threat information alongside asset inventory, exposure and operational impact. For related response planning, see [Mithril's incident response guide](https://blog.mithril.fund/cyber-incident-response-by-country?lang=en). Sources reviewed on 2026-10-29. This guide does not establish the status or risk of any particular system."
    ],
    "bodyJa": [],
    "i18n": {},
    "englishOnly": true
  }
];
