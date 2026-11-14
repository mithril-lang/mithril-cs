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
