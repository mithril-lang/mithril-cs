PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS cs_targets (
 id TEXT PRIMARY KEY, owner TEXT NOT NULL, project TEXT NOT NULL, url TEXT NOT NULL,
 label TEXT NOT NULL, proof TEXT NOT NULL, verified_at INTEGER, paused INTEGER NOT NULL DEFAULT 0,
 version INTEGER NOT NULL DEFAULT 1, created_at INTEGER NOT NULL, UNIQUE(owner,project,url)
);
CREATE TABLE IF NOT EXISTS cs_runs (
 id TEXT PRIMARY KEY, owner TEXT NOT NULL, project TEXT NOT NULL, target_id TEXT NOT NULL REFERENCES cs_targets(id),
 target_version INTEGER NOT NULL, operation TEXT NOT NULL, status TEXT NOT NULL,
 created_at INTEGER NOT NULL, started_at INTEGER, finished_at INTEGER, expires_at INTEGER NOT NULL,
 report TEXT, evidence_key TEXT, evidence_sha256 TEXT, error TEXT, UNIQUE(owner,project,operation)
);
CREATE UNIQUE INDEX IF NOT EXISTS cs_one_active_target ON cs_runs(owner,target_id) WHERE status IN ('queued','running');
CREATE INDEX IF NOT EXISTS cs_runs_owner ON cs_runs(owner,project,created_at DESC);
CREATE TABLE IF NOT EXISTS cs_findings (
 id TEXT PRIMARY KEY, owner TEXT NOT NULL, project TEXT NOT NULL, run_id TEXT NOT NULL REFERENCES cs_runs(id),
 target_id TEXT NOT NULL, rule_id TEXT NOT NULL, data TEXT NOT NULL, triage TEXT NOT NULL DEFAULT 'needs-review',
 note TEXT, version INTEGER NOT NULL DEFAULT 1, created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS cs_fixes (
 id TEXT PRIMARY KEY, owner TEXT NOT NULL, project TEXT NOT NULL, finding_id TEXT NOT NULL REFERENCES cs_findings(id),
 run_id TEXT NOT NULL, target_id TEXT NOT NULL, target_version INTEGER NOT NULL,
 evidence_sha256 TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'proposed', patch TEXT NOT NULL,
 created_at INTEGER NOT NULL, reviewed_at INTEGER, note TEXT,
 UNIQUE(owner,project,finding_id)
);
CREATE TABLE IF NOT EXISTS cs_audit (
 id TEXT PRIMARY KEY, owner TEXT NOT NULL, project TEXT NOT NULL, action TEXT NOT NULL, object_id TEXT NOT NULL,
 created_at INTEGER NOT NULL
);
