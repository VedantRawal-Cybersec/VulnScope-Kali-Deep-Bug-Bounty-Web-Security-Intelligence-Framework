PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS entities (
 id TEXT PRIMARY KEY, kind TEXT NOT NULL, name TEXT,
 data_json TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS relationships (
 id TEXT PRIMARY KEY, src_id TEXT NOT NULL, relation TEXT NOT NULL, dst_id TEXT NOT NULL,
 data_json TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS observations (
 id TEXT PRIMARY KEY, job_id TEXT NOT NULL, agent_id TEXT NOT NULL,
 class TEXT NOT NULL CHECK(class IN ('FACT','INFERENCE','UNKNOWN')),
 summary TEXT NOT NULL, evidence_ids_json TEXT NOT NULL DEFAULT '[]',
 session_ref TEXT, scope_decision TEXT, created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS tests (
 id TEXT PRIMARY KEY, specialist TEXT NOT NULL, objective TEXT NOT NULL,
 status TEXT NOT NULL, target_entity_ids_json TEXT NOT NULL DEFAULT '[]',
 session_refs_json TEXT NOT NULL DEFAULT '[]', created_at TEXT NOT NULL, completed_at TEXT
);

CREATE TABLE IF NOT EXISTS evidence (
 id TEXT PRIMARY KEY, kind TEXT NOT NULL, sha256 TEXT NOT NULL,
 storage_ref TEXT NOT NULL, metadata_json TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS coverage (
 dimension TEXT NOT NULL, key TEXT NOT NULL,
 state TEXT NOT NULL CHECK(state IN ('UNMAPPED','MAPPED','UNTESTED','TESTING','TESTED','NOT_APPLICABLE')),
 data_json TEXT NOT NULL DEFAULT '{}', updated_at TEXT NOT NULL,
 PRIMARY KEY(dimension,key)
);

CREATE TABLE IF NOT EXISTS negative_knowledge (
 id TEXT PRIMARY KEY, target_key TEXT NOT NULL, test_signature TEXT NOT NULL,
 result_summary TEXT NOT NULL, evidence_ids_json TEXT NOT NULL DEFAULT '[]', created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS candidates (
 id TEXT PRIMARY KEY, source_observation_id TEXT NOT NULL, status TEXT NOT NULL,
 validation_json TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS findings (
 id TEXT PRIMARY KEY, candidate_id TEXT NOT NULL UNIQUE, title TEXT NOT NULL,
 impact TEXT NOT NULL, evidence_ids_json TEXT NOT NULL,
 promotion_record_json TEXT NOT NULL, created_at TEXT NOT NULL
);