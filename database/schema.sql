-- Phishing Triage Platform - SQLite schema
-- Version: 1.0
-- Enable foreign-key enforcement for every connection.
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS emails (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    original_filename   TEXT NOT NULL,
    file_hash           TEXT,
    sender              TEXT,
    recipient           TEXT,
    subject             TEXT,
    email_date          TEXT,
    body                TEXT,
    uploaded_at         TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    status              TEXT NOT NULL DEFAULT 'pending'
                        CHECK (status IN ('pending', 'processing', 'completed', 'failed'))
);

CREATE TABLE IF NOT EXISTS header_analysis (
    id                      INTEGER PRIMARY KEY AUTOINCREMENT,
    email_id                INTEGER NOT NULL UNIQUE,
    spf_result              TEXT NOT NULL DEFAULT 'unknown'
                            CHECK (spf_result IN ('pass', 'fail', 'softfail', 'neutral', 'none', 'temperror', 'permerror', 'unknown')),
    dkim_result             TEXT NOT NULL DEFAULT 'unknown'
                            CHECK (dkim_result IN ('pass', 'fail', 'none', 'temperror', 'permerror', 'unknown')),
    dmarc_result            TEXT NOT NULL DEFAULT 'unknown'
                            CHECK (dmarc_result IN ('pass', 'fail', 'none', 'temperror', 'permerror', 'unknown')),
    authentication_results  TEXT,
    raw_headers             TEXT,
    spoofing_detected       INTEGER NOT NULL DEFAULT 0 CHECK (spoofing_detected IN (0, 1)),
    details                 TEXT,
    FOREIGN KEY (email_id) REFERENCES emails(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS urls (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    email_id        INTEGER NOT NULL,
    url             TEXT NOT NULL,
    domain          TEXT,
    is_shortened    INTEGER NOT NULL DEFAULT 0 CHECK (is_shortened IN (0, 1)),
    is_suspicious   INTEGER NOT NULL DEFAULT 0 CHECK (is_suspicious IN (0, 1)),
    risk_reason     TEXT,
    reputation      TEXT,
    FOREIGN KEY (email_id) REFERENCES emails(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS attachments (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    email_id        INTEGER NOT NULL,
    filename        TEXT NOT NULL,
    extension       TEXT,
    mime_type       TEXT,
    file_size       INTEGER CHECK (file_size IS NULL OR file_size >= 0),
    storage_path    TEXT NOT NULL,
    md5_hash        TEXT,
    sha256_hash     TEXT,
    is_suspicious   INTEGER NOT NULL DEFAULT 0 CHECK (is_suspicious IN (0, 1)),
    risk_reason     TEXT,
    FOREIGN KEY (email_id) REFERENCES emails(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS detection_findings (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    email_id        INTEGER NOT NULL,
    rule_code       TEXT NOT NULL,
    title           TEXT NOT NULL,
    description     TEXT,
    severity        TEXT NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    evidence        TEXT,
    created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    FOREIGN KEY (email_id) REFERENCES emails(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS analysis_reports (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    email_id        INTEGER NOT NULL UNIQUE,
    risk_score      INTEGER NOT NULL DEFAULT 0 CHECK (risk_score BETWEEN 0 AND 100),
    risk_level      TEXT NOT NULL DEFAULT 'low'
                    CHECK (risk_level IN ('low', 'medium', 'high')),
    summary         TEXT,
    analyzed_at     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    FOREIGN KEY (email_id) REFERENCES emails(id) ON DELETE CASCADE
);

-- One result per URL or attachment and intelligence source.
-- Exactly one target must be supplied.
CREATE TABLE IF NOT EXISTS threat_intel_results (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    url_id              INTEGER,
    attachment_id       INTEGER,
    source              TEXT NOT NULL,
    status              TEXT NOT NULL DEFAULT 'unknown'
                        CHECK (status IN ('clean', 'malicious', 'suspicious', 'unknown', 'error')),
    source_reference    TEXT,
    details             TEXT,
    checked_at          TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    CHECK (
        (url_id IS NOT NULL AND attachment_id IS NULL) OR
        (url_id IS NULL AND attachment_id IS NOT NULL)
    ),
    FOREIGN KEY (url_id) REFERENCES urls(id) ON DELETE CASCADE,
    FOREIGN KEY (attachment_id) REFERENCES attachments(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_emails_uploaded_at ON emails(uploaded_at);
CREATE INDEX IF NOT EXISTS idx_emails_status ON emails(status);
CREATE INDEX IF NOT EXISTS idx_urls_email_id ON urls(email_id);
CREATE INDEX IF NOT EXISTS idx_urls_domain ON urls(domain);
CREATE INDEX IF NOT EXISTS idx_attachments_email_id ON attachments(email_id);
CREATE INDEX IF NOT EXISTS idx_attachments_sha256 ON attachments(sha256_hash);
CREATE INDEX IF NOT EXISTS idx_findings_email_id ON detection_findings(email_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON detection_findings(severity);
CREATE INDEX IF NOT EXISTS idx_threat_intel_url_id ON threat_intel_results(url_id);
CREATE INDEX IF NOT EXISTS idx_threat_intel_attachment_id ON threat_intel_results(attachment_id);
CREATE INDEX IF NOT EXISTS idx_threat_intel_source ON threat_intel_results(source);
