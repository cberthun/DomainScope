-- DomainScope Schema v1 (MySQL 8 / MariaDB 10.5+), utf8mb4

CREATE TABLE domains (
    id INT UNSIGNED NOT NULL AUTO_INCREMENT,
    name VARCHAR(253) NOT NULL COMMENT 'registrierbare Domain, ASCII/Punycode, kleingeschrieben',
    unicode_name VARCHAR(253) NOT NULL,
    public_suffix VARCHAR(120) NOT NULL,
    tld VARCHAR(63) NOT NULL,
    monitored TINYINT(1) NOT NULL DEFAULT 0,
    notes TEXT NULL,
    dkim_selectors VARCHAR(500) NOT NULL DEFAULT '',
    created_at DATETIME NOT NULL,
    last_checked_at DATETIME NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_domains_name (name),
    KEY idx_domains_monitored (monitored)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE dns_snapshots (
    id INT UNSIGNED NOT NULL AUTO_INCREMENT,
    domain_id INT UNSIGNED NOT NULL,
    host VARCHAR(253) NOT NULL,
    resolver VARCHAR(40) NOT NULL,
    content_hash CHAR(64) NOT NULL,
    record_count INT UNSIGNED NOT NULL DEFAULT 0,
    errors JSON NULL,
    taken_at DATETIME NOT NULL,
    PRIMARY KEY (id),
    KEY idx_dns_snap_lookup (domain_id, host, resolver, taken_at),
    CONSTRAINT fk_dns_snap_domain FOREIGN KEY (domain_id) REFERENCES domains (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE dns_records (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    snapshot_id INT UNSIGNED NOT NULL,
    name VARCHAR(253) NOT NULL,
    type VARCHAR(12) NOT NULL,
    ttl INT UNSIGNED NULL,
    data TEXT NOT NULL,
    PRIMARY KEY (id),
    KEY idx_dns_rec_snapshot (snapshot_id, type),
    CONSTRAINT fk_dns_rec_snapshot FOREIGN KEY (snapshot_id) REFERENCES dns_snapshots (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE registration_snapshots (
    id INT UNSIGNED NOT NULL AUTO_INCREMENT,
    domain_id INT UNSIGNED NOT NULL,
    source VARCHAR(10) NOT NULL COMMENT 'rdap | whois',
    source_url VARCHAR(500) NULL,
    registrar VARCHAR(255) NULL,
    registered_at DATETIME NULL,
    changed_at DATETIME NULL,
    expires_at DATETIME NULL,
    statuses JSON NULL,
    nameservers JSON NULL,
    dnssec_signed TINYINT(1) NULL,
    content_hash CHAR(64) NOT NULL,
    data JSON NULL,
    fetched_at DATETIME NOT NULL,
    PRIMARY KEY (id),
    KEY idx_reg_domain (domain_id, fetched_at),
    CONSTRAINT fk_reg_domain FOREIGN KEY (domain_id) REFERENCES domains (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE subdomain_scans (
    id INT UNSIGNED NOT NULL AUTO_INCREMENT,
    domain_id INT UNSIGNED NOT NULL,
    sources JSON NULL,
    found_count INT UNSIGNED NOT NULL DEFAULT 0,
    new_count INT UNSIGNED NOT NULL DEFAULT 0,
    missing_count INT UNSIGNED NOT NULL DEFAULT 0,
    errors JSON NULL,
    scanned_at DATETIME NOT NULL,
    PRIMARY KEY (id),
    KEY idx_sub_scan_domain (domain_id, scanned_at),
    CONSTRAINT fk_sub_scan_domain FOREIGN KEY (domain_id) REFERENCES domains (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE subdomains (
    id INT UNSIGNED NOT NULL AUTO_INCREMENT,
    domain_id INT UNSIGNED NOT NULL,
    hostname VARCHAR(253) NOT NULL,
    is_wildcard TINYINT(1) NOT NULL DEFAULT 0,
    sources JSON NULL,
    first_seen_scan_id INT UNSIGNED NULL,
    last_seen_scan_id INT UNSIGNED NULL,
    first_seen DATETIME NOT NULL,
    last_seen DATETIME NOT NULL,
    status VARCHAR(10) NOT NULL DEFAULT 'present' COMMENT 'present | missing',
    resolved_ips JSON NULL,
    resolved_cname VARCHAR(253) NULL,
    resolved_status VARCHAR(20) NULL,
    resolved_at DATETIME NULL,
    cert_not_after DATETIME NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_subdomain (domain_id, hostname),
    KEY idx_sub_status (domain_id, status),
    CONSTRAINT fk_sub_domain FOREIGN KEY (domain_id) REFERENCES domains (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE ip_addresses (
    id INT UNSIGNED NOT NULL AUTO_INCREMENT,
    address VARCHAR(45) NOT NULL,
    version TINYINT UNSIGNED NOT NULL,
    classification VARCHAR(40) NOT NULL DEFAULT 'public',
    reverse_dns VARCHAR(253) NULL,
    asn INT UNSIGNED NULL,
    as_name VARCHAR(255) NULL,
    prefix VARCHAR(50) NULL,
    country VARCHAR(8) NULL,
    registry VARCHAR(20) NULL,
    rdap_name VARCHAR(255) NULL,
    rdap_data JSON NULL,
    data_sources JSON NULL,
    checked_at DATETIME NULL,
    first_seen DATETIME NOT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_ip_address (address),
    KEY idx_ip_asn (asn)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE domain_ips (
    id INT UNSIGNED NOT NULL AUTO_INCREMENT,
    domain_id INT UNSIGNED NOT NULL,
    ip_id INT UNSIGNED NOT NULL,
    hostname VARCHAR(253) NOT NULL,
    record_type VARCHAR(8) NOT NULL,
    source VARCHAR(30) NOT NULL DEFAULT 'dns',
    first_seen DATETIME NOT NULL,
    last_seen DATETIME NOT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_domain_ip (domain_id, ip_id, hostname),
    KEY idx_domain_ips_ip (ip_id),
    CONSTRAINT fk_dip_domain FOREIGN KEY (domain_id) REFERENCES domains (id) ON DELETE CASCADE,
    CONSTRAINT fk_dip_ip FOREIGN KEY (ip_id) REFERENCES ip_addresses (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE certificates (
    id INT UNSIGNED NOT NULL AUTO_INCREMENT,
    fingerprint_sha256 CHAR(64) NOT NULL,
    subject VARCHAR(500) NOT NULL,
    issuer VARCHAR(500) NOT NULL,
    serial VARCHAR(100) NULL,
    sans JSON NULL,
    not_before DATETIME NULL,
    not_after DATETIME NULL,
    signature_algorithm VARCHAR(60) NULL,
    key_type VARCHAR(20) NULL,
    key_bits INT UNSIGNED NULL,
    first_seen DATETIME NOT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_cert_fp (fingerprint_sha256),
    KEY idx_cert_expiry (not_after)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE tls_checks (
    id INT UNSIGNED NOT NULL AUTO_INCREMENT,
    domain_id INT UNSIGNED NOT NULL,
    host VARCHAR(253) NOT NULL,
    port SMALLINT UNSIGNED NOT NULL DEFAULT 443,
    ip VARCHAR(45) NULL,
    status VARCHAR(20) NOT NULL COMMENT 'ok | invalid | unreachable',
    certificate_id INT UNSIGNED NULL,
    protocol VARCHAR(20) NULL,
    cipher VARCHAR(80) NULL,
    chain_trusted TINYINT(1) NULL,
    hostname_match TINYINT(1) NULL,
    error VARCHAR(500) NULL,
    details JSON NULL,
    checked_at DATETIME NOT NULL,
    PRIMARY KEY (id),
    KEY idx_tls_lookup (domain_id, host, port, checked_at),
    CONSTRAINT fk_tls_domain FOREIGN KEY (domain_id) REFERENCES domains (id) ON DELETE CASCADE,
    CONSTRAINT fk_tls_cert FOREIGN KEY (certificate_id) REFERENCES certificates (id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE module_results (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    domain_id INT UNSIGNED NOT NULL,
    module VARCHAR(30) NOT NULL COMMENT 'email | dnssec | http | delegation | dns_consistency',
    subject VARCHAR(253) NOT NULL DEFAULT '',
    status VARCHAR(20) NOT NULL,
    summary VARCHAR(500) NULL,
    content_hash CHAR(64) NOT NULL,
    data JSON NOT NULL,
    duration_ms INT UNSIGNED NULL,
    checked_at DATETIME NOT NULL,
    PRIMARY KEY (id),
    KEY idx_modres_lookup (domain_id, module, subject, checked_at),
    CONSTRAINT fk_modres_domain FOREIGN KEY (domain_id) REFERENCES domains (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE assets (
    id INT UNSIGNED NOT NULL AUTO_INCREMENT,
    name VARCHAR(200) NOT NULL,
    type VARCHAR(30) NOT NULL,
    address VARCHAR(253) NULL,
    description TEXT NULL,
    provider VARCHAR(150) NULL,
    environment VARCHAR(20) NOT NULL DEFAULT 'production',
    tags VARCHAR(500) NOT NULL DEFAULT '',
    notes TEXT NULL,
    domain_id INT UNSIGNED NULL,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    last_checked_at DATETIME NULL,
    PRIMARY KEY (id),
    KEY idx_assets_type (type),
    KEY idx_assets_address (address),
    CONSTRAINT fk_assets_domain FOREIGN KEY (domain_id) REFERENCES domains (id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE asset_relationships (
    id INT UNSIGNED NOT NULL AUTO_INCREMENT,
    from_asset_id INT UNSIGNED NOT NULL,
    to_asset_id INT UNSIGNED NOT NULL,
    relation VARCHAR(40) NOT NULL DEFAULT 'depends_on',
    origin VARCHAR(10) NOT NULL DEFAULT 'manual' COMMENT 'manual | observed',
    confirmed TINYINT(1) NOT NULL DEFAULT 1,
    note VARCHAR(255) NULL,
    created_at DATETIME NOT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_asset_rel (from_asset_id, to_asset_id, relation),
    CONSTRAINT fk_rel_from FOREIGN KEY (from_asset_id) REFERENCES assets (id) ON DELETE CASCADE,
    CONSTRAINT fk_rel_to FOREIGN KEY (to_asset_id) REFERENCES assets (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE findings (
    id INT UNSIGNED NOT NULL AUTO_INCREMENT,
    fingerprint CHAR(40) NOT NULL,
    rule_id VARCHAR(60) NOT NULL,
    module VARCHAR(20) NOT NULL,
    domain_id INT UNSIGNED NULL,
    subject VARCHAR(253) NOT NULL DEFAULT '',
    title VARCHAR(255) NOT NULL,
    category VARCHAR(30) NOT NULL,
    severity VARCHAR(10) NOT NULL,
    status VARCHAR(15) NOT NULL DEFAULT 'open' COMMENT 'open | acknowledged | ignored | resolved',
    reasoning TEXT NOT NULL,
    recommendation TEXT NOT NULL,
    evidence JSON NULL,
    source VARCHAR(60) NOT NULL,
    first_seen DATETIME NOT NULL,
    last_seen DATETIME NOT NULL,
    resolved_at DATETIME NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_finding_fp (fingerprint),
    KEY idx_findings_status (status, severity),
    KEY idx_findings_domain (domain_id),
    CONSTRAINT fk_findings_domain FOREIGN KEY (domain_id) REFERENCES domains (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE finding_events (
    id INT UNSIGNED NOT NULL AUTO_INCREMENT,
    finding_id INT UNSIGNED NOT NULL,
    event VARCHAR(30) NOT NULL,
    detail VARCHAR(500) NULL,
    created_at DATETIME NOT NULL,
    PRIMARY KEY (id),
    KEY idx_fe_finding (finding_id, created_at),
    CONSTRAINT fk_fe_finding FOREIGN KEY (finding_id) REFERENCES findings (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE change_events (
    id INT UNSIGNED NOT NULL AUTO_INCREMENT,
    domain_id INT UNSIGNED NOT NULL,
    type VARCHAR(40) NOT NULL,
    summary VARCHAR(500) NOT NULL,
    detail JSON NULL,
    detected_at DATETIME NOT NULL,
    PRIMARY KEY (id),
    KEY idx_change_domain (domain_id, detected_at),
    KEY idx_change_type (type),
    CONSTRAINT fk_change_domain FOREIGN KEY (domain_id) REFERENCES domains (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE scan_jobs (
    id INT UNSIGNED NOT NULL AUTO_INCREMENT,
    domain_id INT UNSIGNED NULL,
    trigger_type VARCHAR(10) NOT NULL DEFAULT 'manual' COMMENT 'manual | cron',
    status VARCHAR(10) NOT NULL DEFAULT 'running' COMMENT 'running | ok | partial | failed',
    started_at DATETIME NOT NULL,
    finished_at DATETIME NULL,
    message VARCHAR(500) NULL,
    PRIMARY KEY (id),
    KEY idx_jobs_started (started_at),
    CONSTRAINT fk_jobs_domain FOREIGN KEY (domain_id) REFERENCES domains (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE scan_results (
    id INT UNSIGNED NOT NULL AUTO_INCREMENT,
    job_id INT UNSIGNED NOT NULL,
    module VARCHAR(30) NOT NULL,
    status VARCHAR(10) NOT NULL,
    message VARCHAR(500) NULL,
    duration_ms INT UNSIGNED NULL,
    PRIMARY KEY (id),
    KEY idx_results_job (job_id),
    CONSTRAINT fk_results_job FOREIGN KEY (job_id) REFERENCES scan_jobs (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE data_source_status (
    name VARCHAR(60) NOT NULL,
    label VARCHAR(120) NOT NULL,
    last_ok_at DATETIME NULL,
    last_error_at DATETIME NULL,
    last_error VARCHAR(500) NULL,
    ok_count INT UNSIGNED NOT NULL DEFAULT 0,
    fail_count INT UNSIGNED NOT NULL DEFAULT 0,
    avg_ms INT UNSIGNED NULL,
    PRIMARY KEY (name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE activity_log (
    id INT UNSIGNED NOT NULL AUTO_INCREMENT,
    type VARCHAR(30) NOT NULL,
    message VARCHAR(500) NOT NULL,
    domain_id INT UNSIGNED NULL,
    created_at DATETIME NOT NULL,
    PRIMARY KEY (id),
    KEY idx_activity_created (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE application_settings (
    `key` VARCHAR(80) NOT NULL,
    value TEXT NOT NULL,
    updated_at DATETIME NOT NULL,
    PRIMARY KEY (`key`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE login_attempts (
    id INT UNSIGNED NOT NULL AUTO_INCREMENT,
    ip VARCHAR(45) NOT NULL,
    attempted_at DATETIME NOT NULL,
    PRIMARY KEY (id),
    KEY idx_login_ip (ip, attempted_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
