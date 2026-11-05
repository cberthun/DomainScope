-- Certificate-Transparency-Einträge (Alarm bei neuen, unbekannten Zertifikaten)
CREATE TABLE ct_certificates (
    id INT UNSIGNED NOT NULL AUTO_INCREMENT,
    domain_id INT UNSIGNED NOT NULL,
    serial VARCHAR(100) NOT NULL,
    ct_id VARCHAR(40) NULL,
    issuer VARCHAR(200) NOT NULL,
    names JSON NULL,
    not_before DATETIME NULL,
    not_after DATETIME NULL,
    first_seen DATETIME NOT NULL,
    last_seen DATETIME NOT NULL,
    baseline TINYINT(1) NOT NULL DEFAULT 0 COMMENT '1 = beim ersten Scan vorhanden (Ausgangsbestand)',
    known_issuer TINYINT(1) NOT NULL DEFAULT 1,
    PRIMARY KEY (id),
    UNIQUE KEY uq_ct_serial (domain_id, serial, issuer),
    KEY idx_ct_domain (domain_id, first_seen),
    CONSTRAINT fk_ct_domain FOREIGN KEY (domain_id) REFERENCES domains (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Zugangsdaten (überschreiben den Hash aus der .env), TOTP-Secret verschlüsselt
CREATE TABLE auth_credentials (
    id TINYINT UNSIGNED NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    totp_secret TEXT NULL,
    totp_enabled TINYINT(1) NOT NULL DEFAULT 0,
    totp_last_counter BIGINT UNSIGNED NOT NULL DEFAULT 0,
    recovery_codes JSON NULL,
    updated_at DATETIME NOT NULL,
    PRIMARY KEY (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
