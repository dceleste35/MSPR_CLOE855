DROP TABLE IF EXISTS clients;
CREATE TABLE clients (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    nom TEXT NOT NULL,
    prenom TEXT NOT NULL,
    adresse TEXT NOT NULL
);

DROP TABLE IF EXISTS connection_logs;
CREATE TABLE IF NOT EXISTS connection_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    username TEXT NOT NULL,
    ip_address TEXT,
    success BOOLEAN,
    user_agent TEXT
);

DROP TABLE IF EXISTS security_threats;
CREATE TABLE IF NOT EXISTS security_threats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    threat_type TEXT NOT NULL,
    ip_address TEXT,
    details TEXT,
    severity TEXT,
    status TEXT DEFAULT 'NEW'
);
