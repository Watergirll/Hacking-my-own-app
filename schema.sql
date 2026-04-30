PRAGMA foreign_keys = ON;

-- Drop in dependency order for clean re-init during development.
DROP TABLE IF EXISTS ticket_tags;
DROP TABLE IF EXISTS audit_logs;
DROP TABLE IF EXISTS tickets;
DROP TABLE IF EXISTS users;

CREATE TABLE users (
    id TEXT PRIMARY KEY,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('ANALYST', 'MANAGER')),
    failed_logins INTEGER NOT NULL DEFAULT 0,
    is_locked INTEGER NOT NULL DEFAULT 0 CHECK (is_locked IN (0, 1)),
    last_login_at TEXT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE tickets (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL CHECK (length(title) <= 200),
    description TEXT NOT NULL,
    severity TEXT NOT NULL CHECK (severity IN ('LOW', 'MED', 'HIGH')),
    status TEXT NOT NULL CHECK (status IN ('OPEN', 'IN_PROGRESS', 'RESOLVED')),
    owner_id TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE ticket_tags (
    ticket_id TEXT NOT NULL,
    tag TEXT NOT NULL CHECK (length(tag) <= 50),
    PRIMARY KEY (ticket_id, tag),
    FOREIGN KEY (ticket_id) REFERENCES tickets(id) ON DELETE CASCADE
);

CREATE TABLE audit_logs (
    id TEXT PRIMARY KEY,
    user_id TEXT NULL,
    action TEXT NOT NULL CHECK (
        action IN (
            'REGISTER',
            'LOGIN_SUCCESS',
            'LOGIN_FAILED',
            'LOGOUT',
            'TICKET_CREATE',
            'TICKET_VIEW',
            'TICKET_UPDATE',
            'TICKET_DELETE',
            'TICKET_STATUS_CHANGE',
            'SEARCH',
            'UNAUTHORIZED_ACCESS',
            'ERROR'
        )
    ),
    resource_type TEXT NOT NULL CHECK (length(resource_type) <= 30),
    resource_id TEXT NULL,
    message TEXT NULL,
    ip_address TEXT NULL CHECK (length(ip_address) <= 45),
    user_agent TEXT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
);

-- Recommended indexes from project requirements.
CREATE INDEX idx_users_role ON users(role);

CREATE INDEX idx_tickets_owner_id ON tickets(owner_id);
CREATE INDEX idx_tickets_status ON tickets(status);
CREATE INDEX idx_tickets_severity ON tickets(severity);

CREATE INDEX idx_ticket_tags_tag ON ticket_tags(tag);

CREATE INDEX idx_audit_logs_created_at ON audit_logs(created_at);
CREATE INDEX idx_audit_logs_user_id ON audit_logs(user_id);
CREATE INDEX idx_audit_logs_resource ON audit_logs(resource_type, resource_id);
