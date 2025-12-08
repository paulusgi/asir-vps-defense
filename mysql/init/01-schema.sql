CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    role ENUM('admin', 'viewer') DEFAULT 'viewer',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS audit_log (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    action VARCHAR(255) NOT NULL,
    ip_address VARCHAR(45),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- View for simplified audit analysis
CREATE OR REPLACE VIEW view_audit_summary AS
SELECT 
    a.id,
    u.username,
    a.action,
    a.ip_address,
    a.created_at
FROM audit_log a
LEFT JOIN users u ON a.user_id = u.id
ORDER BY a.created_at DESC;

CREATE TABLE IF NOT EXISTS ip_geo_cache (
    ip VARCHAR(45) PRIMARY KEY,
    country_code CHAR(2) DEFAULT '??',
    country_name VARCHAR(100) DEFAULT 'Desconocido',
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

