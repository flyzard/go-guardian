package database

import (
	"fmt"
	"log"
)

type Migration struct {
	Version    string
	Name       string
	UpSQLite   string
	DownSQLite string
	UpMySQL    string
	DownMySQL  string
}

var migrations = []Migration{
	{
		Version: "001",
		Name:    "create_users_table",
		UpSQLite: `
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                verified BOOLEAN DEFAULT FALSE,
                created_at DATETIME NOT NULL,
                updated_at DATETIME
            );
            CREATE INDEX idx_users_email ON users(email);
        `,
		DownSQLite: `DROP TABLE IF EXISTS users;`,
		UpMySQL: `
            CREATE TABLE IF NOT EXISTS users (
                id BIGINT PRIMARY KEY AUTO_INCREMENT,
                email VARCHAR(255) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                verified TINYINT(1) DEFAULT 0,
                created_at DATETIME NOT NULL,
                updated_at DATETIME NULL,
                INDEX idx_users_email (email)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
        `,
		DownMySQL: `DROP TABLE IF EXISTS users;`,
	},
	{
		Version: "002",
		Name:    "create_tokens_table",
		UpSQLite: `
            CREATE TABLE IF NOT EXISTS tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                token TEXT UNIQUE NOT NULL,
                user_id INTEGER NOT NULL,
                purpose TEXT NOT NULL,
                expires_at DATETIME NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            CREATE INDEX idx_tokens_token ON tokens(token);
            CREATE INDEX idx_tokens_expires ON tokens(expires_at);
        `,
		DownSQLite: `DROP TABLE IF EXISTS tokens;`,
		UpMySQL: `
            CREATE TABLE IF NOT EXISTS tokens (
                id BIGINT PRIMARY KEY AUTO_INCREMENT,
                token VARCHAR(255) UNIQUE NOT NULL,
                user_id BIGINT NOT NULL,
                purpose VARCHAR(50) NOT NULL,
                expires_at DATETIME NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_tokens_token (token),
                INDEX idx_tokens_expires (expires_at),
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
        `,
		DownMySQL: `DROP TABLE IF EXISTS tokens;`,
	},
	{
		Version: "003",
		Name:    "create_sessions_table",
		UpSQLite: `
            CREATE TABLE IF NOT EXISTS sessions (
                id TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                data TEXT,
                expires_at DATETIME NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            CREATE INDEX idx_sessions_expires ON sessions(expires_at);
        `,
		DownSQLite: `DROP TABLE IF EXISTS sessions;`,
		UpMySQL: `
            CREATE TABLE IF NOT EXISTS sessions (
                id VARCHAR(255) PRIMARY KEY,
                user_id BIGINT NOT NULL,
                data TEXT,
                expires_at DATETIME NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_sessions_expires (expires_at),
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
        `,
		DownMySQL: `DROP TABLE IF EXISTS sessions;`,
	},
	{
		Version: "004",
		Name:    "create_roles_and_permissions",
		UpSQLite: `
		CREATE TABLE IF NOT EXISTS roles (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT UNIQUE NOT NULL
		);
		
		CREATE TABLE IF NOT EXISTS permissions (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT UNIQUE NOT NULL
		);
		
		CREATE TABLE IF NOT EXISTS role_permissions (
			role_id INTEGER NOT NULL,
			permission_id INTEGER NOT NULL,
			PRIMARY KEY (role_id, permission_id),
			FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE,
			FOREIGN KEY (permission_id) REFERENCES permissions(id) ON DELETE CASCADE
		);
		
		CREATE TABLE IF NOT EXISTS remember_tokens (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER NOT NULL,
			token TEXT UNIQUE NOT NULL,
			expires_at DATETIME NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
		);
		
		ALTER TABLE users ADD COLUMN role_id INTEGER DEFAULT 1;
		
		-- Create default roles
		INSERT INTO roles (name) VALUES ('user'), ('admin');
		INSERT INTO permissions (name) VALUES ('user.view'), ('user.edit'), ('admin.access');
		INSERT INTO role_permissions VALUES (1, 1), (2, 1), (2, 2), (2, 3);
	`,
		DownSQLite: `
		DROP TABLE IF EXISTS role_permissions;
		DROP TABLE IF EXISTS permissions;
		DROP TABLE IF EXISTS roles;
		DROP TABLE IF EXISTS remember_tokens;
	`,
		UpMySQL: `
		CREATE TABLE IF NOT EXISTS roles (
			id BIGINT PRIMARY KEY AUTO_INCREMENT,
			name VARCHAR(100) UNIQUE NOT NULL
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
		
		CREATE TABLE IF NOT EXISTS permissions (
			id BIGINT PRIMARY KEY AUTO_INCREMENT,
			name VARCHAR(100) UNIQUE NOT NULL
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
		
		CREATE TABLE IF NOT EXISTS role_permissions (
			role_id BIGINT NOT NULL,
			permission_id BIGINT NOT NULL,
			PRIMARY KEY (role_id, permission_id),
			FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE,
			FOREIGN KEY (permission_id) REFERENCES permissions(id) ON DELETE CASCADE
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
		
		CREATE TABLE IF NOT EXISTS remember_tokens (
			id BIGINT PRIMARY KEY AUTO_INCREMENT,
			user_id BIGINT NOT NULL,
			token VARCHAR(255) UNIQUE NOT NULL,
			expires_at DATETIME NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			INDEX idx_remember_token (token),
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
		
		ALTER TABLE users ADD COLUMN role_id BIGINT DEFAULT 1;
		
		-- Create default roles
		INSERT INTO roles (name) VALUES ('user'), ('admin');
		INSERT INTO permissions (name) VALUES ('user.view'), ('user.edit'), ('admin.access');
		INSERT INTO role_permissions VALUES (1, 1), (2, 1), (2, 2), (2, 3);
	`,
		DownMySQL: `
		DROP TABLE IF EXISTS role_permissions;
		DROP TABLE IF EXISTS permissions;
		DROP TABLE IF EXISTS roles;
		DROP TABLE IF EXISTS remember_tokens;
	`,
	},
}

func (db *DB) Migrate() error {
	// Create migrations table based on database type
	migrationTableSQL := getMigrationTableSQL(db.dbType)
	if _, err := db.DB.Exec(migrationTableSQL); err != nil {
		return err
	}

	// Run migrations
	for _, m := range migrations {
		if err := db.runMigration(m); err != nil {
			return fmt.Errorf("migration %s failed: %w", m.Version, err)
		}
	}

	return nil
}

func getMigrationTableSQL(dbType string) string {
	if dbType == "mysql" {
		return `
            CREATE TABLE IF NOT EXISTS migrations (
                version VARCHAR(10) PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                applied_at DATETIME DEFAULT CURRENT_TIMESTAMP
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
        `
	}
	// SQLite
	return `
        CREATE TABLE IF NOT EXISTS migrations (
            version TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            applied_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
    `
}

func (db *DB) runMigration(m Migration) error {
	// Check if already applied
	var count int
	err := db.DB.QueryRow("SELECT COUNT(*) FROM migrations WHERE version = ?", m.Version).Scan(&count)
	if err != nil {
		return err
	}

	if count > 0 {
		return nil // Already applied
	}

	// Get appropriate SQL based on database type
	var upSQL string
	switch db.dbType {
	case "mysql":
		upSQL = m.UpMySQL
	case "sqlite":
		upSQL = m.UpSQLite
	default:
		return fmt.Errorf("unsupported database type: %s", db.dbType)
	}

	// Run migration in transaction
	tx, err := db.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if _, err := tx.Exec(upSQL); err != nil {
		return err
	}

	if _, err := tx.Exec(
		"INSERT INTO migrations (version, name) VALUES (?, ?)",
		m.Version, m.Name,
	); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return err
	}

	log.Printf("Applied migration %s: %s", m.Version, m.Name)
	return nil
}
