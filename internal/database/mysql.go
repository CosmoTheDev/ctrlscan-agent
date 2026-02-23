package database

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"

	"github.com/CosmoTheDev/ctrlscan-agent/internal/config"
	_ "github.com/go-sql-driver/mysql"
)

// MySQLDB implements DB using MySQL via go-sql-driver/mysql.
type MySQLDB struct {
	db  *sql.DB
	dsn string
}

// NewMySQL opens a MySQL connection using cfg.DSN.
func NewMySQL(cfg config.DatabaseConfig) (*MySQLDB, error) {
	if cfg.DSN == "" {
		return nil, fmt.Errorf("mysql DSN is required when driver is mysql")
	}

	// Append parseTime=true if not already set.
	dsn := cfg.DSN
	if !strings.Contains(dsn, "parseTime") {
		if strings.Contains(dsn, "?") {
			dsn += "&parseTime=true"
		} else {
			dsn += "?parseTime=true"
		}
	}

	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, fmt.Errorf("opening mysql connection: %w", err)
	}

	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)

	m := &MySQLDB{db: db, dsn: dsn}
	if err := m.Ping(context.Background()); err != nil {
		return nil, fmt.Errorf("pinging mysql: %w", err)
	}
	return m, nil
}

func (m *MySQLDB) Driver() string { return "mysql" }

func (m *MySQLDB) Ping(ctx context.Context) error {
	return m.db.PingContext(ctx)
}

func (m *MySQLDB) Close() error {
	return m.db.Close()
}

// Migrate applies pending SQL migrations adapted for MySQL syntax.
// MySQL uses AUTO_INCREMENT instead of AUTOINCREMENT and different ON CONFLICT.
func (m *MySQLDB) Migrate(ctx context.Context) error {
	_, err := m.db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		id         INT          NOT NULL AUTO_INCREMENT PRIMARY KEY,
		filename   VARCHAR(255) NOT NULL UNIQUE,
		applied_at VARCHAR(64)  NOT NULL
	) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`)
	if err != nil {
		return fmt.Errorf("creating schema_migrations: %w", err)
	}

	entries, err := migrationsFS.ReadDir("migrations")
	if err != nil {
		return fmt.Errorf("reading migrations dir: %w", err)
	}

	names := make([]string, 0)
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".sql") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)

	for _, name := range names {
		var count int
		row := m.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM schema_migrations WHERE filename = ?`, name)
		if err := row.Scan(&count); err != nil {
			return fmt.Errorf("checking migration %s: %w", name, err)
		}
		if count > 0 {
			continue
		}

		data, err := migrationsFS.ReadFile("migrations/" + name)
		if err != nil {
			return fmt.Errorf("reading migration %s: %w", name, err)
		}

		// Translate SQLite-specific syntax to MySQL.
		sql := mysqlAdapt(string(data))

		stmts := strings.Split(sql, ";")
		for _, stmt := range stmts {
			stmt = strings.TrimSpace(stmt)
			if stmt == "" {
				continue
			}
			if _, err := m.db.ExecContext(ctx, stmt); err != nil {
				return fmt.Errorf("applying migration %s statement: %w\nSQL: %s", name, err, stmt)
			}
		}

		_, err = m.db.ExecContext(ctx,
			`INSERT INTO schema_migrations (filename, applied_at) VALUES (?, ?)`,
			name, time.Now().UTC().Format(time.RFC3339))
		if err != nil {
			return fmt.Errorf("recording migration %s: %w", name, err)
		}
		slog.Info("Applied migration", "file", name, "driver", "mysql")
	}
	return nil
}

// Select executes query and scans all rows into dest.
func (m *MySQLDB) Select(ctx context.Context, dest interface{}, query string, args ...interface{}) error {
	rows, err := m.db.QueryContext(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("query: %w", err)
	}
	defer rows.Close()
	return scanRows(rows, dest)
}

// Get executes query and scans a single row.
func (m *MySQLDB) Get(ctx context.Context, dest interface{}, query string, args ...interface{}) error {
	row := m.db.QueryRowContext(ctx, query, args...)
	return scanRow(row, dest)
}

// Exec executes a statement returning no rows.
func (m *MySQLDB) Exec(ctx context.Context, query string, args ...interface{}) error {
	_, err := m.db.ExecContext(ctx, query, args...)
	return err
}

// Insert inserts record into table using `db:` tags.
func (m *MySQLDB) Insert(ctx context.Context, table string, record interface{}) (int64, error) {
	cols, placeholders, vals := structToInsert(record)
	// Internal DB helper: table/column names come from trusted application code, values remain parameterized.
	// nosemgrep: go.lang.security.audit.database.string-formatted-query.string-formatted-query
	query := fmt.Sprintf("INSERT INTO %s (%s) VALUES (%s)",
		table, strings.Join(cols, ", "), strings.Join(placeholders, ", "))
	res, err := m.db.ExecContext(ctx, query, vals...)
	if err != nil {
		return 0, fmt.Errorf("insert into %s: %w", table, err)
	}
	return res.LastInsertId()
}

// Update updates rows matching where clause.
func (m *MySQLDB) Update(ctx context.Context, table string, record interface{}, where string, args ...interface{}) error {
	cols, vals := structToUpdate(record)
	sets := make([]string, len(cols))
	for i, c := range cols {
		sets[i] = c + " = ?"
	}
	// Internal DB helper: callers provide trusted SQL fragments for table/where; data values are bound separately.
	// nosemgrep: go.lang.security.audit.database.string-formatted-query.string-formatted-query
	query := fmt.Sprintf("UPDATE %s SET %s WHERE %s", table, strings.Join(sets, ", "), where)
	_, err := m.db.ExecContext(ctx, query, append(vals, args...)...)
	return err
}

// Upsert uses INSERT ... ON DUPLICATE KEY UPDATE for MySQL.
func (m *MySQLDB) Upsert(ctx context.Context, table string, record interface{}, conflictCols []string) error {
	cols, placeholders, vals := structToInsert(record)

	updatePairs := make([]string, 0, len(cols))
	for _, c := range cols {
		skip := false
		for _, cc := range conflictCols {
			if c == cc {
				skip = true
				break
			}
		}
		if !skip {
			updatePairs = append(updatePairs, fmt.Sprintf("%s = VALUES(%s)", c, c))
		}
	}

	// Internal DB helper: SQL identifiers are constructed from trusted struct tags/inputs; values are parameterized.
	// nosemgrep: go.lang.security.audit.database.string-formatted-query.string-formatted-query
	query := fmt.Sprintf(
		"INSERT INTO %s (%s) VALUES (%s) ON DUPLICATE KEY UPDATE %s",
		table,
		strings.Join(cols, ", "),
		strings.Join(placeholders, ", "),
		strings.Join(updatePairs, ", "),
	)
	_, err := m.db.ExecContext(ctx, query, vals...)
	return err
}

// mysqlAdapt converts SQLite-specific SQL fragments to MySQL equivalents.
func mysqlAdapt(sql string) string {
	// AUTOINCREMENT → AUTO_INCREMENT
	sql = strings.ReplaceAll(sql, "AUTOINCREMENT", "AUTO_INCREMENT")
	// INTEGER PRIMARY KEY → INT NOT NULL AUTO_INCREMENT PRIMARY KEY
	sql = strings.ReplaceAll(sql, "INTEGER PRIMARY KEY AUTO_INCREMENT",
		"INT NOT NULL AUTO_INCREMENT PRIMARY KEY")
	// REAL → DOUBLE
	sql = strings.ReplaceAll(sql, " REAL ", " DOUBLE ")
	// Remove SQLite-specific ON CONFLICT — handled via ON DUPLICATE KEY UPDATE above
	sql = strings.ReplaceAll(sql, "ON CONFLICT DO NOTHING", "")
	return sql
}
