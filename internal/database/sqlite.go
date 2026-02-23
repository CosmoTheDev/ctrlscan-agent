package database

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/CosmoTheDev/ctrlscan-agent/internal/config"
	_ "github.com/mattn/go-sqlite3"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// SQLiteDB implements DB using SQLite via mattn/go-sqlite3.
type SQLiteDB struct {
	db   *sql.DB
	path string
}

// NewSQLite opens (or creates) the SQLite database at cfg.Path.
func NewSQLite(cfg config.DatabaseConfig) (*SQLiteDB, error) {
	path := cfg.Path
	if path == "" {
		home, _ := os.UserHomeDir()
		path = filepath.Join(home, config.DefaultDBFile)
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("creating database directory: %w", err)
	}

	dsn := fmt.Sprintf("file:%s?_foreign_keys=on&_journal_mode=WAL&_synchronous=NORMAL", path)
	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return nil, fmt.Errorf("opening sqlite database: %w", err)
	}

	db.SetMaxOpenConns(1) // SQLite is single-writer
	db.SetMaxIdleConns(1)

	s := &SQLiteDB{db: db, path: path}
	if err := s.Ping(context.Background()); err != nil {
		return nil, fmt.Errorf("pinging sqlite: %w", err)
	}
	return s, nil
}

func (s *SQLiteDB) Driver() string { return "sqlite" }

func (s *SQLiteDB) Ping(ctx context.Context) error {
	return s.db.PingContext(ctx)
}

func (s *SQLiteDB) Close() error {
	return s.db.Close()
}

// Migrate applies all *.sql files from migrations/ in sorted order,
// using a migrations table to track what has been applied.
func (s *SQLiteDB) Migrate(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		id          INTEGER PRIMARY KEY AUTOINCREMENT,
		filename    TEXT    NOT NULL UNIQUE,
		applied_at  TEXT    NOT NULL
	)`)
	if err != nil {
		return fmt.Errorf("creating schema_migrations table: %w", err)
	}

	entries, err := migrationsFS.ReadDir("migrations")
	if err != nil {
		return fmt.Errorf("reading migrations dir: %w", err)
	}

	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".sql") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)

	for _, name := range names {
		var count int
		row := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM schema_migrations WHERE filename = ?`, name)
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

		if _, err := s.db.ExecContext(ctx, string(data)); err != nil {
			return fmt.Errorf("applying migration %s: %w", name, err)
		}

		_, err = s.db.ExecContext(ctx,
			`INSERT INTO schema_migrations (filename, applied_at) VALUES (?, ?)`,
			name, time.Now().UTC().Format(time.RFC3339))
		if err != nil {
			return fmt.Errorf("recording migration %s: %w", name, err)
		}
		slog.Info("Applied migration", "file", name)
	}
	return nil
}

// Select executes query and scans all rows into dest (must be a pointer to a slice of structs).
func (s *SQLiteDB) Select(ctx context.Context, dest interface{}, query string, args ...interface{}) error {
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("query: %w", err)
	}
	defer rows.Close()
	return scanRows(rows, dest)
}

// Get executes query and scans a single row into dest.
func (s *SQLiteDB) Get(ctx context.Context, dest interface{}, query string, args ...interface{}) error {
	row := s.db.QueryRowContext(ctx, query, args...)
	return scanRow(row, dest)
}

// Exec executes a statement that returns no rows.
func (s *SQLiteDB) Exec(ctx context.Context, query string, args ...interface{}) error {
	_, err := s.db.ExecContext(ctx, query, args...)
	return err
}

// Insert inserts a struct into table using its `db:` tags.
// Returns the last inserted row ID.
func (s *SQLiteDB) Insert(ctx context.Context, table string, record interface{}) (int64, error) {
	cols, placeholders, vals := structToInsert(record)
	// Internal DB helper: table/column names come from trusted application code, values remain parameterized.
	// nosemgrep: go.lang.security.audit.database.string-formatted-query.string-formatted-query
	query := fmt.Sprintf("INSERT INTO %s (%s) VALUES (%s)",
		table, strings.Join(cols, ", "), strings.Join(placeholders, ", "))
	res, err := s.db.ExecContext(ctx, query, vals...)
	if err != nil {
		return 0, fmt.Errorf("insert into %s: %w", table, err)
	}
	return res.LastInsertId()
}

// Update updates rows in table matching where clause.
func (s *SQLiteDB) Update(ctx context.Context, table string, record interface{}, where string, args ...interface{}) error {
	cols, vals := structToUpdate(record)
	sets := make([]string, len(cols))
	for i, c := range cols {
		sets[i] = c + " = ?"
	}
	// Internal DB helper: callers provide trusted SQL fragments for table/where; data values are bound separately.
	// nosemgrep: go.lang.security.audit.database.string-formatted-query.string-formatted-query
	query := fmt.Sprintf("UPDATE %s SET %s WHERE %s", table, strings.Join(sets, ", "), where)
	allArgs := append(vals, args...)
	_, err := s.db.ExecContext(ctx, query, allArgs...)
	return err
}

// Upsert inserts or replaces based on conflictCols using INSERT OR REPLACE.
func (s *SQLiteDB) Upsert(ctx context.Context, table string, record interface{}, conflictCols []string) error {
	cols, placeholders, vals := structToInsert(record)
	updateCols := make([]string, 0, len(cols))
	for _, c := range cols {
		skip := false
		for _, cc := range conflictCols {
			if c == cc {
				skip = true
				break
			}
		}
		if !skip {
			updateCols = append(updateCols, fmt.Sprintf("%s = excluded.%s", c, c))
		}
	}

	// Internal DB helper: SQL identifiers are constructed from trusted struct tags/inputs; values are parameterized.
	// nosemgrep: go.lang.security.audit.database.string-formatted-query.string-formatted-query
	query := fmt.Sprintf(
		"INSERT INTO %s (%s) VALUES (%s) ON CONFLICT(%s) DO UPDATE SET %s",
		table,
		strings.Join(cols, ", "),
		strings.Join(placeholders, ", "),
		strings.Join(conflictCols, ", "),
		strings.Join(updateCols, ", "),
	)
	_, err := s.db.ExecContext(ctx, query, vals...)
	return err
}

// --- reflection helpers ---

// structToInsert extracts column names, placeholders and values from a struct
// using `db:` tags. Fields with db:"-" or zero-value id fields are skipped.
func structToInsert(record interface{}) (cols, placeholders []string, vals []interface{}) {
	v := reflect.ValueOf(record)
	if v.Kind() == reflect.Ptr {
		v = v.Elem()
	}
	t := v.Type()
	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		tag := field.Tag.Get("db")
		if tag == "" || tag == "-" {
			continue
		}
		// Skip zero-value "id" to let the DB auto-assign.
		if tag == "id" && v.Field(i).IsZero() {
			continue
		}
		cols = append(cols, tag)
		placeholders = append(placeholders, "?")
		vals = append(vals, v.Field(i).Interface())
	}
	return
}

// structToUpdate extracts column/value pairs (excluding id).
func structToUpdate(record interface{}) (cols []string, vals []interface{}) {
	v := reflect.ValueOf(record)
	if v.Kind() == reflect.Ptr {
		v = v.Elem()
	}
	t := v.Type()
	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		tag := field.Tag.Get("db")
		if tag == "" || tag == "-" || tag == "id" {
			continue
		}
		cols = append(cols, tag)
		vals = append(vals, v.Field(i).Interface())
	}
	return
}

// scanRows scans sql.Rows into a slice of structs using `db:` tags.
func scanRows(rows *sql.Rows, dest interface{}) error {
	cols, err := rows.Columns()
	if err != nil {
		return err
	}

	dv := reflect.ValueOf(dest)
	if dv.Kind() != reflect.Ptr || dv.Elem().Kind() != reflect.Slice {
		return fmt.Errorf("Select: dest must be a pointer to a slice")
	}
	sliceVal := dv.Elem()
	elemType := sliceVal.Type().Elem()
	isPtr := elemType.Kind() == reflect.Ptr
	if isPtr {
		elemType = elemType.Elem()
	}

	for rows.Next() {
		elem := reflect.New(elemType).Elem()
		ptrs := fieldPointers(elem, cols)
		if err := rows.Scan(ptrs...); err != nil {
			return err
		}
		if isPtr {
			sliceVal.Set(reflect.Append(sliceVal, elem.Addr()))
		} else {
			sliceVal.Set(reflect.Append(sliceVal, elem))
		}
	}
	return rows.Err()
}

// scanRow scans a single sql.Row into dest struct.
func scanRow(row *sql.Row, dest interface{}) error {
	// We can't get column names from sql.Row directly without QueryContext,
	// so we use a simple scan by reflecting the struct field order.
	dv := reflect.ValueOf(dest)
	if dv.Kind() != reflect.Ptr {
		return fmt.Errorf("Get: dest must be a pointer")
	}
	elem := dv.Elem()
	var ptrs []interface{}
	for i := 0; i < elem.NumField(); i++ {
		f := elem.Type().Field(i)
		if tag := f.Tag.Get("db"); tag != "" && tag != "-" {
			ptrs = append(ptrs, elem.Field(i).Addr().Interface())
		}
	}
	return row.Scan(ptrs...)
}

// fieldPointers maps column names to struct field pointers via `db:` tags.
func fieldPointers(elem reflect.Value, cols []string) []interface{} {
	tagMap := map[string]interface{}{}
	t := elem.Type()
	for i := 0; i < t.NumField(); i++ {
		tag := t.Field(i).Tag.Get("db")
		if tag != "" && tag != "-" {
			tagMap[tag] = elem.Field(i).Addr().Interface()
		}
	}
	ptrs := make([]interface{}, len(cols))
	for i, c := range cols {
		if p, ok := tagMap[c]; ok {
			ptrs[i] = p
		} else {
			var discard interface{}
			ptrs[i] = &discard
		}
	}
	return ptrs
}
