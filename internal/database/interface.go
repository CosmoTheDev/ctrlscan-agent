package database

import (
	"context"
	"fmt"

	"github.com/CosmoTheDev/ctrlscan-agent/internal/config"
)

// DB is the generic storage interface used throughout ctrlscan.
// Implementations exist for SQLite (default) and MySQL.
// Additional backends (PostgreSQL, etc.) implement this interface.
type DB interface {
	// Select executes a query and scans rows into dest (slice pointer).
	Select(ctx context.Context, dest interface{}, query string, args ...interface{}) error

	// Get executes a query expected to return a single row and scans into dest.
	Get(ctx context.Context, dest interface{}, query string, args ...interface{}) error

	// Exec executes a statement that returns no rows.
	Exec(ctx context.Context, query string, args ...interface{}) error

	// Insert inserts a struct-tagged record into table and returns the new row ID.
	Insert(ctx context.Context, table string, record interface{}) (int64, error)

	// Update updates rows matching the where clause with values from record.
	Update(ctx context.Context, table string, record interface{}, where string, args ...interface{}) error

	// Upsert inserts or updates based on conflictCols (ON CONFLICT clause).
	Upsert(ctx context.Context, table string, record interface{}, conflictCols []string) error

	// Migrate applies pending schema migrations in order.
	Migrate(ctx context.Context) error

	// Ping verifies the database connection is alive.
	Ping(ctx context.Context) error

	// Close releases the database connection.
	Close() error

	// Driver returns the backend name: "sqlite" or "mysql".
	Driver() string
}

// New returns a DB implementation matching cfg.Driver.
// SQLite is the default when driver is empty or unrecognised.
func New(cfg config.DatabaseConfig) (DB, error) {
	switch cfg.Driver {
	case "mysql":
		return NewMySQL(cfg)
	case "sqlite", "sqlite3", "":
		return NewSQLite(cfg)
	default:
		return nil, fmt.Errorf("unsupported database driver %q (supported: sqlite, mysql)", cfg.Driver)
	}
}
