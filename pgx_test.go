package pgx_test

import (
	"context"
	"os"
	"testing"

	"github.com/cuityhj/pgx/v5"
	_ "github.com/cuityhj/pgx/v5/stdlib"
)

func skipCockroachDB(t testing.TB, msg string) {
	conn, err := pgx.Connect(context.Background(), os.Getenv("PGX_TEST_DATABASE"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(context.Background())

	if conn.PgConn().ParameterStatus("crdb_version") != "" {
		t.Skip(msg)
	}
}
