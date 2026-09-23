package main

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

func TestClientErrorNeverLeaksPostgresText(t *testing.T) {
	pg := &pgconn.PgError{Code: "23514", Message: `new row for relation "rules" violates check constraint "rules_source_check"`,
		ConstraintName: "rules_source_check", TableName: "rules"}
	wrapped := fmt.Errorf("store: create rule: %w", pg)
	got := clientError(wrapped)
	if got != "the value of source is not one of the allowed values" {
		t.Fatalf("got %q", got)
	}
	for _, leak := range []string{"relation", "constraint", "SQLSTATE", "store:"} {
		if strings.Contains(got, leak) {
			t.Fatalf("leaked %q in %q", leak, got)
		}
	}
	uniq := &pgconn.PgError{Code: "23505", ConstraintName: "users_email_key", TableName: "users"}
	if got := clientError(uniq); got != "another record already uses this email" {
		t.Fatalf("unique: %q", got)
	}
	if got := clientError(&pgconn.PgError{Code: "57014"}); !strings.Contains(got, "database error 57014") {
		t.Fatalf("other: %q", got)
	}
}

func TestClientErrorKeepsOurOwnMessages(t *testing.T) {
	msg := "one or more domains are already served by another site"
	if got := clientError(errors.New(msg)); got != msg {
		t.Fatalf("our message changed: %q", got)
	}
}
