package main

import (
	"errors"
	"strings"

	"github.com/jackc/pgx/v5/pgconn"
)

// clientError is the message an API response carries for err.
//
// Handlers returned err.Error() as-is, and for a database failure that is the
// raw Postgres text — `store: create rule: ERROR: new row for relation "rules"
// violates check constraint "rules_source_check" (SQLSTATE 23514)` reached the
// console verbatim. That tells an operator nothing they can act on and tells
// anyone else the schema. A Postgres error becomes a plain sentence naming the
// field when the constraint name says which one; every other error — the
// handlers' own validation messages, request-binding errors — is unchanged.
func clientError(err error) string {
	if err == nil {
		return ""
	}
	var pg *pgconn.PgError
	if !errors.As(err, &pg) {
		return err.Error()
	}
	field := constraintField(pg.ConstraintName, pg.TableName)
	switch pg.Code {
	case "23514": // check_violation
		if field != "" {
			return "the value of " + field + " is not one of the allowed values"
		}
		return "a value is not one of the allowed values"
	case "23505": // unique_violation
		if field != "" {
			return "another record already uses this " + field
		}
		return "a record like this already exists"
	case "23503": // foreign_key_violation
		return "this refers to something that does not exist (or is still in use)"
	case "23502": // not_null_violation
		if pg.ColumnName != "" {
			return pg.ColumnName + " is required"
		}
		return "a required value is missing"
	case "22P02", "22007", "22008": // invalid text representation / datetime
		return "a value is not in the expected format"
	}
	return "the request could not be saved (database error " + pg.Code + ")"
}

// constraintField derives the column from Postgres's default constraint names
// (<table>_<column>_check / _key / _fkey): "rules_source_check" → "source".
func constraintField(constraint, table string) string {
	c := constraint
	for _, suf := range []string{"_check", "_key", "_fkey", "_pkey"} {
		c = strings.TrimSuffix(c, suf)
	}
	if table != "" {
		c = strings.TrimPrefix(c, table+"_")
	}
	if c == "" || c == constraint {
		return ""
	}
	return strings.ReplaceAll(c, "_", " ")
}
