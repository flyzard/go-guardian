package database

import (
	"database/sql"
	"fmt"
	"strings"
)

// QueryBuilder provides a fluent interface for building SQL queries
type QueryBuilder struct {
	db *DB
}

// Query creates a new QueryBuilder instance
func (db *DB) Query() *QueryBuilder {
	return &QueryBuilder{db: db}
}

// Select builds a SELECT query with parameterized inputs
func (qb *QueryBuilder) Select(table string, columns ...string) *SelectQuery {
	return &SelectQuery{
		db:      qb.db,
		table:   table,
		columns: columns,
	}
}

// SelectQuery represents a SELECT query
type SelectQuery struct {
	db         *DB
	table      string
	columns    []string
	conditions []condition
	orderBy    string
	limit      int
	offset     int
}

type condition struct {
	column string
	op     string
	value  interface{}
}

// Where adds a WHERE clause to the query
func (q *SelectQuery) Where(column, op string, value interface{}) *SelectQuery {
	q.conditions = append(q.conditions, condition{column, op, value})
	return q
}

// OrderBy adds an ORDER BY clause to the query
func (q *SelectQuery) OrderBy(column string, desc bool) *SelectQuery {
	if desc {
		q.orderBy = column + " DESC"
	} else {
		q.orderBy = column + " ASC"
	}
	return q
}

// Limit adds a LIMIT clause to the query
func (q *SelectQuery) Limit(limit int) *SelectQuery {
	q.limit = limit
	return q
}

// Offset adds an OFFSET clause to the query
func (q *SelectQuery) Offset(offset int) *SelectQuery {
	q.offset = offset
	return q
}

// Build constructs the SQL query and its arguments
func (q *SelectQuery) Build() (string, []interface{}) {
	var query strings.Builder
	var args []interface{}

	// SELECT clause
	query.WriteString("SELECT ")
	if len(q.columns) == 0 {
		query.WriteString("*")
	} else {
		query.WriteString(strings.Join(q.columns, ", "))
	}

	// FROM clause
	query.WriteString(" FROM ")
	query.WriteString(q.table)

	// WHERE clause
	if len(q.conditions) > 0 {
		query.WriteString(" WHERE ")
		for i, cond := range q.conditions {
			if i > 0 {
				query.WriteString(" AND ")
			}
			query.WriteString(cond.column)
			query.WriteString(" ")
			query.WriteString(cond.op)
			query.WriteString(" ?")
			args = append(args, cond.value)
		}
	}

	// ORDER BY clause
	if q.orderBy != "" {
		query.WriteString(" ORDER BY ")
		query.WriteString(q.orderBy)
	}

	// LIMIT clause
	if q.limit > 0 {
		query.WriteString(" LIMIT ?")
		args = append(args, q.limit)
	}

	// OFFSET clause
	if q.offset > 0 {
		query.WriteString(" OFFSET ?")
		args = append(args, q.offset)
	}

	return query.String(), args
}

// QueryRow executes the query and returns a single row
func (q *SelectQuery) QueryRow() *sql.Row {
	query, args := q.Build()
	return q.db.QueryRow(query, args...)
}

// Query executes the query and returns the result set
func (q *SelectQuery) Query() (*sql.Rows, error) {
	query, args := q.Build()
	return q.db.DB.Query(query, args...)
}

// Insert creates an INSERT query
func (qb *QueryBuilder) Insert(table string, data map[string]interface{}) (sql.Result, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("no data to insert")
	}

	var columns []string
	var placeholders []string
	var values []interface{}

	for col, val := range data {
		columns = append(columns, col)
		placeholders = append(placeholders, "?")
		values = append(values, val)
	}

	query := fmt.Sprintf(
		"INSERT INTO %s (%s) VALUES (%s)",
		table,
		strings.Join(columns, ", "),
		strings.Join(placeholders, ", "),
	)

	return qb.db.Exec(query, values...)
}

// Update creates an UPDATE query
func (qb *QueryBuilder) Update(table string, data map[string]interface{}, where map[string]interface{}) (sql.Result, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("no data to update")
	}

	var setClauses []string
	var values []interface{}

	for col, val := range data {
		setClauses = append(setClauses, col+" = ?")
		values = append(values, val)
	}

	query := fmt.Sprintf(
		"UPDATE %s SET %s",
		table,
		strings.Join(setClauses, ", "),
	)

	if len(where) > 0 {
		var whereClauses []string
		for col, val := range where {
			whereClauses = append(whereClauses, col+" = ?")
			values = append(values, val)
		}
		query += " WHERE " + strings.Join(whereClauses, " AND ")
	}

	return qb.db.Exec(query, values...)
}

// Delete creates a DELETE query
func (qb *QueryBuilder) Delete(table string, where map[string]interface{}) (sql.Result, error) {
	query := fmt.Sprintf("DELETE FROM %s", table)

	var values []interface{}
	if len(where) > 0 {
		var whereClauses []string
		for col, val := range where {
			whereClauses = append(whereClauses, col+" = ?")
			values = append(values, val)
		}
		query += " WHERE " + strings.Join(whereClauses, " AND ")
	}

	return qb.db.Exec(query, values...)
}
