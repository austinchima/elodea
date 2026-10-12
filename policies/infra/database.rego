# Title: SQL against databases (reads allowed, destructive writes held)
package elodea.authz

import rego.v1

# database.query arguments: sql (string). Classification is keyword-based and
# deliberately conservative: a statement it cannot classify as a plain read or
# a bounded write goes to a person. A false positive (a keyword inside a
# string literal) costs a review; it never lets a write through as a read.

sql_text := input.arguments.sql

sql_valid if infra_name_valid(sql_text)

# Guarded so a non-string argument is "no match", never a builtin error (which
# the engine would turn into a policy_eval_error deny instead of sql_invalid).
sql_matches(pattern) if {
    is_string(sql_text)
    regex.match(pattern, sql_text)
}

# Statements that change data, schema, permissions, or run code. Any of these
# anywhere (including inside a CTE) disqualifies a statement from being a read.
sql_mutating if sql_matches(`(?i)\b(insert|update|delete|merge|drop|truncate|alter|create|grant|revoke|copy|call|do)\b`)

# More than one statement: "SELECT 1; DROP TABLE users".
sql_multiple_statements if sql_matches(`;\s*\S`)

sql_destructive if sql_matches(`(?i)\b(drop|truncate)\b`)

sql_schema_or_permission_change if sql_matches(`(?i)\b(alter|create|grant|revoke)\b`)

# DELETE or UPDATE with no WHERE clause touches every row.
sql_unbounded_write if {
    sql_matches(`(?i)^\s*(delete|update)\b`)
    not sql_matches(`(?i)\bwhere\b`)
}

sql_read_only if {
    sql_valid
    sql_matches(`(?i)^\s*(select|with|explain|show)\b`)
    not sql_mutating
    not sql_multiple_statements
}

sql_bounded_write if {
    sql_valid
    sql_matches(`(?i)^\s*(insert|update|delete)\b`)
    not sql_unbounded_write
    not sql_destructive
    not sql_schema_or_permission_change
    not sql_multiple_statements
    not sql_matches(`(?i)\b(copy|call|do)\b`)
}

sql_specific_hold if sql_destructive
sql_specific_hold if sql_schema_or_permission_change
sql_specific_hold if sql_unbounded_write
sql_specific_hold if sql_multiple_statements

decisions contains {"action": "allow", "rule": "sql_read_only", "explanation": "Read-only SQL statement"} if {
    infra_tool == "database.query"
    sql_read_only
}

decisions contains {"action": "allow", "rule": "sql_bounded_write", "explanation": "Single INSERT, or UPDATE/DELETE with a WHERE clause"} if {
    infra_tool == "database.query"
    sql_bounded_write
}

decisions contains {"action": "quarantine", "rule": "sql_invalid", "explanation": "SQL statement is missing or empty. Routed to human approval."} if {
    infra_tool == "database.query"
    not sql_valid
}

decisions contains {"action": "quarantine", "rule": "sql_destructive", "explanation": "DROP or TRUNCATE. Routed to human approval."} if {
    infra_tool == "database.query"
    sql_valid
    sql_destructive
}

decisions contains {"action": "quarantine", "rule": "sql_schema_or_permission_change", "explanation": "Schema or permission change. Routed to human approval."} if {
    infra_tool == "database.query"
    sql_valid
    not sql_destructive
    sql_schema_or_permission_change
}

decisions contains {"action": "quarantine", "rule": "sql_unbounded_write", "explanation": "UPDATE or DELETE without a WHERE clause affects every row. Routed to human approval."} if {
    infra_tool == "database.query"
    sql_valid
    not sql_destructive
    not sql_schema_or_permission_change
    sql_unbounded_write
}

decisions contains {"action": "quarantine", "rule": "sql_multiple_statements", "explanation": "More than one SQL statement in a call. Routed to human approval."} if {
    infra_tool == "database.query"
    sql_valid
    not sql_destructive
    not sql_schema_or_permission_change
    not sql_unbounded_write
    sql_multiple_statements
}

decisions contains {"action": "quarantine", "rule": "sql_unclassified", "explanation": "SQL statement is neither a plain read nor a bounded write. Routed to human approval."} if {
    infra_tool == "database.query"
    sql_valid
    not sql_read_only
    not sql_bounded_write
    not sql_specific_hold
}
