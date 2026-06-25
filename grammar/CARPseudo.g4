// CARPseudo.g4 — ANTLR4 grammar for MITRE CAR pseudocode
// Strict mode: rejects ambiguous input for human review
// Covers the core DSL: search, filter, join, group, output, assign

grammar CARPseudo;

// === PARSER RULES ===

program
    : statement+ EOF
    ;

statement
    : searchStmt
    | filterStmt
    | joinStmt
    | groupStmt
    | selectStmt
    | outputStmt
    | assignStmt
    | runStmt
    | setDiffStmt
    ;

// variable = search DataModel:Action[, DataModel:Action]*
searchStmt
    : ID ASSIGN 'search' dataModelRef (',' dataModelRef)*
    ;

// variable = filter source where (conditions)
filterStmt
    : ID ASSIGN 'filter' ID 'where' '(' expr ')'
    ;

// variable = join (var1, var2) where (conditions)
joinStmt
    : ID ASSIGN 'join' '(' idList ')' 'where' '(' expr ')'
    ;

// variable = group source by field1, field2 [temporal]
groupStmt
    : ID ASSIGN 'group' ID 'by' fieldList temporalClause?
    ;

// variable = from source select aggregations
selectStmt
    : ID ASSIGN 'from' ID 'select' aggExpr (',' aggExpr)*
    ;

// output var1[, var2, ...]
outputStmt
    : 'output' idList
    ;

// variable.field = expression
assignStmt
    : fieldRef ASSIGN expr
    ;

// variable = run Analytic:CAR-ID
runStmt
    : ID ASSIGN 'run' 'Analytic:' CAR_ID
    ;

// variable = a - b (set difference)
setDiffStmt
    : ID ASSIGN ID '-' ID
    ;

// === DATA MODEL ===

dataModelRef
    : ID ':' ID                     // e.g., Process:Create, Flow:Message
    ;

// === EXPRESSIONS ===

expr
    : expr 'and' expr               // boolean AND
    | expr 'or' expr                // boolean OR
    | 'not' expr                    // boolean NOT
    | '(' expr ')'                  // grouping
    | comparison                    // leaf comparison
    | temporalExpr                  // time-based condition
    ;

comparison
    : fieldRef compOp value                     // field == "value"
    | fieldRef 'not' 'in' valueList             // field not in [...]
    | fieldRef 'in' valueList                   // field in [...]
    | fieldRef 'match' STRING                   // field match "regex"
    | fieldRef 'exists'                         // field exists
    | fieldRef compOp fieldRef                  // field == other.field
    ;

temporalExpr
    : fieldRef '<' fieldRef '<' fieldRef '+' duration   // a.time < b.time < a.time + 1sec
    | fieldRef '<' fieldRef                             // a.time < b.time
    | fieldRef '-' fieldRef compOp duration             // latest - earliest <= 1 hour
    ;

compOp
    : '=='
    | '!='
    | '<'
    | '>'
    | '<='
    | '>='
    ;

// === VALUES ===

value
    : STRING                        // "cmd.exe", "*\\cmd.exe"
    | INT                           // 445, 3389
    | 'null'                        // null
    | duration                      // 1 hour, 30 minutes
    ;

valueList
    : '[' value (',' value)* ']'    // [1100, 1102, 1104]
    | '(' value (',' value)* ')'   // ("val1", "val2")
    ;

duration
    : INT timeUnit
    ;

timeUnit
    : 'sec' | 'second' | 'seconds'
    | 'minute' | 'minutes' | 'min'
    | 'hour' | 'hours'
    | 'day' | 'days'
    ;

// === AGGREGATIONS ===

aggExpr
    : aggFunc '(' fieldRef ')' ('as' ID)?
    ;

aggFunc
    : 'min' | 'max' | 'count' | 'unique' | 'average' | 'standard_deviation'
    ;

// === FIELD REFERENCES ===

fieldRef
    : ID ('.' ID)*                  // hostname, smb_write.proto_info.file_name
    ;

fieldList
    : fieldRef (',' fieldRef)*
    ;

idList
    : ID (',' ID)*
    ;

temporalClause
    : 'where' '(' 'max' 'time' 'between' 'two' 'events' 'is' duration ')'
    ;

// === LEXER RULES ===

ASSIGN  : '=' ;

CAR_ID  : 'CAR-' [0-9]+ '-' [0-9]+ '-' [0-9]+ ;

ID      : [a-zA-Z_] [a-zA-Z0-9_]* ;

STRING  : '"' (~["\r\n] | '\\"')* '"'
        | '\'' (~['\r\n] | '\\\'')* '\''
        ;

INT     : [0-9]+ ;

// Skip whitespace and comments
WS      : [ \t\r\n]+ -> skip ;
COMMENT : '#' ~[\r\n]* -> skip ;
