use thiserror::Error;

#[derive(Debug, Error)]
pub enum ParseError {
    #[error("syntax error at line {line}, col {col}: {message}")]
    Syntax {
        line: usize,
        col: usize,
        message: String,
    },

    #[error("unexpected end of input")]
    UnexpectedEof,

    #[error("invalid rule id: {0}")]
    InvalidRuleId(String),

    #[error("unknown target: {0}")]
    UnknownTarget(String),

    #[error("unknown operator: {0}")]
    UnknownOperator(String),

    #[error("unknown action: {0}")]
    UnknownAction(String),

    #[error("unknown phase: {0}")]
    UnknownPhase(String),

    #[error("invalid float: {0}")]
    InvalidFloat(String),

    #[error("invalid integer: {0}")]
    InvalidInt(String),

    #[error("unmatched braces")]
    UnmatchedBraces,
}

/// Return the (line, column) of `remaining` within `full_input`.
pub fn line_col(full_input: &str, remaining: &str) -> (usize, usize) {
    let offset = full_input.len().saturating_sub(remaining.len());
    let consumed = &full_input[..offset];
    let line = consumed.bytes().filter(|&b| b == b'\n').count() + 1;
    let col = consumed.rfind('\n').map(|p| offset - p).unwrap_or(offset) + 1;
    (line, col)
}

impl ParseError {
    pub fn from_nom(full_input: &str, err: nom::Err<nom::error::Error<&str>>) -> Self {
        match err {
            nom::Err::Incomplete(_) => Self::UnexpectedEof,
            nom::Err::Error(e) | nom::Err::Failure(e) => {
                let (line, col) = line_col(full_input, e.input);
                Self::Syntax {
                    line,
                    col,
                    message: format!("{:?}", e.code),
                }
            }
        }
    }
}
