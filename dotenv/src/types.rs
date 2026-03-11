#[derive(PartialEq, Clone, Debug)]
pub enum QuoteType {
    Single,
    Double,
    Backtick,
    None,
}

#[derive(Clone, Debug)]
pub enum Line {
    Comment(String),
    Kv(String, String, QuoteType),
    Newline,
    Whitespace(String),
}
