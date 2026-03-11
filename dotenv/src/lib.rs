use pest::iterators::Pair;
use pest::Parser;
use pest_derive::Parser;
use std::collections::HashMap;
use std::ffi::OsString;
use std::fmt;
use types::QuoteType;
mod types;
#[derive(Parser)]
#[grammar = "dotenv.pest"]
struct DotenvLineParser;
pub use types::Line;

impl fmt::Display for QuoteType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            QuoteType::Single => write!(f, "single"),
            QuoteType::Double => write!(f, "double"),
            QuoteType::Backtick => write!(f, "backtick"),
            QuoteType::None => write!(f, "none"),
        }
    }
}

pub fn lines_to_string(lines: Vec<Line>) -> String {
    let mut output = String::new();
    for x in lines {
        match x {
            Line::Comment(comment) => {
                output.push_str(&format!("{}", comment));
            }
            Line::Whitespace(whitespace) => {
                output.push_str(&format!("{}", whitespace));
            }
            Line::Kv(k, v, quote_type) => match quote_type {
                QuoteType::Single => {
                    output.push_str(&format!("{}='{}'", k, v));
                }
                QuoteType::Double => {
                    output.push_str(&format!("{}=\"{}\"", k, v));
                }
                QuoteType::Backtick => {
                    output.push_str(&format!("{}=`{}`", k, v));
                }
                QuoteType::None => {
                    output.push_str(&format!("{}={}", k, v));
                }
            },
            Line::Newline => {
                output.push_str("\n");
            }
        }
    }
    output
}

pub fn lines_to_kv(lines: Vec<Line>) -> HashMap<OsString, OsString> {
    let mut output: HashMap<OsString, OsString> = HashMap::new();
    for x in lines {
        match x {
            Line::Comment(_comment) => {}
            Line::Whitespace(_whitespace) => {}

            Line::Kv(k, v, _quote_type) => {
                output.insert(k.into(), v.into());
            }
            Line::Newline => {}
        }
    }
    output
}

pub fn get_value(source: Vec<Line>, key: &str) -> Result<String, &str> {
    // iterate over source
    for x in source {
        match x {
            Line::Comment(_comment) => {}
            Line::Whitespace(_whitespace) => {}
            Line::Kv(k, v, _quote_type) => {
                if k == key {
                    return Ok(v);
                }
            }
            Line::Newline => {}
        }
    }

    Err("Key not found")
}
//

pub fn add_or_replace_value(source: Vec<Line>, key: &str, value: &str) -> Vec<Line> {
    let mut output: Vec<Line> = Vec::new();
    // iterate over source
    let mut found = false;
    for x in source {
        match x {
            Line::Comment(comment) => {
                output.push(Line::Comment(comment));
            }
            Line::Whitespace(whitespace) => {
                output.push(Line::Whitespace(whitespace));
            }
            Line::Kv(k, v, quote_type) => {
                if k == key {
                    output.push(Line::Kv(k, value.into(), quote_type));
                    found = true;
                } else {
                    output.push(Line::Kv(k, v, quote_type));
                }
            }
            Line::Newline => {
                output.push(Line::Newline);
            }
        }
    }
    if !found {
        // add a newline
        output.push(Line::Newline);
        // add a comment: do not edit this line
        output.push(Line::Comment(
            "# do not edit this line, it was added by dotsec".into(),
        ));
        // add another newline
        output.push(Line::Newline);
        output.push(Line::Kv(key.into(), value.into(), QuoteType::Double));

        output.push(Line::Newline);
    }
    output
}

// pub fn remove_key(source: Vec<Line>, key: &str) -> Vec<Line> {
//     let mut output: Vec<Line> = Vec::new();
//     // iterate over source
//     for x in source {
//         match x {
//             Line::Comment(comment) => {
//                 output.push(Line::Comment(comment));
//             }
//             Line::Whitespace(whitespace) => {
//                 output.push(Line::Whitespace(whitespace));
//             }
//             Line::Kv(k, v, quote_type) => {
//                 if k != key {
//                     output.push(Line::Kv(k, v, quote_type));
//                 }
//             }
//             Line::Newline => {
//                 output.push(Line::Newline);
//             }
//         }
//     }
//     output
// }

pub fn sha_all_values(source: Vec<Line>) -> (Vec<Line>, String) {
    let mut output: Vec<Line> = Vec::new();
    // create hashmap with string and string
    let mut data: HashMap<String, HashMap<&str, String>> = HashMap::new();

    // iterate over source
    for x in source {
        match x {
            Line::Comment(comment) => {
                output.push(Line::Comment(comment));
            }
            Line::Whitespace(whitespace) => {
                output.push(Line::Whitespace(whitespace));
            }
            Line::Kv(k, v, quote_type) => {
                // string with quote type, key and value
                let hash = sha256::digest(format!("{}::{}::{}", quote_type, k, v));

                output.push(Line::Kv(k.clone(), hash.clone(), QuoteType::Double));
                // insert k, hash into data
                // clone k, create str
                let mut store = HashMap::new();
                store.insert("quote_type", format!("{}", quote_type));
                store.insert("key", k.clone());
                store.insert("value", v);
                // store.insert("hash", hash);
                data.insert(k, store);
            }
            Line::Newline => {
                output.push(Line::Newline);
            }
        }
    }
    // use serde to convert hashmap to string
    let serialized = serde_json::to_string(&data).unwrap();
    (output, serialized)
}

// pub fn normalize_to_double_quotes(source: Vec<Line>) -> Vec<Line> {
//     let mut output: Vec<Line> = Vec::new();
//     // iterate over source
//     for x in source {
//         match x {
//             Line::Comment(comment) => {
//                 output.push(Line::Comment(comment));
//             }
//             Line::Whitespace(whitespace) => {
//                 output.push(Line::Whitespace(whitespace));
//             }
//             Line::Kv(k, v, quote_type) => {
//                 if quote_type == QuoteType::Single || quote_type == QuoteType::Backtick {
//                     // replace new lines with \n in v
//                     let v = v.replace("\n", "\\n");
//                     output.push(Line::Kv(k, v, QuoteType::Double));
//                 } else if quote_type == QuoteType::None {
//                     // replace new lines with \n in v
//                     output.push(Line::Kv(k, v, QuoteType::Double));
//                 } else {
//                     output.push(Line::Kv(k, v, quote_type));
//                 }
//             }
//             Line::Newline => {
//                 output.push(Line::Newline);
//             }
//         }
//     }
//     output
// }

/// Parse the .env file source.
pub fn parse_dotenv(source: &str) -> Result<Vec<Line>, pest::error::Error<Rule>> {
    let mut output: Vec<Line> = Vec::new();

    let pairs = DotenvLineParser::parse(Rule::env, source)?;
    for pair in pairs {
        match pair.as_rule() {
            Rule::NEW_LINE => {
                output.push(Line::Newline);
            }
            Rule::COMMENT => {
                let comment = pair.clone().as_str();
                output.push(Line::Comment(comment.into()));
            }
            Rule::WHITESPACE => {
                let whitespace = pair.clone().as_str();
                output.push(Line::Whitespace(whitespace.into()));
            }
            Rule::kv => {
                if let Some((key, value, quote_type)) = parse_kv(pair) {
                    // add to output
                    output.push(Line::Kv(key.clone(), value.clone(), quote_type));
                }
            }
            _ => {}
        }
    }

    Ok(output)
}

/// Parse a key-value pair.
fn parse_kv(pair: Pair<Rule>) -> Option<(String, String, QuoteType)> {
    match pair.as_rule() {
        Rule::kv => {
            let mut inner_rules = pair.into_inner(); // key ~ "=" ~ value
            let name: &str = inner_rules.next().unwrap().as_str();
            let value = inner_rules.next().unwrap(); // value
                                                     // check if is a escaped_dq

            // get inner value
            let (parsed_value, quote_type) = parse_value(value).unwrap();
            Some((name.into(), parsed_value, quote_type))
            // parse_value(value).map(|v| (name.into(), v))
        }
        _ => None,
    }
}

/// Parse a value, which might be a string or a naked variable.
fn parse_value(pair: Pair<Rule>) -> Option<(String, QuoteType)> {
    match pair.as_rule() {
        Rule::value => {
            let inner = pair.clone().into_inner().next();
            // If there are no inner pairs, the current value is a naked
            // variable, otherwise it's a string and we need to extract the
            // inner_sq or inner_dq pair.
            match inner {
                None => Some((pair.as_str().into(), QuoteType::None)),
                Some(inner_pair) => match inner_pair.into_inner().next() {
                    None => None,
                    Some(inner_string) => {
                        // lets check the rules
                        // get inner
                        let inner_string_inner = inner_string.clone().into_inner();
                        // iterate over rules
                        let mut another_clone = inner_string_inner.clone();
                        let quote_type = match another_clone.next() {
                            Some(x) => match x.as_rule() {
                                Rule::escaped_dq => (
                                    another_clone.clone().next().unwrap().as_str().into(),
                                    QuoteType::Double,
                                ),
                                Rule::escaped_sq => (
                                    another_clone.clone().next().unwrap().as_str().into(),
                                    QuoteType::Single,
                                ),
                                Rule::escaped_bt => (
                                    another_clone.clone().next().unwrap().as_str().into(),
                                    QuoteType::Backtick,
                                ),
                                _ => {
                                    println!("string IDK IDK IDK: {}", x.as_str());
                                    (x.as_str().into(), QuoteType::None)
                                }
                            },
                            None => (inner_string.as_str().into(), QuoteType::None),
                        };

                        Some(quote_type)
                    }
                },
            }
        }
        _ => None,
    }
}

pub fn lines_to_json(lines: &Vec<Line>) -> Result<String, serde_json::Error> {
    let mut output: Vec<HashMap<String, String>> = Vec::new();
    for x in lines {
        match x {
            Line::Comment(_comment) => {}
            Line::Whitespace(_whitespace) => {}
            Line::Kv(k, v, _quote_type) => {
                let mut map = HashMap::new();
                map.insert(k.to_string(), v.to_string());
                output.push(map);
            }
            Line::Newline => {}
        }
    }
    Ok(serde_json::to_string(&output).unwrap())
}

pub fn lines_to_csv(lines: &Vec<Line>) -> Result<String, Box<dyn std::error::Error>> {
    let mut output = String::new();
    output.push_str("name,value\n");
    for x in lines {
        match x {
            Line::Comment(_comment) => {}
            Line::Whitespace(_whitespace) => {}
            Line::Kv(k, v, _quote_type) => {
                // escape commas
                output.push_str(&format!("{}\t{}\n", k, v));
            }
            Line::Newline => {}
        }
    }
    Ok(output)
}
// #[cfg(test)]
// mod tests {
//     use super::parse_dotenv;
//     use std::collections::BTreeMap;

//     #[test]
//     fn empty_file() {
//         assert_eq!(parse_dotenv("").unwrap(), BTreeMap::new());
//     }

//     #[test]
//     fn one_kv() {
//         let bm = vec![("key", "value")]
//             .into_iter()
//             .map(|(a, b)| (a.into(), b.into()))
//             .collect();
//         assert_eq!(parse_dotenv("key = value").unwrap(), bm);
//     }

//     #[test]
//     fn one_line() {
//         let bm = vec![("key", "value")]
//             .into_iter()
//             .map(|(a, b)| (a.into(), b.into()))
//             .collect();
//         assert_eq!(parse_dotenv("key = value\n").unwrap(), bm);
//     }

//     #[test]
//     fn two_lines() {
//         let bm = vec![("key", "value"), ("key2", "value2")]
//             .into_iter()
//             .map(|(a, b)| (a.into(), b.into()))
//             .collect();
//         assert_eq!(parse_dotenv("key = value\nkey2 = value2").unwrap(), bm);
//     }

//     #[test]
//     fn non_alphanumeric_chars() {
//         let bm = vec![("key", "https://1.3.2.3:234/a?b=c")]
//             .into_iter()
//             .map(|(a, b)| (a.into(), b.into()))
//             .collect();
//         assert_eq!(parse_dotenv("key=https://1.3.2.3:234/a?b=c\n").unwrap(), bm);
//     }

//     #[test]
//     fn export() {
//         let bm = vec![("key", "value"), ("key2", "value2")]
//             .into_iter()
//             .map(|(a, b)| (a.into(), b.into()))
//             .collect();
//         assert_eq!(
//             parse_dotenv("key = value\nexport key2 = value2").unwrap(),
//             bm
//         );
//     }

//     #[test]
//     fn string_single_quotes() {
//         let bm = vec![("key", "value"), ("key2", "val ue2")]
//             .into_iter()
//             .map(|(a, b)| (a.into(), b.into()))
//             .collect();
//         assert_eq!(parse_dotenv("key = value\nkey2 = 'val ue2'").unwrap(), bm);
//     }

//     #[test]
//     fn string_double_quotes() {
//         let bm = vec![("key", "value"), ("key2", "val ue2")]
//             .into_iter()
//             .map(|(a, b)| (a.into(), b.into()))
//             .collect();
//         assert_eq!(parse_dotenv("key = value\nkey2 = \"val ue2\"").unwrap(), bm);
//     }

//     #[test]
//     fn empty_value_single_quotes() {
//         let bm = vec![("key", "value"), ("key2", "")]
//             .into_iter()
//             .map(|(a, b)| (a.into(), b.into()))
//             .collect();
//         assert_eq!(parse_dotenv("key = value\nkey2 = ''").unwrap(), bm);
//     }

//     #[test]
//     fn empty_value_double_quotes() {
//         let bm = vec![("key", "value"), ("key2", "")]
//             .into_iter()
//             .map(|(a, b)| (a.into(), b.into()))
//             .collect();
//         assert_eq!(parse_dotenv("key = value\nkey2 = \"\"").unwrap(), bm);
//     }

//     #[test]
//     fn comments() {
//         let source = r#"
//             # one here
//             ENV_FOR_HYDRO=production # another one here
//         "#;
//         let bm = vec![("ENV_FOR_HYDRO", "production")]
//             .into_iter()
//             .map(|(a, b)| (a.into(), b.into()))
//             .collect();
//         assert_eq!(parse_dotenv(source).unwrap(), bm);
//     }

//     #[test]
//     fn complete_dotenv() {
//         let source = r#"
//             # main comment

//             ENV_FOR_HYDRO='testing 2' # another one here
//             export USER_ID=5gpPN5rcv5G41U_S
//             API_TOKEN=30af563ccc668bc8ced9e24e  # relax! these values are fake
//             APP_SITE_URL=https://my.example.com
//         "#;
//         let bm = vec![
//             ("ENV_FOR_HYDRO", "testing 2"),
//             ("USER_ID", "5gpPN5rcv5G41U_S"),
//             ("API_TOKEN", "30af563ccc668bc8ced9e24e"),
//             ("APP_SITE_URL", "https://my.example.com"),
//         ]
//         .into_iter()
//         .map(|(a, b)| (a.into(), b.into()))
//         .collect();
//         assert_eq!(parse_dotenv(source).unwrap(), bm);
//     }
// }
// pub fn replace_value(source: Vec<Line>, key: &str, value: &str) -> Vec<Line> {
//     debug!("Replacing value for key: {}", key.yellow());

//     let mut output: Vec<Line> = Vec::new();
//     // iterate over source
//     for x in source {
//         match x {
//             Line::Comment(comment) => {
//                 output.push(Line::Comment(comment));
//             }
//             Line::Whitespace(whitespace) => {
//                 output.push(Line::Whitespace(whitespace));
//             }
//             Line::Kv(k, v, quote_type) => {
//                 if k == key {
//                     debug!(
//                         "Found key: {}, replacing '{}' with '{}'",
//                         key.yellow(),
//                         v.red(),
//                         value.bright_green()
//                     );

//                     output.push(Line::Kv(k, value.into(), quote_type));
//                 } else {
//                     output.push(Line::Kv(k, v, quote_type));
//                 }
//             }
//             Line::Newline => {
//                 output.push(Line::Newline);
//             }
//         }
//     }
//     output
// }
