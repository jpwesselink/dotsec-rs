use comfy_table::{
    modifiers::UTF8_ROUND_CORNERS, presets::UTF8_FULL, Cell, CellAlignment, ContentArrangement,
    Table,
};
pub use configuration::*;
use dotenv::{lines_to_json, Line};
use schemars::schema_for;
mod configuration;
mod constants;
mod errors;

// pub fn hola_mundo() {
//     println!("Hola, mundo!");
// }

pub fn encrypt() {
    println!("Encryopt");
}

pub fn run() {
    println!("Run");
}

pub fn create_schema() {
    println!("Create schema");
}

async fn load_and_parse_env_file(env_file: &str) -> Result<Vec<Line>, Box<dyn std::error::Error>> {
    let env_content = load_file(env_file)?;
    let lines = dotenv::parse_dotenv(&env_content)?;
    Ok(lines)
}

pub enum ShowTarget {
    Env,
    Sec(EncryptionEngine),
}
pub async fn show(
    file_name: &str,
    show_target: &ShowTarget,
    output_format: &OutputFormat,
) -> Result<String, Box<dyn std::error::Error>> {
    let lines = match show_target {
        ShowTarget::Env => load_and_parse_env_file(file_name).await?,
        ShowTarget::Sec(encryption_engine) => match &encryption_engine {
            EncryptionEngine::Aws(_encryption_options) => {
                let key_id = _encryption_options.key_id.as_ref();
                aws::user_can_connect_to_aws(key_id).await?;
                load_and_parse_sec_file(file_name, encryption_engine).await?
            }
            EncryptionEngine::Pki(_) => {
                return Err("Encryption engine PKI is not supported yet".into());
            }
            EncryptionEngine::None => {
                return Err("Encryption engine is required".into());
            }
        },
    };

    create_output(&lines, &output_format)
}

fn create_output(
    lines: &Vec<Line>,
    output_format: &OutputFormat,
) -> Result<String, Box<dyn std::error::Error>> {
    match output_format {
        OutputFormat::Raw => {
            // just return the kv lines as a string with no formatting like {key}={value}
            let lines_string = lines
                .iter()
                .filter_map(|line| match line {
                    Line::Kv(key, value, _) => Some(format!("{key}={value}")),
                    _ => None,
                })
                .collect::<Vec<String>>()
                .join("\n");

            Ok(lines_string)
        }
        OutputFormat::Text => {
            let mut table = Table::new();
            table
                .load_preset(UTF8_FULL)
                .apply_modifier(UTF8_ROUND_CORNERS)
                .set_content_arrangement(ContentArrangement::Dynamic)
                .set_header(vec!["Key", "Value"]);
            for line in lines {
                match line {
                    dotenv::Line::Kv(var_name, var_value, _) => {
                        table.add_row(vec![var_name, &var_value]);
                    }
                    _ => continue,
                }
            }
            let table_string: String = format!("{table}");

            Ok(table_string)
        }
        OutputFormat::Json => {
            let json = lines_to_json(lines)?;
            Ok(json)
        }
        OutputFormat::Csv => {
            let csv = dotenv::lines_to_csv(lines)?;
            Ok(csv)
        }
    }
}

pub async fn load_and_parse_sec_file(
    sec_file: &str,
    encryption_engine: &EncryptionEngine,
) -> Result<Vec<Line>, Box<dyn std::error::Error>> {
    // check if user can connect to AWS

    match encryption_engine {
        EncryptionEngine::Aws(encryption_options) => {
            let cloned_encryption_options = encryption_options.clone();
            let aws_key_id = cloned_encryption_options.key_id.as_ref();
            println!("AWS key id: {:?}", aws_key_id);
            let sec_content = load_file(sec_file)?;
            let sec_lines = dotenv::parse_dotenv(&sec_content)?;
            let dotsec_value_option = dotenv::get_value(sec_lines, "__DOTSEC__");
            // create result
            let dotsec_value = dotsec_value_option?;
            let plaintext_content = aws::decrypt(dotsec_value.as_str(), aws_key_id).await?;

            let plaintext_lines = dotenv::parse_dotenv(&plaintext_content)?;
            Ok(plaintext_lines)
        }
        EncryptionEngine::Pki(_) => {
            return Err("Encryption engine PKI is not supported yet".into());
        }
        EncryptionEngine::None => {
            return Err("Encryption engine is required".into());
        }
    }
}

pub fn load_file(file: &str) -> Result<String, std::io::Error> {
    let result = std::fs::read_to_string(file);
    match result {
        Ok(content) => Ok(content),
        Err(error) => Err(error),
    }
}

pub fn parse_content(content: &str) -> Result<Vec<Line>, Box<dyn std::error::Error>> {
    let parse_result = dotenv::parse_dotenv(content)?;
    Ok(parse_result)
}

pub fn create_configuration_json_schema() -> Result<String, serde_json::Error> {
    let schema = schema_for!(DotsecConfig);

    return serde_json::to_string_pretty(&schema);
}
