use std::{str::FromStr, time::Duration};
mod constants;

use crate::constants::AWS_KEY_ID;
use aes_gcm::Aes128Gcm;
use aws_config::{meta::region::RegionProviderChain, BehaviorVersion};
use aws_sdk_kms::{
    error::SdkError,
    operation::{
        describe_key::DescribeKeyError, get_key_policy::GetKeyPolicyError, list_keys::ListKeysError,
    },
};
use aws_sdk_sts::{
    config::http::HttpResponse, operation::get_caller_identity::GetCallerIdentityError,
};
use aws_sdk_verifiedpermissions::operation::{
    is_authorized::IsAuthorizedError, is_authorized_with_token::IsAuthorizedWithTokenError,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use colored::Colorize;
use envelopers::{
    CacheOptions, CachingKeyWrapper, EncryptedRecord, EnvelopeCipher, KMSKeyProvider,
};
use log::{debug, info};
use thiserror::Error;

// create compound error with to_string

#[derive(Error, Debug)]
pub enum DataStoreError {
    #[error("encryption error")]
    EncryptionError(#[from] envelopers::EncryptionError),
    #[error("decryption error")]
    DecryptionError(#[from] envelopers::DecryptionError),
    #[error("decoding error")]
    DecodError(#[from] base64::DecodeError),
    #[error["authorization error {0}"]]
    AuthorizationError(#[from] ListKeysError),
    #[error("unknown data store error")]
    Unknown(#[from] std::io::Error),

    #[error["authorization error"]]
    UnauthorizedError(#[from] IsAuthorizedError),
    #[error["authorization error"]]
    UnauthorizedWithTokenError(#[from] IsAuthorizedWithTokenError),
    #[error("Could not get AWS caller identity, or, in other words, with the current AWS credentials, AWS will not authenticate you. Take a look at https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-quickstart.html#cli-configure-quickstart-creds for more information.")]
    Nope(#[from] GetCallerIdentityError),

    #[error("kms access denied")]
    KmsAccessDenied(#[from] SdkError<GetKeyPolicyError, HttpResponse>),

    #[error("Couldn't find key '{key_id}'\nGot error:{error}")]
    KmsKeyNotFound {
        key_id: String,
        error: SdkError<DescribeKeyError, HttpResponse>,
    },
}
pub async fn encrypt(
    env_contents: &str,
    key_id: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let config = aws_config::load_from_env().await;
    let client = aws_sdk_kms::Client::new(&config);
    // if log_level is verbose or on, print filename

    info!("Encrypting {} variables", "unencrypted".yellow());

    let env_parsed = dotenv::parse_dotenv(env_contents);

    match env_parsed {
        Ok(lines) => {
            let new_lines = lines.clone();

            let (lines_with_sha_values, _serialized) = dotenv::sha_all_values(new_lines.clone());

            let lines_string = dotenv::lines_to_string(new_lines);

            let provider =
                KMSKeyProvider::<Aes128Gcm>::new(client.clone(), String::from_str(key_id).unwrap());
            let cipher: EnvelopeCipher<_> = EnvelopeCipher::init(CachingKeyWrapper::new(
                provider,
                CacheOptions::default()
                    .with_max_age(Duration::from_secs(30))
                    .with_max_bytes(100 * 1024)
                    .with_max_messages(10)
                    .with_max_entries(10),
            ));

            let encrypted = cipher
                .encrypt(lines_string.as_bytes())
                .await
                .map_err(|source| DataStoreError::EncryptionError(source))?;
            // shit
            let some_vec = encrypted.to_vec()?;
            let some_vec_str = STANDARD.encode(some_vec.clone());

            // create a new key in the env file, with the encrypted string
            let new_env_contents =
                dotenv::add_or_replace_value(lines_with_sha_values, "__DOTSEC__", &some_vec_str);

            let new_env_contents = dotenv::lines_to_string(new_env_contents);

            Ok(new_env_contents)
        }
        Err(e) => {
            println!("Error encrypting: {}", e);
            return Err(e.into());
        }
    }
}

pub async fn decrypt(
    ciphertext: &str,
    key_id: Option<&String>,
) -> Result<String, Box<dyn std::error::Error>> {
    let aws_key_id_constant = String::from(AWS_KEY_ID);
    let key_id = key_id.unwrap_or(&aws_key_id_constant);
    let region_provider = RegionProviderChain::default_provider().or_else("us-east-1");
    let config = aws_config::defaults(BehaviorVersion::latest())
        .region(region_provider)
        .load()
        .await;
    let client = aws_sdk_kms::Client::new(&config);

    let dotsec_value_decoded = STANDARD.decode(ciphertext)?;
    // create EncryptedRecord from vec
    let encrypted: EncryptedRecord = EncryptedRecord::from_vec(dotsec_value_decoded).unwrap();
    // decrypt
    let provider =
        KMSKeyProvider::<Aes128Gcm>::new(client.clone(), String::from_str(key_id).unwrap());
    let cipher: EnvelopeCipher<_> = EnvelopeCipher::init(CachingKeyWrapper::new(
        provider,
        CacheOptions::default()
            .with_max_age(Duration::from_secs(30))
            .with_max_bytes(100 * 1024)
            .with_max_messages(10)
            .with_max_entries(10),
    ));

    let decrypted_vec = cipher
        .decrypt(&encrypted)
        .await
        .map_err(|source| DataStoreError::DecryptionError(source))?;
    let new_env_contents = String::from_utf8(decrypted_vec)?;
    Ok(new_env_contents)
}

pub async fn user_can_connect_to_aws(key_id: Option<&String>) -> Result<(), DataStoreError> {
    debug!("Checking if user can connect to AWS");
    // debug key_id
    debug!("Key ID: {:?}", key_id);
    let aws_key_id_constant = String::from(AWS_KEY_ID);
    let key_id = key_id.unwrap_or(&aws_key_id_constant);
    debug!("Key ID: {:?}", &key_id);

    let config = aws_config::load_from_env().await;

    // check if current user can KMS:Decrypt and KMS:Encrypt on our specific alias
    let kms_client = aws_sdk_kms::Client::new(&config);
    // get real key id from alias
    let key_description = kms_client.describe_key().key_id(key_id).send().await;
    if let Err(e) = key_description {
        return Err(DataStoreError::KmsKeyNotFound {
            key_id: key_id.to_string(),
            error: e,
        });
    }
    debug!("key_description: {:?}", key_description);

    // extract key id from the response
    let describe_key_output = key_description.unwrap();
    let key_metadata = describe_key_output.key_metadata.unwrap();
    let key_id_real = key_metadata.key_id();
    debug!("Key ID real: {:?}", key_id_real);
    let kms_policy = kms_client.get_key_policy().key_id(key_id_real).send().await;
    debug!("KMS policy: {:?}", kms_policy);

    if kms_policy.is_ok() {
        debug!("User has access to the key");
    } else {
        debug!("User does not have access to the key");
        let damn_error = kms_policy.unwrap_err();
        return Err(DataStoreError::KmsAccessDenied(damn_error));
    }

    Ok(())
}

pub fn get_error_chain(e: &Box<dyn std::error::Error>) -> String {
    let mut error_chain = String::new();
    let mut source = e.source();
    while let Some(e) = source {
        error_chain.push_str(&format!("{}\n", e));
        source = e.source();
    }
    error_chain
}
pub async fn check_if_user_is_logged_in() -> bool {
    let config = aws_config::load_from_env().await;
    let client = aws_sdk_kms::Client::new(&config);
    // ask aws if user is logged in

    let result = client.list_keys().send().await;

    match result {
        Ok(_) => true,
        Err(_) => false,
    }
}

// #[cfg(test)]
// mod tests {
//     use super::*;

//     #[test]
//     fn it_works() {
//         let result = add(2, 2);
//         assert_eq!(result, 4);
//     }
// }
