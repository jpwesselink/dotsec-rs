//! End-to-end KMS round-trip via LocalStack. Closes the coverage gap noted in
//! `aws::generate_data_key`'s doc-comment: the symmetric `EncryptionContext`
//! contract between `generate_data_key` and `unwrap_data_key` was only ever
//! exercised against real AWS accounts.
//!
//! Marked `#[ignore]` so `cargo test` skips it by default. Docker has to be
//! running. Invoke explicitly:
//!
//! ```sh
//! cargo test --test localstack_kms -- --ignored --nocapture
//! ```
//!
//! Why a single test function rather than multiple smaller ones: this test
//! mutates process-global env vars (`AWS_ENDPOINT_URL_KMS`, fake creds) so
//! the AWS SDK redirects to LocalStack. Splitting it across `#[tokio::test]`s
//! that run in parallel would race on those env vars.

use aws_sdk_kms::types::KeySpec;
use testcontainers::{
    core::{IntoContainerPort, WaitFor},
    runners::AsyncRunner,
    GenericImage, ImageExt,
};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires docker; run with --ignored"]
async fn kms_round_trip_via_localstack() {
    let container = GenericImage::new("localstack/localstack", "3.8")
        .with_exposed_port(4566.tcp())
        .with_wait_for(WaitFor::message_on_stdout("Ready."))
        .with_env_var("SERVICES", "kms")
        .with_env_var("DEBUG", "0")
        .start()
        .await
        .expect("failed to start LocalStack container — is docker running?");

    let port = container
        .get_host_port_ipv4(4566)
        .await
        .expect("could not resolve mapped port");
    let endpoint = format!("http://127.0.0.1:{port}");

    // Point the AWS SDK at LocalStack. Modern aws-sdk-rust resolves
    // `AWS_ENDPOINT_URL_KMS` automatically; falling back to the universal
    // `AWS_ENDPOINT_URL` for older behavior versions is belt-and-braces.
    std::env::set_var("AWS_ENDPOINT_URL_KMS", &endpoint);
    std::env::set_var("AWS_ENDPOINT_URL", &endpoint);
    std::env::set_var("AWS_ACCESS_KEY_ID", "test");
    std::env::set_var("AWS_SECRET_ACCESS_KEY", "test");
    std::env::set_var("AWS_REGION", "us-east-1");

    // Create a KMS key inside LocalStack directly via the SDK. We can't use
    // `aws::check_key_alias` for this because we need to create the key first
    // and capture the returned key id. Same SDK client config as our lib will
    // produce because we share the env-driven endpoint.
    let admin_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .load()
        .await;
    let admin = aws_sdk_kms::Client::new(&admin_config);
    let create = admin
        .create_key()
        .key_spec(KeySpec::SymmetricDefault)
        .send()
        .await
        .expect("LocalStack create_key");
    let key_id = create
        .key_metadata()
        .expect("LocalStack returned no key_metadata")
        .key_id()
        .to_string();

    // --- Round-trip 1: same context, decrypt must succeed ---

    let context = vec![("dotsec:format".to_string(), "v3".to_string())];

    let (plaintext_dek, wrapped_dek) = aws::generate_data_key(&key_id, Some("us-east-1"), &context)
        .await
        .expect("generate_data_key");
    assert_eq!(
        plaintext_dek.len(),
        32,
        "AES-256 DEK should be 32 bytes, got {}",
        plaintext_dek.len()
    );
    assert!(!wrapped_dek.is_empty(), "wrapped DEK must not be empty");

    let unwrapped = aws::unwrap_data_key(&wrapped_dek, Some("us-east-1"), &context)
        .await
        .expect("unwrap_data_key with matching context");
    assert_eq!(
        &*unwrapped, &*plaintext_dek,
        "round-trip DEK mismatch — KMS returned a different plaintext"
    );

    // --- Round-trip 2: wrong context must fail ---
    //
    // This is the contract that `kms_encryption_context_pins_format_v3` pins
    // at the type level. Here we verify KMS actually enforces it on the wire.

    let wrong_context = vec![("dotsec:format".to_string(), "v2".to_string())];
    let err = aws::unwrap_data_key(&wrapped_dek, Some("us-east-1"), &wrong_context)
        .await
        .expect_err("unwrap with mismatched context must fail");
    let msg = err.to_string();
    // KMS returns InvalidCiphertextException for a context mismatch, but our
    // `DataStoreError::KmsError(e.to_string())` collapses the AWS SDK error
    // down to "KMS error: service error" — losing the specificity. Asserting
    // on the message is brittle until error-sanitization lands; for now
    // require only that the call errored.
    assert!(
        !msg.is_empty(),
        "expected non-empty error on context mismatch"
    );

    // --- Round-trip 3: missing context must also fail ---

    let empty_context: aws::EncryptionContext = vec![];
    let err = aws::unwrap_data_key(&wrapped_dek, Some("us-east-1"), &empty_context)
        .await
        .expect_err("unwrap with no context must fail when wrap had one");
    assert!(
        !err.to_string().is_empty(),
        "expected non-empty error from KMS on missing context"
    );
}
