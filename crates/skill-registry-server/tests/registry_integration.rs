use std::{collections::BTreeMap, path::Path, sync::Arc};

use ed25519_dalek::SigningKey;
use reqwest::{multipart::Form, multipart::Part, StatusCode};
use safeagent_skill_registry::{pack_skill, sign_skill, VerifiedPublicKey, VerifiedPublishers};
use safeagent_skill_registry_server::{app_router, RegistryIndex, RegistryState};
use tempfile::TempDir;
use tokio::net::TcpListener;
use tokio::sync::Mutex;

#[tokio::test]
async fn registry_publish_and_reject_flows() {
    let temp = TempDir::new().expect("temp");
    let storage = temp.path().join("registry_store");
    std::fs::create_dir_all(&storage).expect("create storage dir");

    let verified_path = temp.path().join("verified.json");
    let trusted_signing = SigningKey::from_bytes(&[42u8; 32]);
    let trusted_verifying = trusted_signing.verifying_key();
    write_verified_store(
        &verified_path,
        "sample-publisher",
        "sample-key",
        &hex::encode(trusted_verifying.to_bytes()),
    );

    let valid_pkg = build_signed_pkg(
        &temp.path().join("valid"),
        "sample-publisher",
        "sample-key",
        &[42u8; 32],
    );

    let state = RegistryState {
        storage_root: storage.clone(),
        catalog_path: storage.join("catalog.json"),
        verified_publishers_path: verified_path,
        index: Arc::new(Mutex::new(RegistryIndex::default())),
    };

    let app = app_router(state);
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let bind = listener.local_addr().expect("local addr");
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("server");
    });
    let base = format!("http://{bind}");

    let client = reqwest::Client::new();
    let publish_ok = publish_package(&client, &base, &valid_pkg, "stable").await;
    assert_eq!(publish_ok, StatusCode::OK);

    let list = client
        .get(format!("{}/skills", &base))
        .send()
        .await
        .expect("list request")
        .json::<Vec<String>>()
        .await
        .expect("skills list");
    assert!(list.contains(&"sample.safeagent.echo".to_string()));

    let versions = client
        .get(format!(
            "{}/skills/{}/versions",
            &base, "sample.safeagent.echo"
        ))
        .send()
        .await
        .expect("versions request")
        .json::<Vec<serde_json::Value>>()
        .await
        .expect("versions list");
    assert!(!versions.is_empty());

    let pulled = client
        .get(format!(
            "{}/skills/{}/{}/download",
            &base, "sample.safeagent.echo", "0.1.0"
        ))
        .send()
        .await
        .expect("download request");
    assert_eq!(pulled.status(), StatusCode::OK);

    let tampered_dir = temp.path().join("tampered");
    let tampered_pkg =
        build_signed_pkg(&tampered_dir, "sample-publisher", "sample-key", &[42u8; 32]);
    std::fs::write(
        tampered_pkg.join("skill.toml"),
        "id = \"sample.safeagent.tampered\"\n",
    )
    .expect("tamper");
    assert_ne!(
        publish_package(&client, &base, &tampered_pkg, "stable").await,
        StatusCode::OK
    );

    let unverified_pkg = build_signed_pkg(
        &temp.path().join("unverified"),
        "untrusted-publisher",
        "bad-key",
        &[13u8; 32],
    );
    assert_ne!(
        publish_package(&client, &base, &unverified_pkg, "stable").await,
        StatusCode::OK
    );
}

async fn publish_package(
    client: &reqwest::Client,
    base: &str,
    package_dir: &Path,
    channel: &str,
) -> StatusCode {
    let form = Form::new()
        .part("manifest", file_part(package_dir.join("skill.toml")))
        .part("payload", file_part(package_dir.join("payload.tar.gz")))
        .part("signature", file_part(package_dir.join("signature.sig")))
        .part("checksums", file_part(package_dir.join("checksums.json")))
        .text("channel", channel.to_string());

    client
        .post(format!("{}/publish", base))
        .multipart(form)
        .send()
        .await
        .expect("publish request")
        .status()
}

fn file_part(path: impl AsRef<Path>) -> Part {
    let path = path.as_ref();
    let bytes = std::fs::read(path).expect("read multipart file");
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("file");
    Part::bytes(bytes).file_name(file_name.to_string())
}

fn build_signed_pkg(
    root: &Path,
    publisher_id: &str,
    key_id: &str,
    seed: &[u8; 32],
) -> std::path::PathBuf {
    let src = root.join("src");
    let pkg = root.join("pkg");
    std::fs::create_dir_all(&src).expect("src dir");
    std::fs::create_dir_all(&pkg).expect("pkg dir");
    std::fs::write(src.join("entry.sh"), "#!/bin/sh\necho ok\n").expect("entry");
    let manifest = format!(
        "id = \"sample.safeagent.echo\"\nname = \"sample\"\nversion = \"0.1.0\"\nentrypoint = \"entry.sh\"\ndescription = \"test\"\nrequired_scopes = [\"skill:echo\"]\npublisher_id = \"{publisher_id}\"\nsigning_key_id = \"{key_id}\"\nfiles = [\"entry.sh\"]\n"
    );
    std::fs::write(src.join("skill.toml"), manifest).expect("manifest");

    pack_skill(&src, &pkg).expect("pack");

    let signing = SigningKey::from_bytes(seed);
    let key_path = root.join("signing.key");
    std::fs::write(&key_path, hex::encode(signing.to_bytes())).expect("signing key");
    sign_skill(&pkg, &key_path).expect("sign");
    pkg
}

fn write_verified_store(path: &Path, publisher_id: &str, key_id: &str, public_key: &str) {
    let store = VerifiedPublishers {
        publishers: BTreeMap::from([(
            publisher_id.to_string(),
            vec![VerifiedPublicKey {
                key_id: key_id.to_string(),
                public_key: public_key.to_string(),
            }],
        )]),
    };
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("verified parent");
    }
    std::fs::write(
        path,
        serde_json::to_vec_pretty(&store).expect("serialize store"),
    )
    .expect("store write");
}
