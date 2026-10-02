fn main() {
    let shared = "../../shared/client.json";
    println!("cargo:rerun-if-changed={shared}");
    let client: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(shared).expect("read shared client config"))
            .expect("parse shared client config");
    println!(
        "cargo:rustc-env=NUCLEAGENT_TRUSTED_DOMAIN={}",
        client["trustedDomain"].as_str().unwrap()
    );
    let config: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string("tauri.conf.json").expect("read Tauri config"),
    )
    .expect("parse Tauri config");
    assert_eq!(
        config["build"]["frontendDist"], "../../dist/shell",
        "local asset path drift"
    );
    assert_eq!(config["productName"], client["brandName"], "brand drift");
    assert_eq!(config["identifier"], client["appId"], "app ID drift");
    tauri_build::try_build(tauri_build::Attributes::new().app_manifest(
        tauri_build::AppManifest::new().commands(&[
            "runner_snapshot",
            "runner_install",
            "runner_control",
        ]),
    ))
    .expect("build Tauri ACL");
}
