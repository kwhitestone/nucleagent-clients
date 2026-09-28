#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use tauri::webview::NewWindowResponse;

fn is_trusted(url: &tauri::Url) -> bool {
    let domain = env!("NUCLEAGENT_TRUSTED_DOMAIN");
    url.scheme() == "https"
        && url.username().is_empty()
        && url.password().is_none()
        && url.port_or_known_default() == Some(443)
        && url
            .host_str()
            .is_some_and(|host| host == domain || host.ends_with(&format!(".{domain}")))
}

fn open_external(url: &tauri::Url) {
    if matches!(url.scheme(), "http" | "https" | "mailto" | "tel") {
        if let Err(error) = open::that_detached(url.as_str()) {
            eprintln!("Unable to open system browser: {error}");
        }
    }
}

fn main() {
    tauri::Builder::default()
        .setup(|app| {
            let handle = app.handle().clone();
            tauri::WebviewWindowBuilder::from_config(app, &app.config().app.windows[0])?
                .on_navigation(|url| {
                    if is_trusted(url) {
                        true
                    } else {
                        open_external(url);
                        false
                    }
                })
                .on_new_window(move |url, _features| {
                    if is_trusted(&url) {
                        use tauri::Manager;
                        if let Some(window) = handle.get_webview_window("main") {
                            let _ = window.navigate(url);
                        }
                    } else {
                        open_external(&url);
                    }
                    NewWindowResponse::Deny
                })
                .build()?;
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("failed to run NucleAgent");
}

#[cfg(test)]
mod tests {
    use super::is_trusted;

    #[test]
    fn allows_only_https_domain_and_real_subdomains() {
        for url in [
            "https://whitestone.top/",
            "https://nucleagent.whitestone.top/",
            "https://core.whitestone.top:443/",
        ] {
            assert!(is_trusted(&url.parse().unwrap()), "{url}");
        }
        for url in [
            "https://whitestone.top.evil.example/",
            "https://evilwhitestone.top/",
            "https://whitestone.top@evil.example/",
            "http://whitestone.top/",
            "https://whitestone.top:8443/",
            "https://user@whitestone.top/",
            "file:///etc/passwd",
            "javascript:alert(1)",
        ] {
            assert!(!is_trusted(&url.parse().unwrap()), "{url}");
        }
    }
}
