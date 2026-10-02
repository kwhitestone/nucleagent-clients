use serde_json::{json, Value};
use std::{
    io::{BufRead, BufReader, Read},
    process::{ChildStdin, Command, Stdio},
    sync::{Arc, Mutex},
};
use tauri::{Manager, WebviewWindow};

#[derive(Default, Clone)]
pub struct RunnerState(Arc<Mutex<Progress>>);
#[derive(Default)]
struct Progress {
    busy: bool,
    last: Option<Value>,
    stdin: Option<ChildStdin>,
    stop_requested: bool,
    events: Vec<Value>,
    device: Option<Value>,
}

fn local_origin(url: &tauri::Url) -> bool {
    url.username().is_empty()
        && url.password().is_none()
        && ((url.scheme() == "tauri"
            && url.host_str() == Some("localhost")
            && url.port().is_none())
            || (url.scheme() == "http"
                && url.host_str() == Some("tauri.localhost")
                && url.port_or_known_default() == Some(80)))
}
fn local_caller(label: &str, url: &tauri::Url) -> bool {
    label == "local-runner" && local_origin(url)
}
fn authorize(window: &WebviewWindow) -> Result<(), String> {
    if !local_caller(
        window.label(),
        &window.url().map_err(|_| "Window origin unavailable")?,
    ) {
        return Err("Local runner access denied".into());
    }
    Ok(())
}
fn command(app: &tauri::AppHandle, action: &str, backend: Option<&str>) -> Result<Command, String> {
    let executable = std::env::current_exe().map_err(|_| "Application location unavailable")?;
    let directory = executable
        .parent()
        .ok_or("Application directory unavailable")?;
    let binary = directory.join(if cfg!(windows) {
        "nucleagent-runner.exe"
    } else {
        "nucleagent-runner"
    });
    let mut command = Command::new(binary);
    command
        .arg(action)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    if action != "doctor" {
        let root = app
            .path()
            .app_local_data_dir()
            .map_err(|_| "Application data directory unavailable")?
            .join("runner");
        command.arg("--data-dir").arg(root);
    }
    if let Some(backend) = backend {
        command.arg("--backend").arg(backend);
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x08000000); // CREATE_NO_WINDOW
    }
    Ok(command)
}
fn snapshot(app: tauri::AppHandle, state: RunnerState) -> Result<Value, String> {
    {
        let progress = state.0.lock().map_err(|_| "Runner state unavailable")?;
        if progress.busy {
            return Ok(
                json!({"busy":true,"progress":progress.last,"device":progress.device,"events":progress.events}),
            );
        }
    }
    let mut doctor = command(&app, "doctor", None)?
        .spawn()
        .map_err(|_| "Bundled runner unavailable")?;
    let mut data = Vec::new();
    doctor
        .stdout
        .take()
        .ok_or("Runner output unavailable")?
        .take(65537)
        .read_to_end(&mut data)
        .map_err(|_| "Runner output failed")?;
    let status = doctor.wait().map_err(|_| "Runner exited unexpectedly")?;
    if !status.success() || data.len() > 65536 {
        return Err("Runner diagnostic failed".into());
    }
    let identity: Value = serde_json::from_slice(&data).map_err(|_| "Invalid runner diagnostic")?;
    let mut backends = Vec::new();
    if identity["nativeUserReady"] == true {
        for backend in ["codex", "opencode"] {
            let mut child = command(&app, "status", Some(backend))?
                .spawn()
                .map_err(|_| "Runner status failed")?;
            let mut data = Vec::new();
            child
                .stdout
                .take()
                .ok_or("Runner output unavailable")?
                .take(65537)
                .read_to_end(&mut data)
                .map_err(|_| "Runner output failed")?;
            let _ = child.wait();
            if data.len() > 65536 {
                return Err("Runner status exceeds bound".into());
            }
            backends
                .push(serde_json::from_slice::<Value>(&data).map_err(|_| "Invalid runner status")?);
        }
    }
    let device = command(&app, "device-status", None)?
        .output()
        .ok()
        .and_then(|out| {
            if out.status.success() && out.stdout.len() <= 65536 {
                serde_json::from_slice::<Value>(&out.stdout).ok()
            } else {
                None
            }
        });
    let progress = state.0.lock().map_err(|_| "Runner state unavailable")?;
    Ok(
        json!({"busy":false,"doctor":identity,"backends":backends,"device":device,"progress":progress.last,"events":progress.events}),
    )
}

#[tauri::command]
pub async fn runner_snapshot(
    window: WebviewWindow,
    app: tauri::AppHandle,
    state: tauri::State<'_, RunnerState>,
) -> Result<Value, String> {
    authorize(&window)?;
    let state = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || snapshot(app, state))
        .await
        .map_err(|_| "Runner diagnostic worker failed")?
}

#[tauri::command]
pub async fn runner_install(
    window: WebviewWindow,
    app: tauri::AppHandle,
    state: tauri::State<'_, RunnerState>,
    backend: String,
) -> Result<Value, String> {
    authorize(&window)?;
    if backend != "codex" && backend != "opencode" {
        return Err("Unsupported backend".into());
    }
    let state = state.inner().clone();
    {
        let mut progress = state.0.lock().map_err(|_| "Runner state unavailable")?;
        if progress.busy {
            return Err("An installation is already running".into());
        }
        progress.busy = true;
        progress.last = Some(json!({"state":"starting","backend":backend}));
    }
    tauri::async_runtime::spawn_blocking(move || {
        let result = (|| {
            let mut child = command(&app, "install", Some(&backend))?
                .arg("--parent-stdin")
                .spawn()
                .map_err(|_| "Bundled runner unavailable")?;
            let stdout = child.stdout.take().ok_or("Runner output unavailable")?;
            let mut reader = BufReader::new(stdout);
            loop {
                let mut line = Vec::new();
                let count = reader
                    .by_ref()
                    .take(65537)
                    .read_until(b'\n', &mut line)
                    .map_err(|_| "Runner progress failed")?;
                if count == 0 {
                    break;
                }
                if count > 65536 {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err("Runner progress exceeds bound".into());
                }
                let value: Value =
                    serde_json::from_slice(&line).map_err(|_| "Invalid runner progress")?;
                state.0.lock().map_err(|_| "Runner state unavailable")?.last = Some(value);
            }
            // Keep stdin owned until exit. Shell death closes the pipe and
            // causes the runner to cancel downloads and reclaim probe workers.
            let status = child.wait().map_err(|_| "Runner exit unavailable")?;
            if !status.success() {
                return Err("Installation did not complete; see diagnostic state".into());
            }
            Ok(json!({"installed":true,"backend":backend,"admission":"unavailable"}))
        })();
        if let Ok(mut progress) = state.0.lock() {
            progress.busy = false;
        }
        result
    })
    .await
    .map_err(|_| "Runner installer worker failed")?
}

#[tauri::command]
pub async fn runner_control(
    window: WebviewWindow,
    app: tauri::AppHandle,
    state: tauri::State<'_, RunnerState>,
    action: String,
    core_origin: Option<String>,
    consent: bool,
) -> Result<Value, String> {
    authorize(&window)?;
    if action == "stop" {
        let mut progress = state.0.lock().map_err(|_| "Runner state unavailable")?;
        progress.stop_requested = true;
        progress.stdin.take(); // EOF requests cancellation and waits for worker cleanup.
        return Ok(json!({"state":"stopping"}));
    }
    if !["bind", "run", "renew", "revoke"].contains(&action.as_str()) || !consent {
        return Err("Explicit native-access consent required".into());
    }
    let mut cmd = command(&app, &action, Some("codex"))?;
    cmd.arg("--parent-stdin");
    if action == "run" {
        cmd.args(["--enable", "--consent-native-access"]);
    }
    if action == "bind" {
        let origin = core_origin.ok_or("Core HTTPS origin required")?;
        let url = tauri::Url::parse(&origin).map_err(|_| "Invalid Core origin")?;
        if url.scheme() != "https"
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.path() != "/"
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err("Core must be an HTTPS origin without a path or credentials".into());
        }
        cmd.arg("--core-origin")
            .arg(url.origin().ascii_serialization());
    }
    let state = state.inner().clone();
    {
        let mut progress = state.0.lock().map_err(|_| "Runner state unavailable")?;
        if progress.busy {
            return Err("Runner is already active".into());
        }
        progress.busy = true;
        progress.stop_requested = false;
        progress.last = Some(json!({"state":"starting","action":action}));
    }
    tauri::async_runtime::spawn_blocking(move || {
        let result = (|| {
            let mut child = cmd.spawn().map_err(|_| "Bundled runner unavailable")?;
            state
                .0
                .lock()
                .map_err(|_| "Runner state unavailable")?
                .stdin = child.stdin.take();
            let stdout = child.stdout.take().ok_or("Runner output unavailable")?;
            let mut reader = BufReader::new(stdout);
            loop {
                let mut line = Vec::new();
                let count = reader
                    .by_ref()
                    .take(65537)
                    .read_until(b'\n', &mut line)
                    .map_err(|_| "Runner output failed")?;
                if count == 0 {
                    break;
                }
                let parsed = if count <= 65536 {
                    serde_json::from_slice::<Value>(&line).ok()
                } else {
                    None
                };
                let Some(value) = parsed else {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err("Invalid runner output".to_string());
                };
                let mut progress = state.0.lock().map_err(|_| "Runner state unavailable")?;
                if value["conversationId"].is_number() {
                    progress.events.push(value.clone());
                    if progress.events.len() > 50 {
                        progress.events.remove(0);
                    }
                }
                if value["state"] == "bound" {
                    progress.device = Some(value.clone());
                }
                if value["state"] == "revoked" {
                    progress.device = None;
                }
                progress.last = Some(value);
            }
            let status = child.wait().map_err(|_| "Runner exit unavailable")?;
            if !status.success() {
                return Err("Runner stopped; see the reported state".into());
            }
            Ok(json!({"state":"stopped"}))
        })();
        if let Ok(mut progress) = state.0.lock() {
            progress.busy = false;
            progress.stdin.take();
        }
        result
    })
    .await
    .map_err(|_| "Runner control worker failed")?
}

pub fn open(app: &tauri::AppHandle) -> Result<(), tauri::Error> {
    if let Some(window) = app.get_webview_window("local-runner") {
        window.show()?;
        return window.set_focus();
    }
    let handle = app.clone();
    tauri::WebviewWindowBuilder::new(
        app,
        "local-runner",
        tauri::WebviewUrl::App("runner/index.html".into()),
    )
    .title("本机执行 · NucleAgent")
    .inner_size(820.0, 760.0)
    .min_inner_size(640.0, 600.0)
    .on_navigation(local_origin)
    .on_new_window(move |url, _| {
        if url.scheme() == "https" && crate::is_trusted(&url) {
            if let Some(window) = handle.get_webview_window("main") {
                let _ = window.navigate(url);
                let _ = window.set_focus();
            }
        }
        tauri::webview::NewWindowResponse::Deny
    })
    .build()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{local_caller, local_origin};
    #[test]
    fn main_window_has_no_local_runner_authority() {
        let url = "http://tauri.localhost/runner/index.html".parse().unwrap();
        assert!(!local_caller("main", &url));
        assert!(local_caller("local-runner", &url));
        assert!(!local_caller(
            "local-runner",
            &"https://core.example/".parse().unwrap()
        ));
    }
    #[test]
    fn only_packaged_origins_can_reach_runner() {
        for value in [
            "tauri://localhost/runner/index.html",
            "http://tauri.localhost/runner/index.html",
        ] {
            assert!(local_origin(&value.parse().unwrap()));
        }
        for value in [
            "https://hub.example/",
            "http://tauri.localhost.evil/",
            "http://tauri.localhost:8080/",
            "http://user@tauri.localhost/",
            "file:///tmp/runner.html",
        ] {
            assert!(!local_origin(&value.parse().unwrap()));
        }
    }
}
