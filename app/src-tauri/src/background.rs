//! Running in the background (issue #36): closing the window hides it and
//! OpenDrop keeps running in the system tray (Windows, Linux) or menu bar
//! (macOS), still discoverable and still receiving. When something needs an
//! answer while the window is hidden (a file or folder offered, a fetch
//! request, a pairing code), a native notification appears and the window
//! comes back with the question on screen.

use crate::node::AppEvent;
use tauri::menu::{Menu, MenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Manager, Runtime, WindowEvent};
use tauri_plugin_notification::NotificationExt;

/// The main window's label (tauri.conf.json's first window).
pub const MAIN: &str = "main";

/// What to tell the user about an event that needs an answer, as a
/// notification's title and body; `None` for the rest.
pub fn notice(event: &AppEvent) -> Option<(String, String)> {
    match event {
        AppEvent::IncomingRequest {
            peer_name,
            name,
            fetch,
            files,
            text,
            ..
        } => Some(match (fetch, files) {
            // The text itself stays out of the notification (it may be a
            // password); the window shows it.
            _ if text.is_some() => (
                format!("{peer_name} wants to send you text"),
                "Open OpenDrop to see it and accept or decline.".to_owned(),
            ),
            (Some(_), _) => (
                format!("{peer_name} asks for a file"),
                format!("{name}: open OpenDrop to answer."),
            ),
            (None, Some(_)) => (
                format!("{peer_name} wants to send you a folder"),
                format!("{name}: open OpenDrop to accept or decline."),
            ),
            (None, None) => (
                format!("{peer_name} wants to send you a file"),
                format!("{name}: open OpenDrop to accept or decline."),
            ),
        }),
        AppEvent::PairCode {
            device_name,
            code,
            incoming: true,
            ..
        } => Some((
            format!("{device_name} wants to pair"),
            format!("Code {code}: open OpenDrop to compare."),
        )),
        _ => None,
    }
}

/// Bring the main window back and in front.
pub fn show_window<R: Runtime>(app: &AppHandle<R>) {
    if let Some(window) = app.get_webview_window(MAIN) {
        let _ = window.unminimize();
        let _ = window.show();
        let _ = window.set_focus();
    }
}

fn window_hidden<R: Runtime>(app: &AppHandle<R>) -> bool {
    app.get_webview_window(MAIN)
        .is_none_or(|w| !w.is_visible().unwrap_or(true) || w.is_minimized().unwrap_or(false))
}

/// Called for every event before it goes to the window: if it needs an
/// answer and the window is hidden, notify and show the window.
pub fn on_event<R: Runtime>(app: &AppHandle<R>, event: &AppEvent) {
    let Some((title, body)) = notice(event) else {
        return;
    };
    if !window_hidden(app) {
        return;
    }
    let _ = app.notification().builder().title(title).body(body).show();
    show_window(app);
}

/// Add the tray / menu bar icon, and make closing the window hide it.
pub fn setup<R: Runtime>(app: &tauri::App<R>) -> tauri::Result<()> {
    let open = MenuItem::with_id(app, "open", "Open OpenDrop", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", "Quit OpenDrop", true, None::<&str>)?;
    let menu = Menu::with_items(app, &[&open, &quit])?;
    let mut tray = TrayIconBuilder::with_id("opendrop")
        .tooltip("OpenDrop")
        .menu(&menu)
        .show_menu_on_left_click(cfg!(target_os = "macos"))
        .on_menu_event(|app, event| match event.id.as_ref() {
            "open" => show_window(app),
            "quit" => app.exit(0),
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            // Windows and Linux: a left click opens the window; the menu
            // is on the right button.
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = event
            {
                show_window(tray.app_handle());
            }
        });
    if let Some(icon) = app.default_window_icon() {
        tray = tray.icon(icon.clone());
    }
    tray.build(app)?;

    if let Some(window) = app.get_webview_window(MAIN) {
        let hide = window.clone();
        window.on_window_event(move |event| {
            if let WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                let _ = hide.hide();
            }
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::FetchDetails;

    fn offer(fetch: Option<FetchDetails>, files: Option<u64>) -> AppEvent {
        AppEvent::IncomingRequest {
            transfer_id: "t".into(),
            peer_name: "Windows".into(),
            peer_ip: "192.168.1.177".into(),
            verified: true,
            name: "report.pdf".into(),
            size: 10,
            fetch,
            files,
            text: None,
        }
    }

    /// Offers, fetch requests and incoming pairing codes need an answer, so
    /// they notify; everything else (progress, results, our own pairing
    /// attempts) doesn't.
    #[test]
    fn only_questions_notify() {
        assert_eq!(
            notice(&offer(None, None)),
            Some((
                "Windows wants to send you a file".into(),
                "report.pdf: open OpenDrop to accept or decline.".into()
            ))
        );
        assert_eq!(
            notice(&offer(None, Some(3))).unwrap().0,
            "Windows wants to send you a folder"
        );
        let fetch = FetchDetails {
            reason: String::new(),
            via_assistant: false,
            grant_folder: None,
        };
        assert_eq!(
            notice(&offer(Some(fetch), None)).unwrap().0,
            "Windows asks for a file"
        );
        let code = |incoming| AppEvent::PairCode {
            pair_id: "p".into(),
            device_id: "d".into(),
            device_name: "Windows".into(),
            code: "123456".into(),
            incoming,
        };
        assert_eq!(
            notice(&code(true)),
            Some((
                "Windows wants to pair".into(),
                "Code 123456: open OpenDrop to compare.".into()
            ))
        );
        assert_eq!(notice(&code(false)), None);
        let text = AppEvent::IncomingRequest {
            transfer_id: "t".into(),
            peer_name: "Windows".into(),
            peer_ip: "192.168.1.177".into(),
            verified: true,
            name: "Clipboard text".into(),
            size: 6,
            fetch: None,
            files: None,
            text: Some("secret".into()),
        };
        let (title, body) = notice(&text).unwrap();
        assert_eq!(title, "Windows wants to send you text");
        assert!(!body.contains("secret"));
        assert_eq!(
            notice(&AppEvent::SendDone {
                transfer_id: "t".into(),
                sha256: "x".into()
            }),
            None
        );
    }
}
