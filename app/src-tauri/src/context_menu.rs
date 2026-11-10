//! "Send with OpenDrop" in the file browser's right-click menu (issue #37).
//!
//! Choosing it runs this app's executable with `--send <paths>`. A second
//! copy hands those paths to the one already running (see the
//! single-instance plugin in `lib.rs`), whose window then asks which device
//! to send them to.
//!
//! - Windows: entries for files and folders under
//!   `HKCU\Software\Classes\{*,Directory}\shell\OpenDrop` (no admin needed).
//!   On Windows 11 they are under "Show more options".
//! - macOS: a Finder Quick Action, `~/Library/Services/Send with
//!   OpenDrop.workflow`, under Quick Actions (or Services) when you
//!   right-click.
//!
//! Nothing is added until the user turns it on in the app.

use std::io;
use std::path::{Path, PathBuf};

/// The menu entry's text.
pub const LABEL: &str = "Send with OpenDrop";

/// The paths after `--send` in a command line, if it has one.
pub fn send_args(argv: &[String]) -> Option<Vec<String>> {
    let at = argv.iter().position(|a| a == "--send")?;
    let paths: Vec<String> = argv[at + 1..]
        .iter()
        .filter(|p| !p.is_empty())
        .cloned()
        .collect();
    (!paths.is_empty()).then_some(paths)
}

/// The registry keys the Windows entries live under (relative to HKCU).
pub const WINDOWS_KEYS: [&str; 2] = [
    r"Software\Classes\*\shell\OpenDrop",
    r"Software\Classes\Directory\shell\OpenDrop",
];

/// The `reg.exe` commands that add the Windows entries for `exe`.
pub fn windows_add_commands(exe: &Path) -> Vec<Vec<String>> {
    let exe = exe.display().to_string();
    let mut commands = Vec::new();
    for key in WINDOWS_KEYS {
        let key = format!(r"HKCU\{key}");
        let set = |subkey: &str, name: Option<&str>, value: String| {
            let mut args = vec!["add".to_owned(), format!("{key}{subkey}")];
            match name {
                Some(name) => args.extend(["/v".to_owned(), name.to_owned()]),
                None => args.push("/ve".to_owned()),
            }
            args.extend(["/d".to_owned(), value, "/f".to_owned()]);
            args
        };
        commands.push(set("", None, LABEL.to_owned()));
        commands.push(set("", Some("Icon"), exe.clone()));
        commands.push(set(r"\command", None, format!("\"{exe}\" --send \"%1\"")));
    }
    commands
}

/// The Quick Action's folder.
pub fn mac_workflow_dir(home: &Path) -> PathBuf {
    home.join("Library/Services")
        .join(format!("{LABEL}.workflow"))
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// The shell script the Quick Action runs, with the selected files as its
/// arguments.
pub fn mac_script(exe: &Path) -> String {
    let exe = exe.display().to_string().replace('\'', r"'\''");
    format!("'{exe}' --send \"$@\" >/dev/null 2>&1 &")
}

/// The Quick Action's `Info.plist`: a Finder service taking files and
/// folders.
pub fn mac_info_plist() -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>NSServices</key>
	<array>
		<dict>
			<key>NSBackgroundColorName</key>
			<string>background</string>
			<key>NSIconName</key>
			<string>NSActionTemplate</string>
			<key>NSMenuItem</key>
			<dict>
				<key>default</key>
				<string>{LABEL}</string>
			</dict>
			<key>NSMessage</key>
			<string>runWorkflowAsService</string>
			<key>NSRequiredContext</key>
			<dict>
				<key>NSApplicationIdentifier</key>
				<string>com.apple.finder</string>
			</dict>
			<key>NSSendFileTypes</key>
			<array>
				<string>public.item</string>
			</array>
		</dict>
	</array>
</dict>
</plist>
"#
    )
}

/// The Quick Action's `document.wflow`: one "Run Shell Script" action that
/// gets the selection as arguments.
pub fn mac_document(exe: &Path) -> String {
    let script = xml_escape(&mac_script(exe));
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>AMApplicationBuild</key>
	<string>523</string>
	<key>AMApplicationVersion</key>
	<string>2.10</string>
	<key>AMDocumentVersion</key>
	<string>2</string>
	<key>actions</key>
	<array>
		<dict>
			<key>action</key>
			<dict>
				<key>AMAccepts</key>
				<dict>
					<key>Container</key>
					<string>List</string>
					<key>Optional</key>
					<true/>
					<key>Types</key>
					<array>
						<string>com.apple.cocoa.path</string>
					</array>
				</dict>
				<key>AMActionVersion</key>
				<string>2.0.3</string>
				<key>AMApplication</key>
				<array>
					<string>Automator</string>
				</array>
				<key>AMParameterProperties</key>
				<dict>
					<key>COMMAND_STRING</key>
					<dict/>
					<key>CheckedForUserDefaultShell</key>
					<dict/>
					<key>inputMethod</key>
					<dict/>
					<key>shell</key>
					<dict/>
					<key>source</key>
					<dict/>
				</dict>
				<key>AMProvides</key>
				<dict>
					<key>Container</key>
					<string>List</string>
					<key>Types</key>
					<array>
						<string>com.apple.cocoa.string</string>
					</array>
				</dict>
				<key>ActionBundlePath</key>
				<string>/System/Library/Automator/Run Shell Script.action</string>
				<key>ActionName</key>
				<string>Run Shell Script</string>
				<key>ActionParameters</key>
				<dict>
					<key>COMMAND_STRING</key>
					<string>{script}</string>
					<key>CheckedForUserDefaultShell</key>
					<true/>
					<key>inputMethod</key>
					<integer>1</integer>
					<key>shell</key>
					<string>/bin/bash</string>
					<key>source</key>
					<string></string>
				</dict>
				<key>BundleIdentifier</key>
				<string>com.apple.RunShellScript</string>
				<key>CFBundleVersion</key>
				<string>2.0.3</string>
				<key>CanShowSelectedItemsWhenRun</key>
				<false/>
				<key>CanShowWhenRun</key>
				<true/>
				<key>Category</key>
				<array>
					<string>AMCategoryUtilities</string>
				</array>
				<key>Class Name</key>
				<string>RunShellScriptAction</string>
				<key>InputUUID</key>
				<string>6B1F4E0A-3C55-4C8B-9C1E-0D6A9B1E7A01</string>
				<key>Keywords</key>
				<array>
					<string>Shell</string>
					<string>Script</string>
				</array>
				<key>OutputUUID</key>
				<string>6B1F4E0A-3C55-4C8B-9C1E-0D6A9B1E7A02</string>
				<key>UUID</key>
				<string>6B1F4E0A-3C55-4C8B-9C1E-0D6A9B1E7A03</string>
				<key>UnlocalizedApplications</key>
				<array>
					<string>Automator</string>
				</array>
				<key>arguments</key>
				<dict/>
				<key>isViewVisible</key>
				<integer>1</integer>
				<key>location</key>
				<string>309.000000:253.000000</string>
				<key>nibPath</key>
				<string>/System/Library/Automator/Run Shell Script.action/Contents/Resources/Base.lproj/main.nib</string>
			</dict>
			<key>isViewVisible</key>
			<integer>1</integer>
		</dict>
	</array>
	<key>connectors</key>
	<dict/>
	<key>workflowMetaData</key>
	<dict>
		<key>applicationBundleIDsByPath</key>
		<dict/>
		<key>applicationPaths</key>
		<array/>
		<key>inputTypeIdentifier</key>
		<string>com.apple.Automator.fileSystemObject</string>
		<key>outputTypeIdentifier</key>
		<string>com.apple.Automator.nothing</string>
		<key>presentationMode</key>
		<integer>15</integer>
		<key>processesInput</key>
		<false/>
		<key>serviceInputTypeIdentifier</key>
		<string>com.apple.Automator.fileSystemObject</string>
		<key>serviceOutputTypeIdentifier</key>
		<string>com.apple.Automator.nothing</string>
		<key>serviceProcessesInput</key>
		<false/>
		<key>systemImageName</key>
		<string>NSActionTemplate</string>
		<key>useAutomaticInputType</key>
		<false/>
		<key>workflowTypeIdentifier</key>
		<string>com.apple.Automator.servicesMenu</string>
	</dict>
</dict>
</plist>
"#
    )
}

fn home() -> io::Result<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| io::Error::other("no home folder"))
}

/// Whether the entry is in the menu (for this executable or another).
pub fn installed() -> bool {
    if cfg!(windows) {
        std::process::Command::new("reg")
            .args(["query", &format!(r"HKCU\{}", WINDOWS_KEYS[0])])
            .output()
            .is_ok_and(|o| o.status.success())
    } else if cfg!(target_os = "macos") {
        home().is_ok_and(|h| mac_workflow_dir(&h).exists())
    } else {
        false
    }
}

fn run(program: &str, args: &[String]) -> io::Result<()> {
    let output = std::process::Command::new(program).args(args).output()?;
    if output.status.success() {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "{program} {}: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        )))
    }
}

/// Add the entry, pointing at `exe` (this app's executable).
pub fn install(exe: &Path) -> io::Result<()> {
    if cfg!(windows) {
        for args in windows_add_commands(exe) {
            run("reg", &args)?;
        }
        Ok(())
    } else if cfg!(target_os = "macos") {
        let dir = mac_workflow_dir(&home()?);
        let contents = dir.join("Contents");
        std::fs::create_dir_all(&contents)?;
        std::fs::write(contents.join("Info.plist"), mac_info_plist())?;
        std::fs::write(contents.join("document.wflow"), mac_document(exe))?;
        // Tell the Services menu about it now rather than at next login.
        let _ = run("/System/Library/CoreServices/pbs", &["-update".to_owned()]);
        Ok(())
    } else {
        Err(io::Error::other(
            "the right-click menu entry is only available on macOS and Windows",
        ))
    }
}

/// Take the entry out of the menu.
pub fn uninstall() -> io::Result<()> {
    if cfg!(windows) {
        for key in WINDOWS_KEYS {
            let args = ["delete".to_owned(), format!(r"HKCU\{key}"), "/f".to_owned()];
            // Already gone is fine.
            let _ = run("reg", &args);
        }
        Ok(())
    } else if cfg!(target_os = "macos") {
        let dir = mac_workflow_dir(&home()?);
        match std::fs::remove_dir_all(&dir) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        let _ = run("/System/Library/CoreServices/pbs", &["-update".to_owned()]);
        Ok(())
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(args: &[&str]) -> Vec<String> {
        args.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn send_arguments_are_the_paths_after_the_flag() {
        assert_eq!(
            send_args(&argv(&["opendrop-app", "--send", "/a b/c.pdf", "/d"])),
            Some(argv(&["/a b/c.pdf", "/d"]))
        );
        assert_eq!(send_args(&argv(&["opendrop-app"])), None);
        assert_eq!(send_args(&argv(&["opendrop-app", "--send"])), None);
        assert_eq!(send_args(&argv(&["opendrop-app", "--send", ""])), None);
    }

    /// Explorer runs `"<exe>" --send "<file>"`, for files and for folders.
    #[test]
    fn windows_entries_run_the_app_with_the_file() {
        let exe = Path::new(r"C:\dev\OpenDrop\target\debug\opendrop-app.exe");
        let commands = windows_add_commands(exe);
        assert_eq!(commands.len(), 6);
        assert_eq!(
            commands[0],
            argv(&[
                "add",
                r"HKCU\Software\Classes\*\shell\OpenDrop",
                "/ve",
                "/d",
                "Send with OpenDrop",
                "/f"
            ])
        );
        assert_eq!(
            commands[2],
            argv(&[
                "add",
                r"HKCU\Software\Classes\*\shell\OpenDrop\command",
                "/ve",
                "/d",
                r#""C:\dev\OpenDrop\target\debug\opendrop-app.exe" --send "%1""#,
                "/f"
            ])
        );
        assert_eq!(
            commands[5][1],
            r"HKCU\Software\Classes\Directory\shell\OpenDrop\command"
        );
    }

    /// The Quick Action passes the selection to the app as arguments, with
    /// the path quoted for the shell and escaped for the plist.
    #[test]
    fn the_quick_action_runs_the_app_with_the_selection() {
        let exe = Path::new("/Users/aj/Open Drop & Co/opendrop-app");
        assert_eq!(
            mac_script(exe),
            "'/Users/aj/Open Drop & Co/opendrop-app' --send \"$@\" >/dev/null 2>&1 &"
        );
        let document = mac_document(exe);
        assert!(document.contains(
            "<string>'/Users/aj/Open Drop &amp; Co/opendrop-app' --send &quot;$@&quot; \
             &gt;/dev/null 2&gt;&amp;1 &amp;</string>"
        ));
        assert!(document.contains("<key>inputMethod</key>\n\t\t\t\t\t<integer>1</integer>"));
        assert!(mac_info_plist().contains("<string>Send with OpenDrop</string>"));
        assert_eq!(
            mac_workflow_dir(Path::new("/Users/aj")),
            Path::new("/Users/aj/Library/Services/Send with OpenDrop.workflow")
        );
    }
}
