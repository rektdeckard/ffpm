mod app;
mod decrypt;
mod profile;

use anyhow::{Context, Result, bail};
use clap::Parser;
use crossterm::{
    event::{self, Event, KeyEventKind},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::prelude::*;
use std::io;
use std::path::PathBuf;

#[derive(Parser)]
#[command(version, about)]
struct Args {
    /// Firefox profile name
    #[arg(short, long)]
    profile: Option<String>,

    /// Firefox profile directory (direct path)
    #[arg(short, long)]
    dir: Option<PathBuf>,
}

fn main() -> Result<()> {
    let args = Args::parse();

    // Resolve profile directory
    let (profile_dir, profile_name) = if let Some(dir) = args.dir {
        let name = dir
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "custom".into());
        (dir, name)
    } else {
        let ff_dir = profile::firefox_dir()?;
        let profiles = profile::list_profiles(&ff_dir)?;
        let prof = if let Some(ref name) = args.profile {
            profile::find_profile(&profiles, name)?
        } else {
            profile::default_profile(&profiles)
        };
        (prof.path.clone(), prof.name.clone())
    };

    if !profile_dir.is_dir() {
        bail!(
            "profile directory does not exist: {}",
            profile_dir.display()
        );
    }

    // Obtain master key (try empty password first, then prompt)
    let master_keys = match decrypt::get_master_keys(&profile_dir, b"") {
        Ok(key) => key,
        Err(first_err) => {
            eprintln!("Master password required.");
            let password = rpassword::prompt_password("Firefox master password: ")
                .context("failed to read password")?;
            decrypt::get_master_keys(&profile_dir, password.as_bytes()).with_context(|| {
                format!(
                    "failed to unlock key database.\n\
                         With empty password: {first_err:#}\n\
                         With provided password"
                )
            })?
        }
    };

    // Load and decrypt logins
    let logins = profile::load_logins(&profile_dir, &master_keys)?;

    if logins.is_empty() {
        println!("No saved logins found in profile {profile_name:?}.");
        return Ok(());
    }

    // Set up terminal
    let original_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), LeaveAlternateScreen);
        original_hook(info);
    }));

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = app::App::new(logins, profile_name);
    let result = run_loop(&mut terminal, &mut app);

    // Restore terminal
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;

    result
}

fn run_loop(terminal: &mut Terminal<impl Backend>, app: &mut app::App) -> Result<()> {
    loop {
        terminal.draw(|f| app.render(f))?;

        if let Event::Key(key) = event::read()? {
            if key.kind != KeyEventKind::Press {
                continue;
            }
            if app.handle_key(key)? {
                return Ok(());
            }
        }
    }
}
