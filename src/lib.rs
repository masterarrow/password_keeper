use comfy_table::{Attribute, Cell, Color, Table, presets::UTF8_FULL_CONDENSED};
use dialoguer::{Select, theme::ColorfulTheme};
use std::{io::{self, Write}, sync::Arc};
use std::time::Duration;
use secrecy::{ExposeSecret, SecretBox, SecretString};
use console::{Key, Term};
use arboard::Clipboard;

mod database;
mod encoder;
mod config;

use config::Config;
use database::{DB, Record};
use encoder::{encrypt_row_password, decrypt_row_password, verify_master_password, hash_master_password};

pub use encoder::EResult;

pub async fn init() -> EResult<()> {
    println!("\nWelcome to Password keeper.\n");

    // Initialize the configuration and database
    let db = database::DB::new().await;

    let prompt = if db.is_first_run().await? {
        "\n[!] Please set a master password:"
    } else {
        "\n[!] Please enter a master password:"
    };

    // Get master password for the record
    let master_password = request_password(prompt).await?;

    let config = Config::new(db, master_password);

    // Check if the master password is correct
    if let Some(password) = config.db.get_master_password().await? {
        if !verify_master_password(&config.master_password, &password)? {
            println!("\n[!] Invalid master password.\n");
            println!("\n[!] Goodbye.\n");

            return Ok(());
        }
    } else {
        // Set the master password for the first time
        let password = hash_master_password(&config.master_password)?;
        config.db.update_master_password(&password).await?;
    }

    clear_screen()?;
    all_records(config, 0).await
}

/**
 * Show all records
 *
 * Args:
 *
 *     config (Config): Application configuration
 *     offset (int): Offset
 *
 * Returns:
 *
 *     EResult<()>:
 */
async fn all_records(config: Config, mut offset: i64) -> EResult<()> {
    let default_limit = 15;
    let mut limit = default_limit;
    let mut search = None;
    let config = Arc::new(config);

    loop {
        let config = config.clone();
        let records = config.db.all(limit, offset, &search).await?;
        let record_count = config.db.count_records().await?;

        if records.is_empty() {
            println!("\n\n[!] No records found.");

            if offset > 0 {
                offset -= limit;
            }

            let mut actions = vec!["Add a new item"];

            if search.is_some() || offset > 0 || limit != default_limit {
                actions.push("Clear search and pagination");
            }

            actions.push("Quit");
            let selection = option_selection(&actions);

            // Add a new item
            if selection == 0 {
                add_record(config).await?;
                continue;
            }

            // Clear search and pagination
            if selection == 1 && actions.contains(&"Clear search and pagination") {
                search = None;
                offset = 0;
                limit = default_limit;
                continue;
            }

            // Exit
            if selection == actions.len() - 1 {
                println!("\n[!] Goodbye.\n");
                return Ok(());
            }

            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            clear_screen()?;
            continue;
        }

        // Display the available records
        println!("\n\n[-] Available records.");

        let term = Term::stdout();
        term.write_line("\n[V]iew | [A]dd | [E]dit | [D]elete | [S]earch | [Q]uit")?;

        print_records(&records, None);

        term.write_line("\n[M]ore | [N]ext page | [P]revious page | [C]lear search and pagination")?;

        let to = record_count.min(offset + limit);
        println!("\n[*] Showing records {} to {} of {}.", offset + 1, to, record_count);

        println!();

        loop {
            match term.read_char()? {
                'v' | 'V' => {
                    // View a record
                    view_record_details(&config.clone(), false).await?;
                    break;
                }

                'a' | 'A' => {
                    add_record(config).await?;
                    break;
                }

                'e' | 'E' => {
                    // Edit a record
                    edit_record(&config.clone()).await?;
                    break;
                }

                'd' | 'D' => {
                    // Delete a record
                    delete_record(&config.clone()).await?;
                    break;
                }

                's' | 'S' => {
                    // Search for a record
                    search = Some(request_required_input("string to search"));
                    offset = 0;
                    limit = default_limit;
                    break;
                }

                'm' | 'M' => {
                    // More records
                    limit += default_limit;
                    break;
                }

                'n' | 'N' => {
                    // Next page
                    if offset + limit < record_count {
                        offset += limit;
                    }
                    break;
                }

                'p' | 'P' => {
                    // Previous page
                    if offset > 0 {
                        offset -= limit;
                    }
                    break;
                }

                'c' | 'C' => {
                    // Clear search and pagination
                    offset = 0;
                    limit = default_limit;
                    search = None;
                    break;
                }

                'q' | 'Q' => {
                    // Exit
                    println!("\n[!] Goodbye.\n");
                    return Ok(());
                },

                _ => {}
            }
        }

        clear_screen()?;
        continue;
    }
}

/**
 * Add a new record
 *
 * Returns:
 *
 *     EResult<()>:
 */
async fn add_record(config: Arc<Config>) -> EResult<()> {
    let mut record = Record::new();

    record.title = request_required_input("title");
    record.description = request_required_input("description");
    record.username = request_required_input("username");

    let row_password = request_password("\n[+] Enter password:").await?;

    println!();

    // Encrypt password
    if let Ok(password) = encrypt_row_password(&row_password, &config.master_password).await {
        record.password = password;
    } else {
        println!("\n[X] Could not encrypt data!");
        return Ok(());
    }

    match config.db.create(&record).await {
        Ok(_) => {
            println!("\n[+] Record added.");
        }
        Err(e) => {
            println!("\n[!] Error adding a new record: {}", e);
        }
    }

    tokio::time::sleep(Duration::from_secs(1)).await;

    Ok(())
}

/**
 * View a record
 *
 * Args:
 *
 *     config (Arc<Config>)
 *     password_visible (bool): Whether the password should be visible or masked
 *
 * Returns:
 *
 *     EResult<()>:
 */
async fn view_record_details(config: &Arc<Config>, mut password_visible: bool) -> EResult<()> {
    let Some(record) = request_record_id(config, "Record details").await else {
        return Ok(());
    };

    let password = decrypt_row_password(&record.password, &config.master_password).await?;
    let term = Term::stdout();

    loop {
        clear_screen()?;
        println!("\n\n[-] Record details.");

        print_records(
            std::slice::from_ref(&record),
            if password_visible { Some(password.clone()) } else { None }
        );

        println!("\n[*] Press 'c' to copy password, 'u' for username, 's' to toggle visibility, or Enter to return.");

        loop {
            match term.read_key() {
                Ok(Key::Enter) =>  return Ok(()),

                Ok(Key::Char('u') | Key::Char('U')) => {
                    // Copy username to clipboard
                    let uname = SecretBox::from(record.username.clone());
                    copy_to_clipboard(uname.clone(), &term, "Username")?;
                    continue;
                }

                Ok(Key::Char('c') | Key::Char('C')) => {
                    // Copy password to clipboard
                    copy_to_clipboard(password.clone(), &term, "Password")?;
                    // Remove password from clipboard after 60 seconds
                    clear_clipboard(password.clone());
                    continue;
                }

                Ok(Key::Char('s') | Key::Char('S')) => {
                    // Toggle visibility logic here
                    password_visible = !password_visible;
                    break;
                }

                Ok(_) => continue,
                Err(_) => return Ok(()),
            }
        }
    }
}

/**
 * Request record ID
 *
 * Args:
 *
 *     config (Arc<Config>)
 *     prompt (str): Prompt message to display when requesting the record ID
 *
 * Returns:
 *
 *     Option<Record>: Selected record
 */
async fn request_record_id(config: &Arc<Config>, prompt: &str) -> Option<Record> {
    println!("\n[-] {}.", prompt);
    println!("\n[*] If you want to cancel, just leave it blank.");

    let input = get_input("\nEnter a record ID:").unwrap_or_default().trim().to_string();

    if input.is_empty() {
        println!("\n[!] Operation cancelled.");
        tokio::time::sleep(Duration::from_secs(1)).await;
        return None;
    }

    let target_id = match input.parse::<i64>() {
        Ok(id) => id,
        Err(_) => {
            println!("\n[!] Record not found.");
            tokio::time::sleep(Duration::from_secs(1)).await;
            return None;
        }
    };

    let Ok(Some(record)) = config.db.get_by_id(target_id).await else {
        println!("\n[!] Record not found.");
        tokio::time::sleep(Duration::from_secs(1)).await;
        return None;
    };

    Some(record.clone())
}

/**
 * Edit a record
 *
 * Args:
 *
 *     config (Arc<Config>)
 *
 * Returns:
 *
 *     EResult<()>
 */
async fn edit_record(config: &Arc<Config>) -> EResult<()> {
    let Some(mut record) = request_record_id(config, "Editing a record").await else {
        return Ok(());
    };

    clear_screen()?;

    println!("\n\n[-] Editing a record.");

    print_records(std::slice::from_ref(&record), None);

    print!("\n[*] You can leave any value empty to leave it unchanged.\n");

    let title = get_input("\n[+] Enter title:")?;
    if !title.trim().is_empty() {
        record.title = title;
    }

    let description = get_input("\n[+] Enter description:")?;
    if !description.trim().is_empty() {
        record.description = description;
    }

    let username = get_input("\n[+] Enter username:")?;
    if !username.trim().is_empty() {
        record.username = username;
    }

    println!("\n[+] Enter password:");
    let pass = rpassword::prompt_password("\n> ").unwrap_or_default();
    let new_password = SecretBox::from(pass.trim().to_string());

    // User did not enter a new password
    if !new_password.expose_secret().trim().is_empty() {
        // Encrypt password
        if let Ok(encrypted_password) = encrypt_row_password(&new_password, &config.master_password).await {
            record.password = encrypted_password;
        } else {
            println!("\n[X] Could not encrypt data! Using an old password.");
            return Ok(());
        }
    }

    match config.db.update(&record).await? {
        true => {
            println!("\n[+] Record updated.");
        }
        false => {
            println!("\n[!] Could not update record.");
        }
    }

    tokio::time::sleep(Duration::from_secs(1)).await;

    Ok(())
}

/**
 * Delete a record
 *
 * Args:
 *
 *     config (Arc<Config>)
 *
 * Returns:
 *
 *     EResult<()>:
 */
async fn delete_record(config: &Arc<Config>) -> EResult<()> {
    let Some(record) = request_record_id(config, "Deleting a record").await else {
        return Ok(());
    };

    match config.db.remove(record.id).await? {
        true => {
            println!("\n[+] Record deleted.");
        }
        false => {
            println!("\n[!] Could not delete record.");
        }
    }

    tokio::time::sleep(std::time::Duration::from_secs(1)).await;

    Ok(())
}

/**
 * Print records
 *
 * Args:
 *
 *     records (Vec<Record>): Records
 *     password (Option<SecretBox<str>>): Master password for decrypting record passwords
 */
fn print_records(records: &[Record], password: Option<SecretBox<str>>) {
    let mut table = Table::new();
    table.load_style(UTF8_FULL_CONDENSED);

    table.set_header(vec![
        Cell::new("ID").add_attribute(Attribute::Bold).fg(Color::DarkCyan),
        Cell::new("Title").add_attribute(Attribute::Bold).fg(Color::DarkCyan),
        Cell::new("Description").add_attribute(Attribute::Bold).fg(Color::DarkCyan),
        Cell::new("Username").add_attribute(Attribute::Bold).fg(Color::DarkCyan),
        Cell::new("Password").add_attribute(Attribute::Bold).fg(Color::DarkCyan),
    ]);

    for record in records {
        let mut pass = "••••••••".to_string();

        if let Some(password) = &password {
            pass = password.expose_secret().to_string();
        }

        table.add_row(vec![
            Cell::new(record.id.to_string()),
            Cell::new(record.title.clone()),
            Cell::new(record.description.clone()),
            Cell::new(record.username.clone()),
            Cell::new(pass),
        ]);
    }

    println!("\n{table}");
}

/**
 * Request master password
 *
 * Returns:
 *
 *     EResult<SecretBox<str>>: Master password
 */
async fn request_password(prompt: &str) -> EResult<SecretBox<str>> {
    println!("{}", prompt);

    loop {
        let raw_password = rpassword::prompt_password("\n> ").unwrap_or_default();
        if !raw_password.trim().is_empty() {
            return Ok(SecretString::from(raw_password.trim()));
        }
        println!("\n[X] Password cannot be empty.");
    }
}

/**
 * Request required input from the user
 *
 * Args:
 *
 *     param (str): The name of the parameter being requested
 *
 * Returns:
 *
 *     String: The user input
 */
fn request_required_input(param: &str) -> String {
    loop {
        let input = get_input(&format!("\n[+] Enter {}:\n", param)).unwrap_or_default();
        if !input.trim().is_empty() {
            return input;
        }
        println!("\n[X] {} cannot be empty.", param);
    }
}

/**
 * Option selection
 *
 * Args:
 *
 *     options (Vec<&str>): List of options
 *
 * Returns:
 *
 *     int: Selected option
 */
fn option_selection(options: &[&str]) -> usize {
    match Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Please choose an action")
        .items(options)
        .default(0)
        .interact()
    {
        Ok(index) => index,
        Err(_) => 0,
    }
}

/**
 * Get user input
 *
 * Args:
 *
 *     prompt (str): Prompt to show to the user
 *
 * Returns:
 *
 *     EResult<String>: User input
 */
fn get_input(prompt: &str) -> EResult<String> {
    println!("{}", prompt);
    print!("\n> ");
    io::stdout().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;

    Ok(input.trim().to_string())
}

/**
 * Copy password to clipboard
 *
 * Args:
 *
 *     text (SecretBox<str>): Text to copy to clipboard
 *     term (Term): Terminal
 *     field (str): Name of the field being copied
 *
 * Returns:
 *
 *     EResult<()>:
 */
fn copy_to_clipboard(text: SecretBox<str>, term: &Term, field: &str) -> EResult<()> {
    if let Ok(mut clipboard) = Clipboard::new() {
        let _ = clipboard.set_text(text.expose_secret());

        term.write_line(format!("\n[!] {}, copied to clipboard!", field).as_str())?;
    }

    Ok(())
}

/**
 * Clear clipboard if the password has not been replaced by the user within 60 seconds
 *
 * Args:
 *
 *     text (SecretBox<str>): Text to clear from clipboard
 */
fn clear_clipboard(text: SecretBox<str>) {
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(60)).await;

        tokio::task::spawn_blocking(move || {
            if let Ok(mut clipboard) = Clipboard::new() {
                // Check clipboard contents
                if let Ok(cp_text) = clipboard.get_text() {
                    // Clear if text is still in the clipboard
                    if cp_text == text.expose_secret() {
                        let _ = clipboard.set_text("");
                    }
                }
            }
        });
    });
}

/**
 * Clear screen
 */
pub fn clear_screen() -> io::Result<()> {
    print!("\x1B[2J\x1B[1;1H");
    io::stdout().flush()
}
