use anyhow::Error;
use reqwest::redirect::Policy;
use reqwest::{multipart, Client, RequestBuilder};
use serde::{Deserialize, Serialize};
use std::cmp::min;
use std::fmt::format;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq)]
struct SeafileAuth {
    /// Email address
    username: String,
    /// password
    password: String,
}

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq)]
struct SeafileAccToken {
    /// Auth token
    token: String,
}

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq)]
struct SeafileRepoToken {
    /// Auth token
    token: String,
}

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq)]
struct SeafileFileUploadResp {
    file_upload_noret: String,
    file_upload_ret: Vec<SeafileUploadObj>,
}

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq)]
struct SeafileUploadObj {
    name: String,
    id: String,
    size: i32,
}

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq)]
struct SeafileGetUploadLinkParams {
    path: String,
    from: Option<String>,
    replace: Option<String>,
}

impl SeafileGetUploadLinkParams {
    fn from_path(path: &str) -> Self {
        SeafileGetUploadLinkParams {
            path: path.to_string(),
            from: None,
            replace: None,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq)]
struct SeafileSharePermissions {
    can_edit: bool,
    can_download: bool,
    can_upload: bool,
}

impl SeafileSharePermissions {
    fn download_only() -> Self {
        SeafileSharePermissions {
            can_edit: false,
            can_download: true,
            can_upload: false,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq)]
struct SeafileShareObj {
    /// Share owner
    username: String,
    /// Library id
    repo_id: String,
    repo_name: String,
    /// File/folder path being shared
    path: String,
    /// File/folder name
    obj_name: String,
    obj_id: String,
    is_dir: bool,
    /// Idk what this is for
    token: String,
    /// Share link
    link: String,
    /// Tracking :eye:
    view_cnt: u32,
    /// Creation time
    ctime: String,
    /// Expiry date, can be empty string to indicate no expiry
    expire_date: String,
    is_expired: bool,
    permissions: SeafileSharePermissions,
    /// A password to access this share, is empty str when unprotected.
    password: String,
    /// LO
    can_edit: bool,
}

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq)]
struct SeafileCreateaShareLinkParams {
    /// ID of the library/repo
    repo_id: String,
    /// Folder/file to share
    path: String,
    /// Password needed to access the share afterward, omit for public shares
    password: Option<String>,
    /// Number of days after which the share becomes inaccessible
    expire_days: Option<u32>,
    /// Permissions for this share link
    permissions: SeafileSharePermissions,
}
use clap::Parser;
use futures_util::StreamExt;
use keyring::Entry;
use notify_rust::{Hint, Notification, NotificationHandle};
use reqwest::header::{CONTENT_LENGTH, CONTENT_TYPE};
use rusqlite::{Connection, OpenFlags};
use serde::de::DeserializeOwned;
use wl_clipboard_rs::copy::{ClipboardType, MimeType, Options, Source};

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// File to upload
    #[clap(short, long)]
    file: PathBuf,
    /// Seafile server endpoint (e.g. https://seafile.example.com)
    #[clap(long)]
    host: String,
    /// User, your email/username
    username: String,
    /// Library/repo token, obtained via the Library's context menu > Advanced > Api Tokens
    #[clap(long)]
    repo_token: String,
    /// Library/repo id, obtained via the uuid in the url bar when looking at the library.
    #[clap(long)]
    repo_id: String,
}

struct CommunicationContext {
    client: Client,
    host: String,
}

#[tokio::main]
async fn main() {
    let copied_success = Arc::new(Mutex::new(false));
    let args = Args::parse();
    let client = Client::new();

    let account_token = match get_account_token(args.username).await {
        Ok(token) => token,
        Err(e) => {
            println!("{}", e);
            return;
        }
    };

    let com_ctx = CommunicationContext {
        client,
        host: args.host,
    };

    // The seafile library (repo) you want to upload to
    let repo_token = SeafileRepoToken {
        token: args.repo_token,
    };

    // Parent dir, e.g. a  folder in the library to upload to.
    let repo_id = args.repo_id.as_str();
    let parent_dir = "/";

    let upload_link = seafile_get_upload_link(&com_ctx, &repo_token, parent_dir).await;

    // Show initial notification, indicating upload start
    let mut notification_handle = Notification::new()
        .summary("Starting seafile upload")
        .body(
            format!(
                "progress: 0%\nbar: ◻◻◻◻◻◻◻◻◻◻\nfile: {}",
                args.file.display()
            )
            .as_str(),
        )
        .hint(Hint::Resident(true))
        .show()
        .unwrap();

    let uploaded_file = seafile_post_upload(
        &com_ctx,
        args.file,
        &repo_token,
        upload_link,
        parent_dir,
        &mut notification_handle,
    )
    .await
    .pop()
    .unwrap();

    let share_link =
        seafile_get_share_link(&com_ctx, repo_id, &account_token, parent_dir, uploaded_file).await;
    let raw_link = fetch_redirect_loc(format!("{share_link}?dl=1")).await;

    // Show finished notification
    notification_handle
        .summary("Upload to seafile finished")
        .body(raw_link.as_str())
        .action("open", "Open link")
        .action("copy", "Copy link")
        .action("dismiss", "Dismiss")
        .hint(Hint::Resident(true));
    notification_handle.update();
    let notification_id = notification_handle.id();

    notification_handle.wait_for_action(|action| {
        match action {
            "copy" => {
                let opts = Options::new()
                    .foreground(true)
                    .clipboard(ClipboardType::Both)
                    .clone();
                match opts.copy(
                    Source::Bytes(raw_link.into_bytes().into()),
                    MimeType::Autodetect,
                ) {
                    Ok(_) => {
                        println!("Copied successfully");
                        let copy_success_mutex = copied_success.clone();
                        let mut copy_success_guard = copy_success_mutex.lock().unwrap();
                        *copy_success_guard = true;
                    }
                    Err(e) => eprintln!("Failed to copy share link: {e:?}"),
                }
            }
            "open" => {
                // TODO: xdg-open the url
            }
            "default" => println!("you clicked \"default\""),
            "clicked" => println!("don hector salamanca, kill them"),
            // here "__closed" is a hard coded keyword
            "__closed" => println!("the notification was closed"),
            _ => (),
        }
    });
    if *copied_success.lock().unwrap() {
        Notification::new()
            .id(notification_id)
            .summary("Copied!")
            .show()
            .expect("AAA");
    } else {
        Notification::new()
            .id(notification_id)
            .summary("Error")
            .body("Something went wrong during the copy, check logs.")
            .show()
            .expect("AAAA");
    }
}

async fn get_account_token(user: String) -> Result<SeafileAccToken, Error> {
    let entry = Entry::new("seafile", user.as_str())?;
    let token = entry.get_password();
    let token_str = match token {
        Ok(token) => token,
        Err(_no_token) => {
            let token = borrow_account_token_from_seafile(user)?;
            entry.set_password(token.as_str())?;
            token
        }
    };
    Ok(SeafileAccToken { token: token_str })
}

fn borrow_account_token_from_seafile(user: String) -> Result<String, Error> {
    // TODO: Replace with home getter
    let seaf_data_path = fs::read_to_string(format!("{}/.ccnet/seafile.ini", env!("HOME")))?;
    let seaf_accounts_path = format!("{seaf_data_path}/accounts.db");
    let con = Connection::open_with_flags(&seaf_accounts_path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let mut stmt = con.prepare("SELECT token FROM Accounts WHERE username= :user")?;
    let mapper = stmt.query_map(&[(":user", user.as_str())], |row| {
        row.get::<&str, String>("token")
    })?;
    let token = mapper
        .collect::<Vec<Result<String, rusqlite::Error>>>()
        .pop()
        .ok_or(Error::msg("No tokens to be stolen here."))?;
    token.map_err(|e| Error::from(e))
}

async fn fetch_redirect_loc(link: String) -> String {
    // Redirects ? Nuh uh
    let client = Client::builder().redirect(Policy::none()).build().unwrap();

    let response = client
        .head(link)
        .send()
        .await
        .expect("One sec I gotta walk my fish");
    println!("{:?}", response);
    String::from_utf8(Vec::from(
        response
            .headers()
            .get("location")
            .expect("This is NOT a redirect, you LIAR!")
            .as_bytes(),
    ))
    .expect("What the f*** is that. What the F*** is that, that's a weird looking f***king cat!")
}

async fn fire<T: DeserializeOwned>(req_builder: RequestBuilder) -> Result<T, Error> {
    let resp = req_builder.send().await;
    match resp {
        Ok(resp) => {
            let resp_dbg = format!("{:?}", resp);
            let result_text = resp
                .text()
                .await
                .expect("apparently they didnt send us text");
            let result = serde_json::from_str(result_text.clone().as_str());
            match result {
                Ok(good) => Ok(good),
                Err(bad) => {
                    eprintln!(
                        "{:?}, serialization error or something, idk\nResp: {:?}\nBody: {:?}",
                        bad, resp_dbg, result_text
                    );
                    Err(Error::msg(bad))
                }
            }
        }
        Err(error) => {
            eprintln!("{:?}, networking error or something, idk", error);
            return Err(Error::from(error));
        }
    }
}

async fn seafile_get_share_link(
    ctx: &CommunicationContext,
    repo_id: &str,
    account_token: &SeafileAccToken,
    parent_dir: &str,
    file: SeafileUploadObj,
) -> String {
    let share_link_params = SeafileCreateaShareLinkParams {
        repo_id: repo_id.to_string(),
        permissions: SeafileSharePermissions::download_only(),
        path: format!("{}{}", parent_dir, file.name),
        password: None,
        expire_days: None,
    };
    let share_obj = fire::<SeafileShareObj>(
        ctx.client
            .post(format!("{}/api/v2.1/share-links/", ctx.host))
            .bearer_auth(&account_token.token)
            .json(&share_link_params),
    )
    .await
    .unwrap();
    share_obj.link
}

async fn seafile_post_upload(
    ctx: &CommunicationContext,
    file_path: PathBuf,
    repo_token: &SeafileRepoToken,
    upload_link: String,
    parent_dir: &str,
    notification_handle: &mut NotificationHandle,
) -> Vec<SeafileUploadObj> {
    let mut form = multipart::Form::new()
        .text("replace", "0")
        .text("parent_dir", parent_dir.to_string())
        .file("file", file_path.clone())
        .await
        .expect("couldn't add video.mp4 to form");

    let boundary = form.boundary();
    let content_type = format!("multipart/form-data; boundary={}", boundary).clone();
    let content_length = form.compute_length();
    let body = form.stream();
    let mut uploaded = 0;
    let block_count = 10usize;
    let mut block_prog = 0usize;
    let total_size = body
        .content_length()
        .unwrap_or(fs::metadata(file_path).unwrap().size());

    let mut body_stream = body.into_stream();
    let coroutine_upl_link = upload_link.clone();
    let notif_id = notification_handle.id();
    let async_stream = async_stream::stream! {
        while let Some(chunk) = body_stream.next().await {
            if let Ok(chunk) = &chunk {
                let new = min(uploaded + (chunk.len() as u64), total_size);
                uploaded = new;
                let new_block_prog = ((uploaded as f64 / total_size as f64) * block_count as f64).floor() as usize;
                if new_block_prog > block_prog {
                    block_prog = new_block_prog;
                    Notification::new()
                        .id(notif_id)
                        .summary("Seafile upload progress")
                        .body(format!("bar: {}{}\nfile: {}", "◼".repeat(block_prog), "◻".repeat(block_count - block_prog), coroutine_upl_link).as_str())
                        .hint(Hint::Resident(true))
                        .show().expect("WORK");
                }
            }
            yield chunk;
        }
    };

    let mut builder = ctx
        .client
        .post(format!("{}?ret-json=1", upload_link))
        .bearer_auth(&repo_token.token)
        .body(reqwest::Body::wrap_stream(async_stream))
        .header(CONTENT_TYPE, content_type);
    if let Some(length) = content_length {
        builder = builder.header(CONTENT_LENGTH, length);
    }

    let uploaded_files: Vec<SeafileUploadObj> = fire(builder).await.unwrap();

    uploaded_files
}

async fn seafile_get_upload_link(
    ctx: &CommunicationContext,
    token: &SeafileRepoToken,
    parent_dir: &str,
) -> String {
    let response = ctx
        .client
        .get(format!("{}/api/v2.1/via-repo-token/upload-link/", ctx.host))
        .query(&SeafileGetUploadLinkParams::from_path(parent_dir))
        .bearer_auth(&token.token)
        .send()
        .await
        .expect("Expected upload link");

    let str: String = response.json().await.expect("Invalid JSON");
    str
}
