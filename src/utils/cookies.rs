use std::{
    collections::{HashMap, HashSet},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use aes::cipher::{BlockDecryptMut, KeyIvInit, block_padding::Pkcs7};
use anyhow::{anyhow, bail};
use log::info;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use tokio::process::Command;

const MINIMAL_BILI_COOKIE_NAMES: [&str; 3] = ["SESSDATA", "bili_jct", "DedeUserID"];

#[derive(sqlx::FromRow)]
struct FirefoxCookie {
    name: String,
    value: String,
}
#[derive(sqlx::FromRow)]
struct ChromeCookie {
    name: String,
    value: String,
    encrypted_value: Vec<u8>,
}

async fn get_kwallet_password(browser: &str) -> anyhow::Result<[u8; 16]> {
    let browser_keyring_name: String = if browser.eq("chrome") {
        "Chrome".into()
    } else if browser.eq("chromium") {
        "Chromium".into()
    } else {
        return Err(anyhow::anyhow!("unknown browser"));
    };
    let dbus_send_cmd = Command::new("dbus-send")
        .args(&[
            "--session",
            "--print-reply=literal",
            "--dest=org.kde.kwalletd5",
            "/modules/kwalletd5",
            "org.kde.KWallet.networkWallet",
        ])
        .output()
        .await?;
    let wallet_name = String::from_utf8_lossy(&dbus_send_cmd.stdout).trim().to_string();
    info!("found wallet name: {}", &wallet_name);
    let kwallet_cmd = Command::new("kwallet-query")
        .args(&[
            "--read-password",
            format!("{} Safe Storage", &browser_keyring_name).as_str(),
            "--folder",
            format!("{} Keys", &browser_keyring_name).as_str(),
            wallet_name.as_str(),
        ])
        .output()
        .await?;
    let mut password = String::from_utf8_lossy(&kwallet_cmd.stdout).trim().to_string();
    if password.starts_with("Failed") {
        password.clear();
    }
    let mut pw_key = [0u8; 16];
    ring::pbkdf2::derive(
        ring::pbkdf2::PBKDF2_HMAC_SHA1,
        std::num::NonZeroU32::new(1).unwrap(),
        b"saltysalt",
        password.as_bytes(),
        &mut pw_key,
    );
    Ok(pw_key)
}

fn decrypt_chrome_cookie(data: &mut [u8], key: &[u8; 16]) -> anyhow::Result<String> {
    if let Some(it) = data.get(0..=2) {
        if it == b"v11" {
            type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;
            let mut buf = data.get(3..).unwrap().to_owned();
            let pt = Aes128CbcDec::new(key.into(), &[32u8; 16].into())
                .decrypt_padded_mut::<Pkcs7>(&mut buf)
                .map_err(|_| anyhow::anyhow!("decryption failed"))?;
            return Ok(String::from_utf8_lossy(pt.get(32..).unwrap_or(b"")).into());
        } else {
            return Err(anyhow::anyhow!("a v10 cookie"));
        }
    }
    todo!()
}

async fn get_chrome_cookies(host: &str, is_chromium: bool) -> anyhow::Result<String> {
    // TODO: detect de
    // let v10_key = b"peanuts";

    let (proj_dirs, v11_key) = if is_chromium {
        (
            directories::ProjectDirs::from("com", "google", "chromium").unwrap(),
            get_kwallet_password("chromium").await?,
        )
    } else {
        (
            directories::ProjectDirs::from("com", "google", "google-chrome").unwrap(),
            get_kwallet_password("chrome").await?,
        )
    };
    let d = proj_dirs.config_dir();
    let cookie_path = d.join("Default/Cookies");
    if !cookie_path.exists() {
        return Err(anyhow::anyhow!("Chrome Cookies file not found!"));
    }

    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect(&format!("sqlite:{}", cookie_path.to_string_lossy()))
        .await?;
    let mut cookies = sqlx::query_as::<_, ChromeCookie>(
        format!(
            "
SELECT name, value, encrypted_value 
FROM cookies
WHERE host_key LIKE '{}'
        ",
            host
        )
        .as_str(),
    )
    .fetch_all(&pool) // -> Vec<Country>
    .await?;
    let mut ret: String = "".into();
    for it in cookies.iter_mut() {
        if it.value.is_empty() {
            ret.push_str(
                format!(
                    "{}={};",
                    it.name,
                    decrypt_chrome_cookie(&mut it.encrypted_value, &v11_key)?
                )
                .as_str(),
            );
        } else {
            ret.push_str(format!("{}={};", it.name, it.value).as_str());
        }
    }
    Ok(ret)
}

#[derive(Default)]
struct IniSection {
    name: String,
    values: HashMap<String, String>,
}

fn parse_ini(contents: &str) -> Vec<IniSection> {
    let mut sections = Vec::new();
    let mut current: Option<IniSection> = None;
    for line in contents.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            if let Some(section) = current.take() {
                sections.push(section);
            }
            current = Some(IniSection {
                name: line[1..line.len() - 1].to_string(),
                values: HashMap::new(),
            });
        } else if let (Some(section), Some((key, value))) = (current.as_mut(), line.split_once('=')) {
            section.values.insert(key.trim().to_string(), value.trim().to_string());
        }
    }
    if let Some(section) = current {
        sections.push(section);
    }
    sections
}

fn resolve_profile_path(root: &Path, path: &str, relative: bool) -> PathBuf {
    if relative { root.join(path) } else { PathBuf::from(path) }
}

fn profiles_from_ini(root: &Path, contents: &str) -> Vec<PathBuf> {
    let sections = parse_ini(contents);
    let mut profiles = Vec::new();

    for section in sections.iter().filter(|section| section.name.starts_with("Install")) {
        if let Some(path) = section.values.get("Default") {
            profiles.push(resolve_profile_path(root, path, true));
        }
    }
    for default_only in [true, false] {
        for section in sections.iter().filter(|section| section.name.starts_with("Profile")) {
            if (section.values.get("Default").map(String::as_str) == Some("1")) != default_only {
                continue;
            }
            if let Some(path) = section.values.get("Path") {
                let relative = section.values.get("IsRelative").map(String::as_str) != Some("0");
                profiles.push(resolve_profile_path(root, path, relative));
            }
        }
    }
    let mut seen = HashSet::new();
    profiles.retain(|path| seen.insert(path.clone()));
    profiles
}

fn firefox_roots(home: &Path) -> Vec<PathBuf> {
    let mut roots = Vec::new();
    #[cfg(target_os = "macos")]
    roots.push(home.join("Library/Application Support/Firefox"));
    #[cfg(not(target_os = "macos"))]
    {
        roots.push(home.join(".mozilla/firefox"));
        roots.push(home.join("snap/firefox/common/.mozilla/firefox"));
        roots.push(home.join(".var/app/org.mozilla.firefox/.mozilla/firefox"));
    }
    roots
}

fn find_firefox_profiles(home: &Path) -> anyhow::Result<Vec<PathBuf>> {
    let mut profiles = Vec::new();
    for root in firefox_roots(home).into_iter().filter(|root| root.is_dir()) {
        if let Ok(contents) = std::fs::read_to_string(root.join("profiles.ini")) {
            profiles.extend(profiles_from_ini(&root, &contents));
        }
        for profile_parent in [root.join("Profiles"), root.clone()] {
            if let Ok(entries) = std::fs::read_dir(profile_parent) {
                let mut fallback = entries
                    .filter_map(Result::ok)
                    .map(|entry| entry.path())
                    .filter(|path| path.join("cookies.sqlite").is_file())
                    .collect::<Vec<_>>();
                fallback.sort_by_key(|path| {
                    std::fs::metadata(path)
                        .and_then(|metadata| metadata.modified())
                        .unwrap_or(SystemTime::UNIX_EPOCH)
                });
                fallback.reverse();
                profiles.extend(fallback);
            }
        }
    }
    let mut seen = HashSet::new();
    profiles.retain(|path| path.join("cookies.sqlite").is_file() && seen.insert(path.clone()));
    if profiles.is_empty() {
        bail!("no Firefox profile with cookies.sqlite was found");
    }
    Ok(profiles)
}

fn cookie_header(cookies: Vec<FirefoxCookie>) -> anyhow::Result<String> {
    let mut values = HashMap::new();
    for cookie in cookies {
        if !cookie.name.is_empty() && !cookie.value.is_empty() {
            values.insert(cookie.name, cookie.value);
        }
    }
    minimal_cookie_values(&values)
}

fn minimal_cookie_values(values: &HashMap<String, String>) -> anyhow::Result<String> {
    if values.get("SESSDATA").is_none_or(String::is_empty) {
        bail!("the required SESSDATA cookie was not found");
    }
    Ok(MINIMAL_BILI_COOKIE_NAMES
        .iter()
        .filter_map(|name| values.get(*name).filter(|value| !value.is_empty()).map(|value| format!("{name}={value}")))
        .collect::<Vec<_>>()
        .join("; "))
}

pub fn minimal_bili_cookie(header: &str) -> anyhow::Result<String> {
    let values = header
        .split(';')
        .filter_map(|item| item.trim().split_once('='))
        .map(|(name, value)| (name.trim().to_string(), value.trim().to_string()))
        .collect::<HashMap<_, _>>();
    minimal_cookie_values(&values)
}

async fn read_firefox_cookies(profile: &Path, host: &str) -> anyhow::Result<String> {
    let cookie_path = profile.join("cookies.sqlite");
    let options = SqliteConnectOptions::new().filename(&cookie_path).read_only(true).create_if_missing(false);
    let pool = SqlitePoolOptions::new().max_connections(1).connect_with(options).await?;
    let bare_host = host.trim_start_matches('.');
    let domain_host = format!(".{bare_host}");
    let www_host = format!("www.{bare_host}");
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;
    let cookies = sqlx::query_as::<_, FirefoxCookie>(
        r#"
SELECT name, value
FROM moz_cookies
WHERE host IN (?1, ?2, ?3)
  AND path = '/'
  AND (expiry = 0 OR expiry > ?4)
  AND originAttributes = ''
  AND name IN ('SESSDATA', 'bili_jct', 'DedeUserID')
ORDER BY lastAccessed ASC
        "#,
    )
    .bind(domain_host)
    .bind(bare_host)
    .bind(www_host)
    .bind(now)
    .fetch_all(&pool)
    .await?;
    pool.close().await;
    cookie_header(cookies)
}

async fn get_firefox_cookies(host: &str) -> anyhow::Result<String> {
    let user_dirs = directories::UserDirs::new().ok_or_else(|| anyhow!("user directory was not found"))?;
    let profiles = find_firefox_profiles(user_dirs.home_dir())?;
    let mut last_error = None;
    for profile in profiles {
        match read_firefox_cookies(&profile, host).await {
            Ok(cookies) => return Ok(cookies),
            Err(error) => {
                last_error = Some(error.context(format!(
                    "failed to read Firefox profile {}",
                    profile.display()
                )))
            }
        }
    }
    Err(last_error.unwrap_or_else(|| anyhow!("Firefox cookies were not found")))
}

pub async fn validate_bili_cookie(cookie: &str) -> anyhow::Result<bool> {
    if cookie.trim().is_empty() {
        return Ok(false);
    }
    let response = reqwest::Client::builder()
        .user_agent(crate::utils::gen_ua_safari())
        .connect_timeout(tokio::time::Duration::from_secs(10))
        .timeout(tokio::time::Duration::from_secs(15))
        .build()?
        .get("https://api.bilibili.com/x/web-interface/nav")
        .header("Referer", "https://www.bilibili.com/")
        .header("Cookie", cookie)
        .send()
        .await?
        .error_for_status()?
        .json::<serde_json::Value>()
        .await?;
    Ok(
        response.pointer("/code").and_then(|value| value.as_i64()) == Some(0)
            && response.pointer("/data/isLogin").and_then(|value| value.as_bool()) == Some(true),
    )
}

pub async fn get_cookies_from_browser(browser: &str, host: &str) -> anyhow::Result<String> {
    match browser.trim().to_ascii_lowercase().as_str() {
        "chrome" => get_chrome_cookies(host, false).await,
        "firefox" => get_firefox_cookies(host).await,
        "chromium" => get_chrome_cookies(host, true).await,
        _ => Err(anyhow!("browser not supported")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_firefox_profiles_are_preferred_and_deduplicated() {
        let root = Path::new("/home/test/.mozilla/firefox");
        let profiles = profiles_from_ini(
            root,
            r#"
[InstallABC]
Default=Profiles/default-release

[Profile0]
Name=default-release
IsRelative=1
Path=Profiles/default-release
Default=1

[Profile1]
Name=other
IsRelative=1
Path=Profiles/other
"#,
        );
        assert_eq!(
            profiles,
            vec![root.join("Profiles/default-release"), root.join("Profiles/other")]
        );
    }

    #[test]
    fn absolute_firefox_profile_paths_are_supported() {
        let profiles = profiles_from_ini(
            Path::new("/unused"),
            "[Profile0]\nIsRelative=0\nPath=/custom/firefox\nDefault=1\n",
        );
        assert_eq!(profiles, vec![PathBuf::from("/custom/firefox")]);
    }

    #[test]
    fn cookie_headers_are_stable_and_do_not_include_empty_values() {
        let header = cookie_header(vec![
            FirefoxCookie {
                name: "SESSDATA".into(),
                value: "session".into(),
            },
            FirefoxCookie {
                name: "bili_jct".into(),
                value: "csrf".into(),
            },
            FirefoxCookie {
                name: "buvid3".into(),
                value: "tracking".into(),
            },
        ])
        .unwrap();
        assert_eq!(header, "SESSDATA=session; bili_jct=csrf");
    }

    #[test]
    fn existing_cookie_headers_are_reduced_to_the_minimum() {
        let header = minimal_bili_cookie(
            "buvid3=tracking; DedeUserID=123; SESSDATA=session=value; bili_jct=csrf; sid=ignored",
        )
        .unwrap();
        assert_eq!(header, "SESSDATA=session=value; bili_jct=csrf; DedeUserID=123");
        assert!(minimal_bili_cookie("bili_jct=csrf; DedeUserID=123").is_err());
    }

    #[tokio::test]
    async fn firefox_reader_filters_expired_scoped_and_container_cookies() {
        let profile = std::env::temp_dir().join(format!("dmlive-firefox-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&profile).unwrap();
        let database = profile.join("cookies.sqlite");
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(SqliteConnectOptions::new().filename(&database).create_if_missing(true))
            .await
            .unwrap();
        sqlx::query(
            r#"CREATE TABLE moz_cookies (
                name TEXT NOT NULL,
                value TEXT NOT NULL,
                host TEXT NOT NULL,
                path TEXT NOT NULL,
                expiry INTEGER NOT NULL,
                originAttributes TEXT NOT NULL,
                lastAccessed INTEGER NOT NULL
            )"#,
        )
        .execute(&pool)
        .await
        .unwrap();
        let future = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64 + 3600;
        let past = future - 7200;
        for values in [
            ("SESSDATA", "session", ".bilibili.com", "/", future, "", 1),
            ("bili_jct", "csrf", ".bilibili.com", "/", future, "", 2),
            ("DedeUserID", "123", ".bilibili.com", "/", future, "", 3),
            ("buvid3", "tracking", ".bilibili.com", "/", future, "", 4),
            ("expired", "old", ".bilibili.com", "/", past, "", 5),
            ("scoped", "path", ".bilibili.com", "/account", future, "", 6),
            ("container", "isolated", ".bilibili.com", "/", future, "userContextId=1", 7),
        ] {
            sqlx::query(
                "INSERT INTO moz_cookies (name, value, host, path, expiry, originAttributes, lastAccessed) VALUES (?, ?, ?, ?, ?, ?, ?)",
            )
            .bind(values.0)
            .bind(values.1)
            .bind(values.2)
            .bind(values.3)
            .bind(values.4)
            .bind(values.5)
            .bind(values.6)
            .execute(&pool)
            .await
            .unwrap();
        }
        pool.close().await;

        let header = read_firefox_cookies(&profile, ".bilibili.com").await.unwrap();
        assert_eq!(header, "SESSDATA=session; bili_jct=csrf; DedeUserID=123");
        std::fs::remove_dir_all(profile).unwrap();
    }
}
