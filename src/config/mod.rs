pub mod config;

use crate::utils::is_android;
use clap::Parser;
use config::{BVideoInfo, BVideoType, Config};
use log::warn;
use reqwest::Url;
use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::path::Path;

#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
pub struct Args {
    /// Set the http url
    #[clap(short = 'u', long, value_parser, value_name = "URL")]
    url: String,

    #[clap(short = 'r', long, action)]
    record: bool,

    #[clap(long = "download-dm", action)]
    download_dm: bool,

    #[clap(short = 'w', long = "wait-interval", value_parser)]
    wait_interval: Option<u64>,

    #[clap(long = "log-level", default_value_t = 3, value_parser)]
    pub log_level: u8,

    /// Serve as a http server
    #[clap(long = "http-address", value_parser)]
    http_address: Option<String>,

    /// Do not print danmaku
    #[clap(short = 'q', long, action)]
    quiet: bool,

    #[clap(long, action)]
    tcp: bool,

    #[clap(long, action)]
    plive: bool,
    // /// Use the Cookies that extracted from browser, could be "chrome" "chromium" or "firefox"
    // #[clap(long = "cookies-from-browser", value_parser)]
    // cookies_from_browser: Option<String>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    Linux,
    LinuxTcp,
    Android,
}
pub enum RunMode {
    Play,
    Record,
}

pub enum RecordMode {
    All,
    Danmaku,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum StreamType {
    FLV,
    HLS(usize),
    DASH,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Site {
    BiliLive,
    BiliVideo,
    BahaVideo,
    DouyuLive,
    HuyaLive,
    TwitchLive,
    YoutubeLive,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum SiteType {
    Live,
    Video,
}

pub struct ConfigManager {
    pub plat: Platform,
    pub bcookie: String,
    pub cookies_from_browser: String,
    pub plive: bool,
    pub quiet: bool,
    pub wait_interval: u64,
    pub font_scale: Cell<f64>,
    pub font_alpha: Cell<f64>,
    pub danmaku_speed: Cell<u64>,
    pub display_fps: Cell<(u64, u64)>,
    pub room_url: String,
    pub http_address: Option<String>,
    pub run_mode: RunMode,
    pub record_mode: RecordMode,
    pub site: Site,
    pub site_type: SiteType,
    pub stream_type: Cell<StreamType>,
    pub bvideo_info: RefCell<BVideoInfo>,
    pub title: RefCell<String>,
    on_writing: Cell<bool>,
}

impl ConfigManager {
    pub fn new(config_path: impl AsRef<Path>, args: &Args) -> Self {
        let mut plat = Platform::Linux;
        if args.tcp {
            plat = Platform::LinuxTcp;
        }
        let mut bvinfo = BVideoInfo {
            base_url: "".into(),
            video_type: BVideoType::Video,
            current_page: 0,
            plist: Vec::new(),
        };
        let c = std::fs::read(config_path).unwrap();
        let c = String::from_utf8_lossy(&c);
        let c = config::load_config(&c).unwrap();
        let room_url = args.url.clone();
        let mut site_type = SiteType::Live;
        let site = if room_url.contains("live.bilibili.com/") {
            Site::BiliLive
        } else if room_url.contains("bilibili.com/") {
            let u = Url::parse(&room_url).unwrap();
            for q in u.query_pairs() {
                if q.0.eq("p") {
                    bvinfo.current_page = q.1.parse().unwrap();
                }
            }
            let vid = u.path_segments().unwrap().filter(|x| !x.is_empty()).last().unwrap().to_string();
            if vid.starts_with("BV") || vid.starts_with("av") {
                bvinfo.video_type = BVideoType::Video;
                bvinfo.base_url.push_str(format!("https://www.bilibili.com/video/{}", vid).as_str());
            } else {
                bvinfo.video_type = BVideoType::Bangumi;
                bvinfo.base_url.push_str(format!("https://www.bilibili.com/bangumi/play/{}", vid).as_str());
            }
            site_type = SiteType::Video;
            Site::BiliVideo
        } else if room_url.contains("ani.gamer.com.tw/") {
            let u = Url::parse(&room_url).unwrap();
            for q in u.query_pairs() {
                if q.0.eq("p") {
                    bvinfo.current_page = q.1.parse().unwrap();
                }
            }
            site_type = SiteType::Video;
            Site::BahaVideo
        } else if room_url.contains("douyu.com/") {
            Site::DouyuLive
        } else if room_url.contains("huya.com/") {
            Site::HuyaLive
        } else if room_url.contains("twitch.tv/") {
            Site::TwitchLive
        } else if room_url.contains("youtube.com/") {
            Site::YoutubeLive
        } else {
            panic!("unknown url")
        };
        let run_mode = if args.record || args.http_address.is_some() || args.download_dm {
            RunMode::Record
        } else {
            RunMode::Play
        };
        let record_mode = if args.download_dm {
            RecordMode::Danmaku
        } else {
            RecordMode::All
        };
        Self {
            room_url: room_url.replace("dmlive://", "https://"),
            stream_type: Cell::new(StreamType::FLV),
            run_mode,
            record_mode,
            site,
            site_type,
            font_scale: Cell::new(c.font_scale.unwrap_or(1.0)),
            font_alpha: Cell::new(c.font_alpha.unwrap_or(0.0)),
            danmaku_speed: Cell::new(c.danmaku_speed.unwrap_or(8000)),
            bvideo_info: RefCell::new(bvinfo),
            bcookie: c.bcookie.unwrap_or_else(|| "".into()),
            http_address: args.http_address.as_ref().map(|it| it.into()),
            plive: args.plive,
            quiet: args.quiet,
            wait_interval: args.wait_interval.unwrap_or(0),
            on_writing: Cell::new(false),
            plat,
            cookies_from_browser: c.cookies_from_browser.unwrap_or_else(|| "".into()),
            display_fps: Cell::new((60, 0)),
            title: RefCell::new("".to_string()),
        }
    }

    pub async fn init(&mut self) -> anyhow::Result<()> {
        if is_android().await {
            self.plat = Platform::Android;
        }
        if self.plat != Platform::Android
            && matches!(self.site, Site::BiliLive | Site::BiliVideo)
            && !self.cookies_from_browser.is_empty()
        {
            self.refresh_bili_cookie_from_browser().await;
        }
        Ok(())
    }

    async fn refresh_bili_cookie_from_browser(&mut self) {
        if let Ok(configured_cookie) = crate::utils::cookies::minimal_bili_cookie(&self.bcookie) {
            match crate::utils::cookies::validate_bili_cookie(&configured_cookie).await {
                Ok(true) => {
                    if configured_cookie != self.bcookie {
                        self.bcookie = configured_cookie;
                        if let Err(error) = self.write_config().await {
                            warn!("the minimal configured cookie is valid but could not be saved: {error}");
                        }
                    }
                    return;
                }
                Ok(false) => warn!("configured video-site cookie is no longer logged in; trying the browser profile"),
                Err(error) => {
                    warn!("could not validate the configured video-site cookie; trying the browser profile: {error}");
                }
            }
        }

        let browser_cookie =
            match crate::utils::cookies::get_cookies_from_browser(&self.cookies_from_browser, ".bilibili.com").await {
                Ok(cookie) => cookie,
                Err(error) => {
                    warn!(
                        "could not read cookies from {}: {error}",
                        self.cookies_from_browser
                    );
                    return;
                }
            };
        let candidate = match crate::utils::cookies::minimal_bili_cookie(&browser_cookie) {
            Ok(cookie) => cookie,
            Err(error) => {
                warn!("cookies from {} do not contain the required login fields: {error}", self.cookies_from_browser);
                return;
            }
        };
        match crate::utils::cookies::validate_bili_cookie(&candidate).await {
            Ok(true) => {
                self.bcookie = candidate;
                if let Err(error) = self.write_config().await {
                    warn!("browser cookies are valid but could not be saved to config: {error}");
                }
            }
            Ok(false) => warn!(
                "cookies from {} are not logged in",
                self.cookies_from_browser
            ),
            Err(error) => warn!(
                "could not validate cookies from {}: {error}",
                self.cookies_from_browser
            ),
        }
    }

    pub fn set_stream_type(&self, stream_info: &HashMap<&str, String>) {
        if stream_info["url"].contains(".m3u8") {
            if self.site == Site::BiliLive {
                self.stream_type.set(StreamType::HLS(1)); // for m4s inside
            } else {
                self.stream_type.set(StreamType::HLS(0)); // for ts inside
            }
        } else if stream_info["url"].contains(".flv") {
            self.stream_type.set(StreamType::FLV);
        } else {
            self.stream_type.set(StreamType::DASH);
        }
        if matches!(self.site, Site::BiliVideo) {
            self.stream_type.set(StreamType::DASH);
        }
    }

    pub async fn write_config(&self) -> anyhow::Result<()> {
        if self.on_writing.replace(true) {
            return Ok(());
        }
        let result = async {
            let proj_dirs = directories::ProjectDirs::from("com", "THMonster", "dmlive").unwrap();
            let d = proj_dirs.config_dir();
            tokio::fs::create_dir_all(&d).await?;
            let config_path = d.join("config.toml");
            let temporary_path = d.join("config.toml.tmp");
            let contents = toml::to_string_pretty(&Config {
                bcookie: Some(self.bcookie.clone()),
                cookies_from_browser: Some(self.cookies_from_browser.clone()),
                danmaku_speed: Some(self.danmaku_speed.get()),
                font_alpha: Some(self.font_alpha.get()),
                font_scale: Some(self.font_scale.get()),
            })
            .unwrap();
            tokio::fs::write(&temporary_path, contents).await?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                tokio::fs::set_permissions(&temporary_path, std::fs::Permissions::from_mode(0o600)).await?;
            }
            tokio::fs::rename(temporary_path, config_path).await?;
            anyhow::Ok(())
        }
        .await;
        self.on_writing.set(false);
        result
    }
}
