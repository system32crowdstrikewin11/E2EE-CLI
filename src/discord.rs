use rand::{rngs::OsRng, RngCore};
use serde::Deserialize;
use serde_json::json;
use std::io::Read;
use std::time::Duration;
use ureq::Agent;
use zeroize::{Zeroize, ZeroizeOnDrop};

const API_BASE: &str = "https://discord.com/api/v9";
const USER_AGENT: &str =
    "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Mobile Safari/537.36";

#[derive(Zeroize, ZeroizeOnDrop)]
struct SecretToken(String);

pub struct DiscordClient {
    agent: Agent,
    token: SecretToken,
    pub me: DiscordUser,
}

#[derive(Clone, Debug, Deserialize)]
pub struct DiscordUser {
    pub id: String,
    pub username: String,
    pub global_name: Option<String>,
}

impl DiscordUser {
    pub fn display_name(&self) -> &str {
        self.global_name
            .as_deref()
            .filter(|s| !s.is_empty())
            .unwrap_or(&self.username)
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct Guild {
    pub id: String,
    pub name: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Channel {
    pub id: String,
    pub name: Option<String>,
    #[serde(rename = "type")]
    pub kind: u8,
    #[serde(default)]
    pub recipients: Vec<DiscordUser>,
}

impl Channel {
    pub fn display_label(&self) -> String {
        if let Some(ref name) = self.name {
            if !name.is_empty() {
                return format!("#{name}");
            }
        }
        if !self.recipients.is_empty() {
            let names: Vec<&str> = self.recipients.iter().map(|u| u.display_name()).collect();
            return format!("@{}", names.join(", "));
        }
        format!("channel:{}", self.id)
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct Attachment {
    pub filename: String,
    pub size: u64,
    pub url: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ReferencedMessage {
    pub channel_id: Option<String>,
    #[serde(default)]
    pub content: String,
    pub author: DiscordUser,
}

#[derive(Clone, Debug, Deserialize)]
pub struct DiscordMessage {
    pub id: String,
    pub channel_id: String,
    #[serde(default)]
    pub content: String,
    pub author: DiscordUser,
    #[serde(default)]
    pub attachments: Vec<Attachment>,
    pub referenced_message: Option<Box<ReferencedMessage>>,
}

impl DiscordClient {
    pub fn login(raw_token: String) -> Result<Self, String> {
        let mut raw = raw_token;
        let clean = raw
            .trim()
            .trim_matches('"')
            .trim_matches('\'')
            .to_string();
        raw.zeroize();

        if clean.is_empty() {
            return Err("Token cannot be empty".into());
        }

        let config = Agent::config_builder()
            .timeout_global(Some(Duration::from_secs(30)))
            .build();
        let agent: Agent = config.into();

        let me: DiscordUser = agent
            .get(&format!("{API_BASE}/users/@me"))
            .header("Authorization", &clean)
            .header("User-Agent", USER_AGENT)
            .call()
            .map_err(fmt_http_err)?
            .body_mut()
            .read_json()
            .map_err(|e| format!("Failed to parse user profile: {e}"))?;

        Ok(Self {
            agent,
            token: SecretToken(clean),
            me,
        })
    }

    pub fn list_dms(&self) -> Result<Vec<Channel>, String> {
        self.get_json(&format!("{API_BASE}/users/@me/channels"))
    }

    pub fn list_guilds(&self) -> Result<Vec<Guild>, String> {
        self.get_json(&format!("{API_BASE}/users/@me/guilds"))
    }

    pub fn list_guild_channels(&self, guild_id: &str) -> Result<Vec<Channel>, String> {
        self.get_json(&format!("{API_BASE}/guilds/{guild_id}/channels"))
    }

    pub fn get_messages(&self, channel_id: &str, limit: usize) -> Result<Vec<DiscordMessage>, String> {
        let lim = limit.clamp(1, 100);
        self.get_json(&format!("{API_BASE}/channels/{channel_id}/messages?limit={lim}"))
    }

    pub fn get_messages_after(
        &self,
        channel_id: &str,
        after_id: &str,
    ) -> Result<Vec<DiscordMessage>, String> {
        self.get_json(&format!(
            "{API_BASE}/channels/{channel_id}/messages?after={after_id}&limit=50"
        ))
    }

    pub fn get_message_by_id(
        &self,
        channel_id: &str,
        message_id: &str,
    ) -> Result<DiscordMessage, String> {
        let msgs: Vec<DiscordMessage> = self.get_json(&format!(
            "{API_BASE}/channels/{channel_id}/messages?around={message_id}&limit=3"
        ))?;
        msgs.into_iter()
            .find(|m| m.id == message_id)
            .ok_or_else(|| format!("Message {message_id} not found in channel {channel_id}"))
    }

    pub fn send_message(&self, channel_id: &str, content: &str) -> Result<DiscordMessage, String> {
        self.agent
            .post(&format!("{API_BASE}/channels/{channel_id}/messages"))
            .header("Authorization", &self.token.0)
            .header("User-Agent", USER_AGENT)
            .send_json(json!({ "content": content }))
            .map_err(fmt_http_err)?
            .body_mut()
            .read_json()
            .map_err(|e| format!("Failed to parse sent message: {e}"))
    }

    pub fn send_file(
        &self,
        channel_id: &str,
        filename: &str,
        encrypted_bytes: &[u8],
        caption: Option<&str>,
    ) -> Result<DiscordMessage, String> {
        let mut rnd = [0u8; 12];
        OsRng.fill_bytes(&mut rnd);
        let mut boundary = String::from("----AegiresBoundary");
        for b in rnd {
            boundary.push_str(&format!("{b:02x}"));
        }

        let safe_name: String = filename
            .chars()
            .map(|c| match c {
                '"' | '\r' | '\n' | '\\' => '_',
                _ => c,
            })
            .collect();

        let payload = match caption {
            Some(c) if !c.is_empty() => json!({ "content": c }),
            _ => json!({}),
        };
        let payload_str = payload.to_string();

        let mut body = Vec::with_capacity(encrypted_bytes.len() + payload_str.len() + 512);
        body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
        body.extend_from_slice(
            b"Content-Disposition: form-data; name=\"payload_json\"\r\nContent-Type: application/json\r\n\r\n",
        );
        body.extend_from_slice(payload_str.as_bytes());
        body.extend_from_slice(b"\r\n");

        body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
        body.extend_from_slice(
            format!(
                "Content-Disposition: form-data; name=\"files[0]\"; filename=\"{safe_name}\"\r\nContent-Type: application/octet-stream\r\n\r\n"
            )
            .as_bytes(),
        );
        body.extend_from_slice(encrypted_bytes);
        body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());

        self.agent
            .post(&format!("{API_BASE}/channels/{channel_id}/messages"))
            .header("Authorization", &self.token.0)
            .header("User-Agent", USER_AGENT)
            .header("Content-Type", &format!("multipart/form-data; boundary={boundary}"))
            .send(body)
            .map_err(fmt_http_err)?
            .body_mut()
            .read_json()
            .map_err(|e| format!("Failed to parse upload response: {e}"))
    }

    pub fn download_reader(&self, url: &str) -> Result<Box<dyn Read + Send>, String> {
        let resp = self
            .agent
            .get(url)
            .header("User-Agent", USER_AGENT)
            .call()
            .map_err(fmt_http_err)?;
        Ok(Box::new(resp.into_body().into_reader()))
    }

    fn get_json<T: for<'de> Deserialize<'de>>(&self, url: &str) -> Result<T, String> {
        self.agent
            .get(url)
            .header("Authorization", &self.token.0)
            .header("User-Agent", USER_AGENT)
            .call()
            .map_err(fmt_http_err)?
            .body_mut()
            .read_json()
            .map_err(|e| format!("Failed to parse JSON response: {e}"))
    }
}

fn fmt_http_err(err: ureq::Error) -> String {
    match err {
        ureq::Error::StatusCode(401) => "HTTP 401 Unauthorized (invalid or expired token)".into(),
        ureq::Error::StatusCode(403) => "HTTP 403 Forbidden (no permission for this channel)".into(),
        ureq::Error::StatusCode(404) => "HTTP 404 Not Found (check channel/message ID)".into(),
        ureq::Error::StatusCode(413) => "HTTP 413 Payload Too Large (exceeds Discord upload limit)".into(),
        ureq::Error::StatusCode(429) => "HTTP 429 Rate limited by Discord — try again in a few seconds".into(),
        other => format!("HTTP error: {other}"),
    }
}
