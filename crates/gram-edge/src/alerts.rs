//! `alerts`: Outgoing Webhooks & Notification Dispatcher for ShuzaGram.
//!
//! Supports:
//! 1. Directed Telegram Bot notifications (`https://api.telegram.org/bot<token>/sendMessage`)
//! 2. Email alerts via HTTP Webhook / Relay
//! 3. Generic Custom Webhooks (HTTP POST with JSON payload)

use std::time::{SystemTime, UNIX_EPOCH};

use gram_core::Store;
use serde::{Deserialize, Serialize};
use serde_json::json;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertConfig {
    pub telegram_bot_token: String,
    pub telegram_chat_id: String,
    pub email_recipient: String,
    pub email_webhook_url: String,
    pub custom_webhook_url: String,
    pub notify_on_login: bool,
    pub notify_on_code: bool,
    pub notify_on_stars: bool,
    pub notify_on_support: bool,
}

impl Default for AlertConfig {
    fn default() -> Self {
        Self {
            telegram_bot_token: String::new(),
            telegram_chat_id: String::new(),
            email_recipient: String::new(),
            email_webhook_url: String::new(),
            custom_webhook_url: String::new(),
            notify_on_login: true,
            notify_on_code: true,
            notify_on_stars: true,
            notify_on_support: true,
        }
    }
}

impl AlertConfig {
    pub fn load(store: &Store) -> Self {
        store
            .acid()
            .get_setting("alerts_config")
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }

    pub fn save(&self, store: &Store) {
        if let Ok(json_str) = serde_json::to_string(self) {
            let _ = store.acid().set_setting("alerts_config", &json_str);
        }
    }
}

/// Send a notification to configured channels (Telegram Bot, Email Webhook, Custom Webhook).
pub async fn dispatch_alert(store: &Store, event_type: &str, title: &str, details: &str) {
    let cfg = AlertConfig::load(store);

    let should_send = match event_type {
        "login" => cfg.notify_on_login,
        "auth_code" => cfg.notify_on_code,
        "stars" | "gift" => cfg.notify_on_stars,
        "support" | "system" => cfg.notify_on_support,
        _ => true,
    };

    if !should_send {
        return;
    }

    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(6))
        .build()
    {
        Ok(c) => c,
        Err(_) => return,
    };

    let now_ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let text_html = format!(
        "🔔 <b>[ShuzaGram Notification]</b>\n<b>Событие:</b> {}\n<b>Тема:</b> {}\n<b>Инфо:</b> {}",
        event_type, title, details
    );

    // 1. Directed Telegram Bot notification
    if !cfg.telegram_bot_token.is_empty() && !cfg.telegram_chat_id.is_empty() {
        let tg_url = format!(
            "https://api.telegram.org/bot{}/sendMessage",
            cfg.telegram_bot_token.trim()
        );
        let payload = json!({
            "chat_id": cfg.telegram_chat_id.trim(),
            "text": text_html,
            "parse_mode": "HTML"
        });
        let _ = client.post(&tg_url).json(&payload).send().await;
    }

    // 2. Email Webhook / Relay
    if !cfg.email_webhook_url.is_empty() {
        let payload = json!({
            "to": cfg.email_recipient.trim(),
            "subject": format!("[ShuzaGram] {}", title),
            "text": format!("Event: {}\nTitle: {}\nDetails: {}", event_type, title, details),
            "html": text_html,
            "timestamp": now_ts
        });
        let _ = client
            .post(cfg.email_webhook_url.trim())
            .json(&payload)
            .send()
            .await;
    }

    // 3. Custom Webhook
    if !cfg.custom_webhook_url.is_empty() {
        let payload = json!({
            "event": event_type,
            "title": title,
            "details": details,
            "timestamp": now_ts
        });
        let _ = client
            .post(cfg.custom_webhook_url.trim())
            .json(&payload)
            .send()
            .await;
    }
}

/// Send a direct test message to a Telegram Bot.
pub async fn test_telegram_alert(token: &str, chat_id: &str) -> Result<String, String> {
    if token.is_empty() || chat_id.is_empty() {
        return Err("Bot token and Chat ID are required".to_string());
    }
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(6))
        .build()
        .map_err(|e| e.to_string())?;

    let tg_url = format!("https://api.telegram.org/bot{}/sendMessage", token.trim());
    let payload = json!({
        "chat_id": chat_id.trim(),
        "text": "✅ <b>ShuzaGram Alert Test</b>\nТестовое уведомление успешно доставлено из ShuzaGram MTProto Control Plane!",
        "parse_mode": "HTML"
    });

    match client.post(&tg_url).json(&payload).send().await {
        Ok(resp) => {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            if status.is_success() {
                Ok("Уведомление успешно доставлено в Telegram!".to_string())
            } else {
                Err(format!("Telegram API error (HTTP {status}): {body}"))
            }
        }
        Err(e) => Err(format!("Network connection error: {e}")),
    }
}

/// Send a direct test payload to an Email Webhook / Relay.
pub async fn test_email_alert(webhook_url: &str, recipient: &str) -> Result<String, String> {
    if webhook_url.is_empty() {
        return Err("Email webhook URL is required".to_string());
    }
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(6))
        .build()
        .map_err(|e| e.to_string())?;

    let payload = json!({
        "to": recipient.trim(),
        "subject": "[ShuzaGram] Тестовое уведомление",
        "text": "Тестовое письмо от ShuzaGram MTProto Control Plane. Вебхук работает успешно!",
        "html": "<h2>ShuzaGram Alert Test</h2><p>Тестовое письмо от ShuzaGram MTProto Control Plane. Вебхук работает успешно!</p>",
        "timestamp": SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
    });

    match client.post(webhook_url.trim()).json(&payload).send().await {
        Ok(resp) => {
            let status = resp.status();
            if status.is_success() {
                Ok("Тестовое уведомление успешно отправлено на Email вебхук!".to_string())
            } else {
                let body = resp.text().await.unwrap_or_default();
                Err(format!("Webhook error (HTTP {status}): {body}"))
            }
        }
        Err(e) => Err(format!("Network error: {e}")),
    }
}
