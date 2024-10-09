use csv::{Reader, WriterBuilder};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader};
use std::{path::Path, sync::Arc};
use teloxide::prelude::*;
use teloxide::types::Message;
use teloxide::types::{ChatKind, ChatMemberStatus, ChatPermissions};
use tokio::sync::Mutex;
use tracing::{error, info, warn};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

const USERS_FILE: &str = "users.csv";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct UserData {
    name: String,
    surname: String,
    registration_code: Option<u64>,
    is_registered: bool,
    user_id: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BotConfig {
    welcome_message: String,
    data_collection_notice: String,
    name_request: String,
    surname_request: String,
    code_request: String,
    code_error: String,
    success_message: String,
    general_error: String,
    invalid_type_error: String,
    too_long_error: String,
    empty_error: String,
    not_number_error: String,
    group_chat_id: i64,
}

#[derive(Debug, Clone)]
enum RegistrationState {
    AwaitingName,
    AwaitingSurname,
    AwaitingCode,
    Completed,
}

struct BotState {
    user_data: HashMap<i64, UserData>,
    registration_states: HashMap<i64, RegistrationState>,
    config: BotConfig,
}
impl BotState {
    // Load users from CSV file
    fn load_users() -> HashMap<i64, UserData> {
        let mut users = HashMap::new();

        if !Path::new(USERS_FILE).exists() {
            info!("No users file found, starting with empty user list");
            return users;
        }

        match Reader::from_path(USERS_FILE) {
            Ok(mut reader) => {
                for result in reader.deserialize::<UserData>() {
                    match result {
                        Ok(user_data) => {
                            info!(
                                "Loaded user {}: {} {}",
                                user_data.user_id, user_data.name, user_data.surname
                            );
                            users.insert(user_data.user_id, user_data);
                        }
                        Err(e) => {
                            error!("Error deserializing user: {}", e);
                        }
                    }
                }
            }
            Err(e) => {
                error!("Error opening users file: {}", e);
            }
        }

        info!("Loaded {} users from file", users.len());
        users
    }

    // Save user to CSV file
}

#[tokio::main]
async fn main() {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "telegram_bot=debug,tower_http=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    info!("Starting bot...");

    let config: BotConfig = match fs::read_to_string("config.json") {
        Ok(content) => match serde_json::from_str(&content) {
            Ok(config) => config,
            Err(e) => {
                error!("Failed to parse config file: {}", e);
                std::process::exit(1);
            }
        },
        Err(e) => {
            error!("Failed to read config file: {}", e);
            std::process::exit(1);
        }
    };

    let bot = Bot::from_env();

    let state = Arc::new(Mutex::new(BotState {
        user_data: BotState::load_users(),
        registration_states: HashMap::new(),
        config,
    }));

    info!("Configuring bot handler...");
    let new_member_handler = Update::filter_chat_member()
        .filter(|chat_member: ChatMemberUpdated| {
            matches!(
                chat_member.new_chat_member.status(),
                ChatMemberStatus::Member
            )
        })
        .endpoint(handle_new_member);

    let private_message_handler = Update::filter_message()
        .filter(|msg: Message| matches!(msg.chat.kind, ChatKind::Private(_)))
        .endpoint(handle_registration);

    let chat_id_handler = Update::filter_message()
        .filter(|msg: Message| msg.text().map(|text| text == "/chat_id").unwrap_or(false))
        .endpoint(handle_chat_id);
    let handler = dptree::entry()
        .branch(new_member_handler)
        .branch(private_message_handler)
        .branch(chat_id_handler);

    info!("Starting bot dispatcher...");
    Dispatcher::builder(bot, handler)
        .dependencies(dptree::deps![state])
        .enable_ctrlc_handler()
        .build()
        .dispatch()
        .await;
}
async fn handle_chat_id(
    bot: Bot,
    msg: Message,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let chat_id = msg.chat.id.0;

    match bot
        .send_message(msg.chat.id, format!("Chat ID: {}", chat_id))
        .await
    {
        Ok(_) => info!("Chat ID sent successfully."),
        Err(e) => error!("Error sending chat ID: {}", e),
    }

    Ok(())
}

async fn handle_new_member(
    bot: Bot,
    msg: ChatMemberUpdated,
    state: Arc<Mutex<BotState>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let member = &msg.new_chat_member.user;
    let user_id = member.id.0 as i64;
    let user_name = member.username.clone().unwrap_or(member.first_name.clone());
    tracing::Span::current().record("user_id", user_id);

    info!("New member joined: {}", user_id);

    let state_guard = state.lock().await;
    let welcome_message = &state_guard.config.welcome_message.clone();

    // Restrict user permissions
    match bot
        .restrict_chat_member(
            msg.chat.id,
            UserId(user_id as u64),
            ChatPermissions::empty(),
        )
        .await
    {
        Ok(_) => info!("Restricted permissions for new user {}", user_id),
        Err(e) => error!("Failed to restrict permissions for user {}: {}", user_id, e),
    }

    // Send welcome message to new member
    match bot
        .send_message(msg.chat.id, welcome_message.replace("{}", &user_name))
        .await
    {
        Ok(_) => info!("Sent welcome message to user {}", user_id),
        Err(e) => {
            error!("Failed to send welcome message to user {}: {}", user_id, e);
        }
    }

    Ok(())
}

async fn handle_registration(
    bot: Bot,
    msg: Message,
    state: Arc<Mutex<BotState>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if let Some(user_id) = msg.from.clone() {
        let user_id = user_id.id.0 as i64;
        tracing::Span::current().record("user_id", user_id);
        let mut state_guard = state.lock().await;
        let surname_request = &state_guard.config.surname_request.clone();
        let code_request = &state_guard.config.code_request.clone();
        let code_error = &state_guard.config.code_error.clone();
        let success_message = &state_guard.config.success_message.clone();
        let general_error = &state_guard.config.general_error.clone();
        let empty_error = &state_guard.config.empty_error.clone();
        let too_long_error = &state_guard.config.too_long_error.clone();
        let invalid_type_error = &state_guard.config.invalid_type_error.clone();
        let not_number_error = &state_guard.config.not_number_error.clone();
        let data_collection_notice = &state_guard.config.data_collection_notice.clone();
        let name_request = &state_guard.config.name_request.clone();

        if !state_guard.registration_states.contains_key(&user_id) {
            state_guard
                .registration_states
                .insert(user_id, RegistrationState::AwaitingName);
            match bot
                .send_message(ChatId(user_id), data_collection_notice)
                .await
            {
                Ok(_) => info!("Sent data collection message to user {}", user_id),
                Err(e) => {
                    error!(
                        "Failed to send data collection message to user {}: {}",
                        user_id, e
                    );
                    return Ok(());
                }
            }
            if let Err(e) = bot.send_message(ChatId(user_id), name_request).await {
                error!("Failed to request name from user {}: {}", user_id, e);
            }
        } else if let Some(text) = msg.text() {
            match sanitize_input(text) {
                Ok(text) => {
                    info!("Sanitized input: {}", text);
                    match state_guard.registration_states.get(&user_id) {
                        Some(RegistrationState::AwaitingName) => {
                            info!("Processing name for user {}", user_id);
                            state_guard.user_data.insert(
                                user_id,
                                UserData {
                                    name: text.to_string(),
                                    surname: String::new(),
                                    registration_code: None,
                                    is_registered: false,
                                    user_id,
                                },
                            );
                            state_guard
                                .registration_states
                                .insert(user_id, RegistrationState::AwaitingSurname);

                            if let Err(e) = bot.send_message(ChatId(user_id), surname_request).await
                            {
                                error!("Failed to request surname from user {}: {}", user_id, e);
                            }
                        }
                        Some(RegistrationState::AwaitingSurname) => {
                            info!("Processing surname for user {}", user_id);
                            // Store surname and ask for registration code
                            if let Some(user_data) = state_guard.user_data.get_mut(&user_id) {
                                user_data.surname = text.to_string();
                            }
                            state_guard
                                .registration_states
                                .insert(user_id, RegistrationState::AwaitingCode);

                            if let Err(e) = bot.send_message(ChatId(user_id), code_request).await {
                                error!(
                                    "Failed to request registration code from user {}: {}",
                                    user_id, e
                                );
                            }
                        }
                        Some(RegistrationState::AwaitingCode) => {
                            info!("Processing registration code for user {}", user_id);
                            // Validate registration code
                            if state_guard.user_data.contains_key(&user_id)
                                && state_guard
                                    .user_data
                                    .get(&user_id)
                                    .unwrap()
                                    .registration_code
                                    .is_none()
                            {
                                info!("Valid registration code provided by user {}", user_id);
                                let user_data = state_guard.user_data.get_mut(&user_id).unwrap();
                                if let Ok(parsed_code) = text.parse::<u64>() {
                                    user_data.registration_code = Some(parsed_code);
                                    user_data.is_registered = true;
                                    if save_user(user_data.clone()).is_err() {
                                        error!("Failed to save user {}", user_id);
                                        if let Err(e) =
                                            bot.send_message(ChatId(user_id), general_error).await
                                        {
                                            error!(
                                            "Failed to send general error message to user {}: {}",
                                            user_id, e
                                        );
                                        }
                                    }
                                    state_guard
                                        .registration_states
                                        .insert(user_id, RegistrationState::Completed);

                                    // Grant privileges
                                    match bot
                                        .restrict_chat_member(
                                            ChatId(state_guard.config.group_chat_id),
                                            UserId(user_id as u64),
                                            get_user_privileges(),
                                        )
                                        .await
                                    {
                                        Ok(_) => info!(
                                            "Updated permissions for registered user {}",
                                            user_id
                                        ),
                                        Err(e) => error!(
                                            "Failed to update permissions for user {}: {}",
                                            user_id, e
                                        ),
                                    }

                                    if let Err(e) =
                                        bot.send_message(ChatId(user_id), success_message).await
                                    {
                                        error!(
                                            "Failed to send completion message to user {}: {}",
                                            user_id, e
                                        );
                                    }
                                } else {
                                    warn!("User sent not number registration code {}", user_id);
                                    if let Err(e) =
                                        bot.send_message(ChatId(user_id), not_number_error).await
                                    {
                                        error!(
                                            "Failed to send not number error message to user {}: {}",
                                            user_id, e
                                        );
                                    }
                                }
                            } else {
                                warn!("Invalid registration code attempt by user {}", user_id);
                                if let Err(e) = bot.send_message(ChatId(user_id), code_error).await
                                {
                                    error!(
                                        "Failed to send invalid code message to user {}: {}",
                                        user_id, e
                                    );
                                }
                            }
                        }
                        _ => {
                            warn!("Received message from user {} in unknown state", user_id);
                        }
                    }
                }
                Err(ValidationError::Empty) => {
                    if let Err(e) = bot.send_message(ChatId(user_id), empty_error).await {
                        error!(
                            "Failed to send empty error message to user {}: {}",
                            user_id, e
                        );
                    }
                    warn!("Received empty message from user {}", user_id);
                }
                Err(ValidationError::TooLong) => {
                    if let Err(e) = bot.send_message(ChatId(user_id), too_long_error).await {
                        error!(
                            "Failed to send too long error message to user {}: {}",
                            user_id, e
                        );
                    }
                    warn!("Received too long message from user {}", user_id);
                }
            }
        } else {
            if let Err(e) = bot.send_message(ChatId(user_id), invalid_type_error).await {
                error!(
                    "Failed to send invalid type message to user {}: {}",
                    user_id, e
                );
            }
            warn!("Received invalid message type from user {}", user_id);
        }
    } else {
        warn!("Received message from unknown user");
    }

    Ok(())
}
pub enum ValidationError {
    Empty,
    TooLong,
}
pub fn sanitize_input(input: &str) -> Result<String, ValidationError> {
    const MAX_LENGTH: usize = 100;
    let sanitized: String = input
        .chars()
        .filter(|&c| (!c.is_control() && c != ',') || c == ' ')
        .collect();
    let trimmed = sanitized.trim();
    if trimmed.is_empty() {
        return Err(ValidationError::Empty);
    }
    if trimmed.len() > MAX_LENGTH {
        return Err(ValidationError::TooLong);
    }
    Ok(sanitized)
}

fn get_user_privileges() -> ChatPermissions {
    let mut permissions = ChatPermissions::empty();
    permissions.insert(ChatPermissions::SEND_MESSAGES);
    permissions.insert(ChatPermissions::SEND_OTHER_MESSAGES);
    permissions.insert(ChatPermissions::SEND_MEDIA_MESSAGES);
    permissions.insert(ChatPermissions::SEND_POLLS);
    permissions.insert(ChatPermissions::ADD_WEB_PAGE_PREVIEWS);
    permissions.insert(ChatPermissions::INVITE_USERS);
    permissions
}
fn save_user(user_data: UserData) -> Result<(), ()> {
    let file_exists = Path::new(USERS_FILE).exists();
    let mut header_exists = false;
    if file_exists {
        if let Ok(file) = File::open(USERS_FILE) {
            let reader = BufReader::new(file);
            if let Some(Ok(line)) = reader.lines().next() {
                if line.contains("user_id") {
                    header_exists = true;
                }
            }
        }
    }
    let file = OpenOptions::new()
        .append(true)
        .create(true)
        .open(USERS_FILE)
        .map_err(|_| ())?;
    let mut writer = WriterBuilder::new().has_headers(false).from_writer(file);
    if !header_exists {
        writer
            .write_record([
                "name",
                "surname",
                "registration_code",
                "is_registered",
                "user_id",
            ])
            .map_err(|_| ())?;
    }
    writer.serialize(user_data.clone()).map_err(|_| ())?;
    writer.flush().map_err(|_| ())?;
    info!("Saved user {} to file", user_data.user_id);
    Ok(())
}
