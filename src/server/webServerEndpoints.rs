use crate::security::encryptionHandler;
use crate::{security, server};
use actix_web::HttpResponse;
use actix_web::web;
use colored::*;
use serde::Deserialize;
use serde_json::json;
use std::sync::atomic;
use tokio::time::Instant;

// Handling ping endpoint
pub async fn HandlePingEndpoint() -> HttpResponse {
    let START = Instant::now();
    let RESPONSE_TIME_MS = START.elapsed().as_millis();

    HttpResponse::Ok().json(json!({
        "message": "pong",
        "RESPONSE_TIME_MS": RESPONSE_TIME_MS
    }))
}

// Handling initialized status endpoint
pub async fn HandleInitializedStatusEndpoint() -> HttpResponse {
    if crate::isInitialized.load(atomic::Ordering::SeqCst) {
        return HttpResponse::Ok().finish();
    } else {
        return HttpResponse::NoContent().finish();
    }
}

// Handling initialize server endpoint
#[derive(Deserialize)]
pub struct SCFAdminDetailsExtendedFLNR {
    #[serde(flatten)]
    admin: crate::SCFAdminDetails,
    pub keyBinHash: String,
}
pub async fn HandleInitializeServerEndpoint(
    req: web::Json<SCFAdminDetailsExtendedFLNR>,
) -> HttpResponse {
    // Safely extract headers without unwrapping
    let NAME = &req.admin.name;
    let MAC_ADDRESS = &req.admin.macAddress;
    let USERNAME = &req.admin.username;
    let PASSWORD = &req.admin.password;
    let KEY_BIN_HASH = &req.keyBinHash;

    // Verifying hash
    if let Ok(ACTUAL_KEY_BIN_HASH) = security::encryptionHandler::ConfigEncryptionKeyHash() {
        if KEY_BIN_HASH != &ACTUAL_KEY_BIN_HASH {
            return HttpResponse::Unauthorized().json(json!({"response": "Invalid key bin hash"}));
        }
    }

    // Format checking
    if NAME == "" {
        return HttpResponse::Unauthorized().json(json!({"response": "Name cannot be empty"}));
    }
    if MAC_ADDRESS == "" || !crate::MAC_ADDRESS_FORMAT.is_match(&MAC_ADDRESS) {
        return HttpResponse::Unauthorized().json(json!({"response": "Invalid admin mac address"}));
    }
    if (USERNAME == "") || (USERNAME.contains(' ')) {
        return HttpResponse::Unauthorized()
            .json(json!({"response": "Username cannot contain spaces"}));
    }
    if PASSWORD == "" {
        return HttpResponse::Unauthorized().json(json!({"response": "Password cannot be empty"}));
    }

    // Initialize config file
    match server::InitializeConfigFile(NAME, MAC_ADDRESS, USERNAME, PASSWORD) {
        Ok(_) => return HttpResponse::Ok().finish(),
        Err(E) => {
            println!(
                "{0} {1:?}",
                "Initialize Server Endpoint Error | HandleInitializeServerEndpoint:  ".red(),
                E
            );
            return HttpResponse::InternalServerError().finish();
        }
    };
}

// Handling login verification endpoint
pub async fn HandleLoginVerificationEndpoint(
    req: web::Json<SCFAdminDetailsExtendedFLNR>,
) -> HttpResponse {
    // Safely extract headers without unwrapping
    let MAC_ADDRESS = &req.admin.macAddress;
    let USERNAME = &req.admin.username;
    let PASSWORD = &req.admin.password;
    let KEY_BIN_HASH = &req.keyBinHash;

    // Verifying hash
    if let Ok(ACTUAL_KEY_BIN_HASH) = security::encryptionHandler::ConfigEncryptionKeyHash() {
        if KEY_BIN_HASH != &ACTUAL_KEY_BIN_HASH {
            return HttpResponse::Unauthorized().json(json!({"response": "Invalid key bin hash"}));
        }
    }

    // Format checking
    if MAC_ADDRESS == "" || !crate::MAC_ADDRESS_FORMAT.is_match(MAC_ADDRESS) {
        return HttpResponse::Unauthorized().json(json!({"response": "Invalid admin mac address"}));
    }

    // Decrypting data
    let DECRYPTED_DATA: crate::ServerConfigFile = match security::encryptionHandler::DecryptData() {
        Ok(DATA) => DATA,
        Err(_) => {
            return HttpResponse::InternalServerError()
                .json(json!({"response": "Internal Server Error"}));
        }
    };

    // Checking if admin mac is valid
    for i in 0..DECRYPTED_DATA.adminDetails.len() {
        if &DECRYPTED_DATA.adminDetails[i].macAddress != MAC_ADDRESS {
            return HttpResponse::Unauthorized().json(json!({"response": "Invalid credentials"}));
        }

        // Checking if username is valid
        if &DECRYPTED_DATA.adminDetails[i].username != USERNAME {
            return HttpResponse::Unauthorized().json(json!({"response": "Invalid credentials"}));
        }

        // Checking if password is valid
        if &DECRYPTED_DATA.adminDetails[i].password != PASSWORD {
            return HttpResponse::Unauthorized().json(json!({"response": "Invalid credentials"}));
        }
    }

    // Return
    HttpResponse::Ok().finish()
}

pub async fn HandleDeveloperSeeConfigFileEndpoint() -> HttpResponse {
    if !cfg!(debug_assertions) {
        return HttpResponse::Unauthorized().finish();
    }

    if let Ok(data) = encryptionHandler::DecryptData() {
        return HttpResponse::Ok().json(json!(data));
    }

    if let Err(E) = encryptionHandler::DecryptData() {
        return HttpResponse::InternalServerError().json(json!({"response": E.to_string()}));
    }

    HttpResponse::NotImplemented().finish()
}
