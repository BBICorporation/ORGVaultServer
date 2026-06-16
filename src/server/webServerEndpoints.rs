use crate::{security, server};
use actix_web::HttpResponse;
use actix_web::web;
use colored::*;
use serde::Deserialize;
use serde_json::json;
use std::{fs, io::Read, sync::atomic};
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
        return HttpResponse::NotImplemented().finish();
    }
}

// Handling initialize server endpoint
pub async fn HandleInitializeServerEndpoint(
    req: web::Json<crate::SCFAdminDetails>,
) -> HttpResponse {
    // Safely extract headers without unwrapping
    let MAC_ADDRESS = &req.macAddress;
    let USERNAME = &req.username;
    let PASSWORD = &req.password;

    // Format checking
    if MAC_ADDRESS == "" || !crate::MAC_ADDRESS_FORMAT.is_match(MAC_ADDRESS) {
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
    match server::InitializeConfigFile(MAC_ADDRESS.clone(), USERNAME.clone(), PASSWORD.clone()) {
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

// Handling verify admin mac endpoint
#[derive(Deserialize)]
pub struct VerifyAdminMacRequest {
    adminMacAddress: String,
    keyBinHash: String,
}

pub async fn HandleVerifyAdminMacEndpoint(req: web::Json<VerifyAdminMacRequest>) -> HttpResponse {
    // Safely extract headers without unwrapping
    let MAC_ADDRESS = &req.adminMacAddress;
    let KEY_BIN_HASH = &req.keyBinHash;

    // Format checking
    if MAC_ADDRESS == "" || !crate::MAC_ADDRESS_FORMAT.is_match(MAC_ADDRESS) {
        return HttpResponse::Unauthorized().json(json!({"response": "Invalid admin mac address"}));
    }

    // Verifying hash
    let ACTUAL_KEY_BIN_HASH = match security::encryptionHandler::ConfigEncryptionKeyHash() {
        Ok(hash) => hash,
        Err(E) => {
            println!(
                "{0} {1:?}",
                "Verify Admin Mac Address Endpoint Error (ACTUAL_KEY_BIN_HASH) | HandleVerifyAdminMacEndpoint | E:():  ".red(),
                E
            );
            return HttpResponse::InternalServerError()
                .json(json!({"response": "Internal Server Error"}));
        }
    };

    if KEY_BIN_HASH != &ACTUAL_KEY_BIN_HASH {
        return HttpResponse::Unauthorized().json(json!({"response": "Invalid key bin hash"}));
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
    if &DECRYPTED_DATA.adminDetails.macAddress != MAC_ADDRESS {
        return HttpResponse::Unauthorized().json(json!({"response": "Invalid admin mac address"}));
    }

    // Return
    HttpResponse::Ok().finish()
}

// Handling login verification endpoint
pub async fn HandleLoginVerificationEndpoint(
    req: web::Json<crate::SCFAdminDetails>,
) -> HttpResponse {
    // Safely extract headers without unwrapping
    let MAC_ADDRESS = &req.macAddress;
    let USERNAME = &req.username;
    let PASSWORD = &req.password;

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
    if &DECRYPTED_DATA.adminDetails.macAddress != MAC_ADDRESS {
        return HttpResponse::Unauthorized().json(json!({"response": "Invalid credentials"}));
    }

    // Checking if username is valid
    if &DECRYPTED_DATA.adminDetails.username != USERNAME {
        return HttpResponse::Unauthorized().json(json!({"response": "Invalid credentials"}));
    }

    // Checking if password is valid
    if &DECRYPTED_DATA.adminDetails.password != PASSWORD {
        return HttpResponse::Unauthorized().json(json!({"response": "Invalid credentials"}));
    }

    // Return
    HttpResponse::Ok().finish()
}
