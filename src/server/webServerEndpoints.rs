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
#[derive(Deserialize)]
pub struct InitializeRequest {
    adminMacAddress: String,
    username: String,
    password: String,
}

pub async fn HandleInitializeServerEndpoint(req: web::Json<InitializeRequest>) -> HttpResponse {
    // Safely extract headers without unwrapping
    let MAC_ADDRESS = &req.adminMacAddress;
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
        Err(e) => {
            println!(
                "{0} {1:?}",
                "Initialize Server Endpoint Error | HandleInitializeServerEndpoint | e:std::io::Error:  ".red(),
                e
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

    // Verifying admin mac
    let mut configFile: fs::File = match fs::File::open(&*crate::GLOBAL_PROGRAM_CONFIG_FILE) {
        Ok(FILE) => FILE,
        Err(E) => {
            println!(
                "{0} {1:?}",
                "Verify Admin Mac Address Endpoint Error (configFile) | HandleVerifyAdminMacEndpoint | E:std::io::Error:  ".red(),
                E
            );
            return HttpResponse::InternalServerError()
                .json(json!({"response": "Internal Server Error"}));
        }
    };
    let mut keyFile: fs::File = match fs::File::open(&*crate::GLOBAL_ENCRYPTION_KEY_FILE_LOCATION) {
        Ok(FILE) => FILE,
        Err(E) => {
            println!(
                "{0} {1:?}",
                "Verify Admin Mac Address Endpoint Error (keyFile) | HandleVerifyAdminMacEndpoint | E:std::io::Error:  ".red(),
                E
            );
            return HttpResponse::InternalServerError()
                .json(json!({"response": "Internal Server Error"}));
        }
    };

    let mut configFileDataBuffer = Vec::new();
    let _ = configFile.read_to_end(&mut configFileDataBuffer);

    let mut keyFileDataBuffer = Vec::new();
    let _ = keyFile.read_to_end(&mut keyFileDataBuffer);

    // Decrypting data
    let DECRYPTED_DATA: Vec<u8> = match security::encryptionHandler::DecryptData(
        &configFileDataBuffer,
        &keyFileDataBuffer,
    ) {
        Ok(DATA) => DATA,
        Err(E) => {
            println!(
                    "{0} {1:?}",
                    "Verify Admin Mac Address Endpoint Error (DECRYPTED_DATA: Vec<u8>) | HandleVerifyAdminMacEndpoint | E:std::io::Error:  ".red(),
                    E
                );
            return HttpResponse::InternalServerError()
                .json(json!({"response": "Internal Server Error"}));
        }
    };

    let DECRYPTED_DATA: crate::ServerConfigFile = match serde_json::from_slice(&DECRYPTED_DATA) {
        Ok(DATA) => DATA,
        Err(E) => {
            println!(
                "{0} {1:?}",
                "Verify Admin Mac Address Endpoint Error (DECRYPTED_DATA: crate::ServerConfigFile) | HandleVerifyAdminMacEndpoint | E:serde_json::Error:  ".red(),
                E
            );
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
