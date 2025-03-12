// src/pkcs7/utils.rs
use crate::pkcs7::types::Pkcs7;
use std::fs;
use std::path::Path;
use bcder::Mode;
use bcder::decode::{Constructed, IntoSource};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;


#[derive(Debug)]
pub enum Pkcs7Format {
    PEM,
    DER
}

/// Load PKCS#7 data either from a file path or from raw bytes
pub fn load_pkcs7<T: AsRef<[u8]>>(input: T) -> Result<Pkcs7, Box<dyn std::error::Error>> {
    let content = if let Ok(path_str) = String::from_utf8(input.as_ref().to_vec()) {
        if Path::new(&path_str).exists() {
            // If input is a valid path, read the file
            fs::read(path_str)?
        } else {
            // If input is not a path, treat it as raw bytes
            input.as_ref().to_vec()
        }
    } else {
        // If input is not valid UTF-8, treat it as raw bytes
        input.as_ref().to_vec()
    };

    // Detect format and parse accordingly
    let format = detect_format(&content).unwrap();
    parse_pkcs7_content(&content, format)
}

/// Detect if the content is PEM or DER format
pub fn detect_format(content: &[u8]) -> Result<Pkcs7Format, Box<dyn std::error::Error>> {
    // Check if content starts with PEM header
    if content.starts_with(b"-----BEGIN") {
        Ok(Pkcs7Format::PEM)
    } 
    // DER ASN1 Sequences starts with byte 0x30
    else if !content.is_empty() && content[0] == 0x30 { 
        Ok(Pkcs7Format::DER)
    }
    else {
        Err("Wrong Format!".into())
    }
}

/// Parse PKCS#7 content based on detected format
fn parse_pkcs7_content(content: &[u8], format: Pkcs7Format) -> Result<Pkcs7, Box<dyn std::error::Error>> {
    match format {
        Pkcs7Format::PEM => parse_pem(content),
        Pkcs7Format::DER => parse_der(content),
    }
}




/// Parse PEM formatted PKCS#7 data
fn parse_pem(content: &[u8]) -> Result<Pkcs7, Box<dyn std::error::Error>> {
    // Convert content to string for PEM processing
    let content_str = String::from_utf8(content.to_vec())?;
    
    // Find the PEM boundaries
    let start_marker = "-----BEGIN PKCS7-----";
    let end_marker = "-----END PKCS7-----";
    
    let start = content_str.find(start_marker)
        .ok_or("Invalid PEM: missing start marker")?;
    let end = content_str.find(end_marker)
        .ok_or("Invalid PEM: missing end marker")?;
    
    // Extract the base64 content
    let base64_content = content_str[start + start_marker.len()..end]
        .replace('\n', "")
        .replace('\r', "");
    
    // Decode base64 to get DER bytes
    let der_bytes = BASE64.decode(base64_content.trim())?;
    
    // Parse the DER content
    parse_der(&der_bytes)
}

/// Parse DER formatted PKCS#7 data
fn parse_der(content: &[u8]) -> Result<Pkcs7, Box<dyn std::error::Error>> {
    let source = content.into_source();
    let pkcs7 = Constructed::decode(source, Mode::Der, |constructed| {
        Pkcs7::take_from(constructed)
    }).map_err(|e| format!("Failed to decode DER: {}", e))?;

    Ok(pkcs7)
}

/*
/// Log parsing information (useful for debugging)
fn log_parsing_info(format: &Pkcs7Format, content: &[u8]) {
    println!(
        "Parsing PKCS#7 data: format={:?}, size={} bytes",
        format,
        content.len()
    );
}*/