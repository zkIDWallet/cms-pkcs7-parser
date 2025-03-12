use cms_pkcs7_parser::pkcs7::*;
use std::fs;

    #[test]
    fn test_der_parsing() {
        
        let test_file = "tests/test_files/ecdsa_1KB.p7m";
        let content = fs::read(test_file).expect("Failed to read test file");

        let result = load_pkcs7(&content);
        assert!(result.is_ok(), "Failed to parse DER: {:?}", result.err());
    }

    #[test]
    fn test_detect_format() {
        let test_file_der = "tests/test_files/ecdsa_1KB.p7m";
        let test_file_pem = "tests/test_files/ecdsa_1KB.pem";
        
        let der_content = fs::read(test_file_der).expect("Failed to read DER test file");
        let pem_content = fs::read(test_file_pem).expect("Failed to read PEM test file");
        
        assert!(matches!(detect_format(&der_content), Ok(Pkcs7Format::DER)));
        assert!(matches!(detect_format(&pem_content), Ok(Pkcs7Format::PEM)));
    }

    #[test]
    fn test_load_from_path() {
        let test_file = "tests/test_files/ecdsa_1KB.p7m";
        let result = load_pkcs7(test_file);
        assert!(result.is_ok(), "Failed to load from path: {:?}", result.err());
    }

    #[test]
    fn test_load_from_bytes() {
        let test_file = "tests/test_files/ecdsa_1KB.p7m";
        let content = fs::read(test_file).expect("Failed to read test file");
        let result = load_pkcs7(content);
        assert!(result.is_ok(), "Failed to load from bytes: {:?}", result.err());
    }

    #[test]
    fn test_pem_parsing() {
        let test_file = "tests/test_files/ecdsa_1KB.pem";
        let content = fs::read(test_file).expect("Failed to read test file");
        let result = load_pkcs7(&content);
        assert!(result.is_ok(), "Failed to parse PEM: {:?}", result.err());
    }

    /*
    // Helper function to print signature details for debugging
    fn debug_signature(signature_bytes: &[u8]) {
        println!("Signature length: {}", signature_bytes.len());
        println!("First few bytes: {:?}", &signature_bytes[..std::cmp::min(10, signature_bytes.len())]);
        if signature_bytes.len() >= 2 {
            println!("ASN.1 length byte: {}", signature_bytes[1]);
        }
    }*/
