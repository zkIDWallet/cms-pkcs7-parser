# pkcs7-parser-rs

Rust parser for PKCS#7 / CMS signed data structures.  
This library is used to extract and deserialize cryptographic information from `.p7b` or `.p7s` files, and is currently employed in the [`zkID_Wallet`](https://github.com/zkid-org/zkID_Wallet) project.

---

## 📦 About

This crate provides a low-level parser for files encoded using **PKCS#7 (Public-Key Cryptography Standards #7)**, now formally known as **Cryptographic Message Syntax (CMS)** as defined in [RFC 5652](https://datatracker.ietf.org/doc/html/rfc5652).

Although **CMS is the current standard**, the term **PKCS#7** is still widely used in practical contexts and tooling (e.g., `.p7b` or `.pkcs7` file extensions), and therefore we keep this naming convention for familiarity and clarity.

The goal of this parser is to extract raw signed data, certificates, CRLs, and signer metadata in a structured and reusable way — suitable for further cryptographic processing, such as signature verification or identity attestation in zero-knowledge systems.

---

## 🔍 Extracted Structures

Given a `.p7b` file, the parser decodes several nested structures including:

- `Pkcs7`: Root container (with content type and signed data)
- `SignedData`: Core structure with digest algorithms, content, certificates and CRLs
- `Certificate`, `TbsCertificate`: X.509 certificate parsing
- `CertificateList`, `TbsCertList`: CRL (Certificate Revocation List) parsing
- `SignerInfo`, `SignerIdentifier`: Signer metadata
- `Attribute`, `Extension`, `AlgorithmIdentifier`, `Name` structures
- Optimized structs (`CertificateData`, `CrlData`) are also provided for serialization (e.g., for sending to guest code in zkVM environments).

### Example extracted struct (simplified):
```rust
#[derive(Debug)]
pub struct Pkcs7 {
    pub content_type: Oid,
    pub content: SignedData,
    pub content_bytes: Vec<u8>,
}
```

--- 

## 🔗 Used in zkID_Wallet

This library was originally developed as part of [`zkCF_Wallet`](https://github.com/paolo9921/zkCF_Wallet), a university thesis project focused on digital identity and zero-knowledge proof integration.

It is now a standalone component of the more advanced [`zkID_Wallet`](https://github.com/zkid-org/zkID_Wallet), a modular and privacy-preserving identity wallet that leverages zero-knowledge cryptography to prove identity attributes without revealing them.

