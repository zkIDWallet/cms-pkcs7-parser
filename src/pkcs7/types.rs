use bcder::Oid;
use serde::{Deserialize, Serialize};

#[derive(Debug)]
pub struct Pkcs7 {
    pub content_type: Oid,
    pub content: SignedData,
    pub content_bytes: Vec<u8>,
}

#[derive(Debug)]
pub struct SignedData {
    pub version: u8,
    pub digest_algorithms: Vec<AlgorithmIdentifier>,
    pub content_info: ContentInfo,
    pub certs: Vec<Certificate>,
    pub crls: Vec<CertificateList>,
    pub signer_infos: Vec<SignerInfo>, // Multiple SignerInfo structures
}

#[derive(Debug)]
pub struct ContentInfo {
    pub content_type: Oid,
    pub e_content: Vec<u8>, // Encapsulated content, present if doc sigend with -nodetach option
}

#[derive(Debug)]
pub struct CertificateList {
    pub tbs_cert_list: TbsCertList,
    pub signature_algorithm: AlgorithmIdentifier,
    pub signature: Vec<u8>,
}

//Optimized struct to send to guest code for verification
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CrlData {
    pub issuer: Vec<u8>,              // Issuer name in DER format
    pub this_update: u64,
    pub next_update: Option<u64>,
    pub revoked_serials: Vec<String>, // List of revoked certificate serial numbers
    pub signature: Vec<u8>,           // CRL signature
    pub tbs_bytes: Vec<u8>,           // To-be-signed CRL bytes for signature verification
    pub issuer_pk: PublicKey,         // Public key of the CRL issuer
}

#[derive(Debug)]
pub struct TbsCertList {
    pub tbs_bytes: Vec<u8>,
    pub version: Option<u8>,
    pub signature: AlgorithmIdentifier,
    pub issuer: Name,
    pub this_update: u64,
    pub next_update: Option<u64>,
    pub revoked_certificates: Vec<RevokedCertificate>,
}

#[derive(Debug)]
pub struct RevokedCertificate {
    pub serial_number: String,
    pub revocation_date: u64,
    pub crl_entry_extensions: Option<Vec<Extension>>,
}

#[derive(Debug)]
pub struct Extension {
    pub extn_id: Oid,
    pub critical: bool,
    pub extn_value: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct SignerInfo {
    pub version: u8,
    pub signer_identifier: SignerIdentifier,
    //pub issuer_and_serial_number: IssuerAndSerialNumber,
    pub digest_algorithm: AlgorithmIdentifier,
    pub auth_attributes: Option<Vec<Attribute>>, // Optional field
    pub auth_bytes: Vec<u8>,
    pub signature_algorithm: AlgorithmIdentifier,
    pub signature: Vec<u8>, // The actual signature (Encrypted digest)
    //pub unauthenticated_attributes: Option<AuthenticatedAttributes>, // Optional field
}

#[derive(Debug, Clone)]
pub struct SignerIdentifier {
    pub issuer: Name,
    pub serial_number: String, //hex
}

/*
#[derive(Debug)]
pub struct IssuerAndSerialNumber {
    pub issuer: Vec<RelativeDistinguishedName>,
    pub serial_number: Vec<u8>,
}*/

#[derive(Debug, Clone)]
pub struct Name {
    pub rdn_sequence: Vec<RelativeDistinguishedName>,
    pub name_bytes: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct RelativeDistinguishedName {
    pub attribute: Attribute,
}

/*
#[derive(Debug)]
pub struct AuthenticatedAttributes {
    //pub auth_attr_bytes: Vec<u8>,
    pub attributes: Vec<Attribute>,
}*/

#[derive(Debug, Clone)]
pub struct Attribute {
    pub oid: Oid,
    pub value: Vec<u8>,
}

#[derive(Debug)]

pub struct Certificate {
    pub tbs_certificate: TbsCertificate,
    pub signature_algorithm: AlgorithmIdentifier,
    pub signature_value: Vec<u8>,
}

//optimized struct for guest verification
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CertificateData {
    pub subject: Vec<u8>,
    pub issuer: Vec<u8>,
    pub issuer_pk: PublicKey,
    pub signature: Vec<u8>,
    pub tbs_bytes: Vec<u8>,
    pub serial_number: String,
    pub not_before: u64,
    pub not_after: u64,
}

#[derive(Debug, Clone)]
pub struct TbsCertificate {
    pub tbs_bytes: Vec<u8>,
    pub version: Option<u8>,
    pub serial_number: String,
    pub signature_algorithm: AlgorithmIdentifier,
    pub issuer: Name,
    pub validity: Validity,
    pub subject: Name,
    pub subject_public_key_info: SubjectPublicKeyInfo,
}

#[derive(Debug, Clone)]
pub struct AlgorithmIdentifier {
    pub algorithm: Oid,
    pub parameters: Vec<u8>, // Optional parameters
}

#[derive(Debug, Clone)]
pub struct Validity {
    pub not_before: u64,
    pub not_after: u64,
}

#[derive(Debug, Clone)]
pub struct SubjectPublicKeyInfo {
    pub algorithm: AlgorithmIdentifier,
    pub subject_public_key: PublicKey,
    //pub exp: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PublicKey {
    Rsa { modulus: Vec<u8>, exponent: Vec<u8> },
    Ecdsa { point: Vec<u8> },
}