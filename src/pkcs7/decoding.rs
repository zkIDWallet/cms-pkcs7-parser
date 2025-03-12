use crate::pkcs7::*;

use bcder::decode::IntoSource;
use bcder::decode::{self, Constructed, DecodeError, ContentError};
use bcder::{Mode, Oid, Tag};
use chrono::{NaiveDateTime, TimeZone, Utc};
use hex;
use std::fmt;


const ECDSA_OID_BYTES: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01];
const ECDSA_SIGN_OID_BYTES: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02];
const RSA_OID_BYTES: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01];


impl Pkcs7 {
    pub fn take_from<S: decode::Source>(
        cons: &mut Constructed<S>,
    ) -> Result<Self, DecodeError<S::Error>> {
        cons.take_sequence(|cons| {
            let content_type = Oid::take_from(cons)?;

            let content_captured = cons.capture_all()?;
            let mut content_bytes = content_captured.as_slice().to_vec();
            content_bytes.drain(0..4); //remove tag and lenght bytes

            let content_source = content_captured.into_source();

            let content = Constructed::decode(content_source, Mode::Ber, |cons| {
                let content_parsed =
                    cons.take_constructed_if(Tag::CTX_0, |cons| SignedData::take_from(cons))?;
                Ok(content_parsed)
            })
            .expect("failed to parse content");

            Ok(Pkcs7 {
                content_type,
                content,
                content_bytes,
            })
        })
    }

    pub fn to_string(&self) -> String {
        format!(
            "Pkcs7 {{\n  content_type: {},\n  content: {}\n}}",
            self.content_type.to_string(),
            self.content.to_string(),
        )
    }
}

impl SignedData {
    pub fn take_from<S: decode::Source>(
        cons: &mut Constructed<S>,
    ) -> Result<Self, DecodeError<S::Error>> {
        cons.take_sequence(|cons| {
            let version = cons.take_primitive_if(Tag::INTEGER, |content| content.to_u8())?;
            let digest_algorithms = cons.take_set(|cons| {
                let mut algorithms = Vec::new();
                while let Ok(algorithm) = AlgorithmIdentifier::take_from(cons) {
                    algorithms.push(algorithm);
                }
                Ok(algorithms)
            })?;
            let content_info = ContentInfo::take_from(cons)?;

            let certs = cons.take_constructed_if(Tag::CTX_0, |cons| {
                let mut certificates = Vec::new();
                while let Ok(cert) = Certificate::take_from(cons) {
                    certificates.push(cert);
                }
                Ok(certificates)
            })?;
            
            let crls = if let Ok(crl_list) = cons.take_constructed_if(Tag::CTX_1, |cons| {
                let mut crl_list = Vec::new();
                while let Ok(crl) = CertificateList::take_from(cons) {
                    crl_list.push(crl);
                }
                Ok(crl_list)
            }) {
                crl_list
            } else {
                Vec::new()
            };

            let signer_infos = cons.take_set(|cons| {
                let mut signers = Vec::new();
                while let Ok(signer) = SignerInfo::take_from(cons) {
                    signers.push(signer);
                }
                Ok(signers)
            })?;

            Ok(SignedData {
                version,
                digest_algorithms,
                content_info,
                certs,
                crls, 
                signer_infos,
            })
        })
    }

    pub fn to_string(&self) -> String {
        format!(
            "SignedData {{\n  version: {},\n  content_info: {},\n  number of certs: {},\n  number of CRLs: {},\n  signer_infos: {}\n}}",
            self.version,
            self.content_info.to_string(),
            self.certs.len(),
            self.crls.len(),
            self.signer_infos
                .iter()
                .map(|s| s.to_string())
                .collect::<String>(),
        )
    }
}



impl CertificateList {
    pub fn take_from<S: decode::Source>(
        cons: &mut Constructed<S>,
    ) -> Result<Self, DecodeError<S::Error>> {
        cons.take_sequence(|cons| {


            let tbs_cert_list = TbsCertList::take_from(cons)?;
            let signature_algorithm = AlgorithmIdentifier::take_from(cons)?;
            let signature = cons.take_value(|_, content| {
                let sign = content.as_primitive()?.slice_all()?.to_vec();
                _ = content.as_primitive()?.skip_all();
                Ok(sign)
            })?;

            Ok(CertificateList {
                tbs_cert_list,
                signature_algorithm,
                signature,
            })
        })
    }

    pub fn extract_data(&self, issuer_cert: &Certificate) -> CrlData {
        let revoked_serials: Vec<String> = self.tbs_cert_list.revoked_certificates
            .iter()
            .map(|cert| cert.serial_number.clone())
            .collect();

        CrlData {
            issuer: self.tbs_cert_list.issuer.to_der(),
            this_update: self.tbs_cert_list.this_update,
            next_update: self.tbs_cert_list.next_update,
            revoked_serials,
            signature: self.signature.clone(),
            tbs_bytes: self.tbs_cert_list.tbs_bytes.clone(),
            issuer_pk: issuer_cert.tbs_certificate.subject_public_key_info.subject_public_key.clone(),
        }
    }
}

impl TbsCertList {
    pub fn take_from<S: decode::Source>(
        cons: &mut Constructed<S>,
    ) -> Result<Self, DecodeError<S::Error>> {
        let tbs_captured = cons.capture_one()?;
        let tbs_bytes = tbs_captured.as_slice().to_vec();
        let tbs_source = tbs_captured.into_source();

        //let mut tbs_bytes: Vec<u8> = Vec::new();
        //let tbs_certificate = cons.take_sequence(|cons| {
        let tbs_certificate = Constructed::decode(tbs_source, Mode::Der, |cons| {
            cons.take_sequence(|cons| {

                // Version is optional, default is v1(0)
                let version = cons.take_opt_primitive_if(Tag::INTEGER, |content| content.to_u8())?;

                let signature = AlgorithmIdentifier::take_from(cons)?;
                let issuer = Name::take_from(cons)?;
                
                // Parse thisUpdate time
                let this_update = cons.take_primitive(|_, content| {
                    let time_str = String::from_utf8(content.slice_all()?.to_vec())
                        .map_err(|_| DecodeError::content("Invalid UTF-8 in thisUpdate", decode::Pos::default()))?;
                    Ok(Validity::parse_asn1_to_timestamp(&time_str).expect("failed to parse this_update date"))
                })?;

                // Parse optional nextUpdate time
                let next_update = if let Ok(time) = cons.take_primitive(|_, content| {
                    let time_str = String::from_utf8(content.slice_all()?.to_vec())
                        .map_err(|_| DecodeError::content("Invalid UTF-8 in nextUpdate", decode::Pos::default()))?;
                    Ok(Validity::parse_asn1_to_timestamp(&time_str).expect("failed to parse next_update date"))
                }) {
                    Some(time)
                } else {
                    None
                };

                // Parse sequence of revoked certificates (optional)
                let revoked_certificates = cons.take_opt_sequence(|cons| {
                    let mut certificates = Vec::new();
                    while let Ok(cert) = RevokedCertificate::take_from(cons) {
                        certificates.push(cert);
                    }
                    Ok(certificates)
                })?.unwrap_or_default();

                Ok(TbsCertList {
                    tbs_bytes,
                    version,
                    signature,
                    issuer,
                    this_update,
                    next_update,
                    revoked_certificates,
                })
            }) 
        })
        .expect("failed to parse tbs certificate");
        Ok(tbs_certificate) 
    }
}

impl RevokedCertificate {
    pub fn take_from<S: decode::Source>(
        cons: &mut Constructed<S>,
    ) -> Result<Self, DecodeError<S::Error>> {
        cons.take_sequence(|cons| {
            // Parse serial number
            let serial_number = cons.take_primitive(|_, content| {
                let bytes = content.slice_all()?.to_vec();
                let hex_bytes = hex::encode(&bytes);
                _ = content.skip_all();
                Ok(hex_bytes)
            })?;

            // Parse revocation date
            let revocation_date = cons.take_primitive(|_, content| {
                let time_str = String::from_utf8(content.slice_all()?.to_vec())
                    .map_err(|_| DecodeError::content("Invalid UTF-8 in revocationDate", decode::Pos::default()))?;
                Ok(Validity::parse_asn1_to_timestamp(&time_str).expect("failed to parse revocation_date"))
            })?;

            // Parse optional CRL entry extensions
            let crl_entry_extensions = cons.take_opt_sequence(|cons| {
                let mut extensions = Vec::new();
                while let Ok(ext) = Extension::take_from(cons) {
                    extensions.push(ext);
                }
                Ok(extensions)
            })?;

            Ok(RevokedCertificate {
                serial_number,
                revocation_date,
                crl_entry_extensions,
            })
        })
    }
}

impl Extension {
    pub fn take_from<S: decode::Source>(
        cons: &mut Constructed<S>,
    ) -> Result<Self, DecodeError<S::Error>> {
        cons.take_sequence(|cons| {
            let extn_id = Oid::take_from(cons)?;
            
            // Parse optional critical flag, defaults to false
            let critical = cons.take_opt_primitive_if(Tag::BOOLEAN, |content| {
                content.to_bool()
            })?.unwrap_or(false);

            // Parse extension value as octet string
            let extn_value = cons.take_primitive(|_, content| {
                let value = content.slice_all()?.to_vec();
                _ = content.skip_all();
                Ok(value)
            })?;

            Ok(Extension {
                extn_id,
                critical,
                extn_value,
            })
        })
    }
}

impl SignerInfo {
    pub fn take_from<S: decode::Source>(
        cons: &mut Constructed<S>,
    ) -> Result<Self, DecodeError<S::Error>> {
        cons.take_sequence(|cons| {
            let version = cons.take_primitive_if(Tag::INTEGER, |content| content.to_u8())?;
            let signer_identifier = SignerIdentifier::take_from(cons)?;
            /*let issuer_and_serial_number = IssuerAndSerialNumber::take_from(cons)?;
            println!("signerInfo issSerial: {:?}",issuer_and_serial_number);*/

            let digest_algorithm = AlgorithmIdentifier::take_from(cons)?;

            /*let auth_captured = cons.capture_one()?;
            let mut auth_bytes = auth_captured.as_slice().to_vec();
            auth_bytes.drain(0..3); //remove implicit tag and lenght (A0,len,len)*/

            let auth_captured = cons.capture_one()?;
            let mut auth_bytes = auth_captured.as_slice().to_vec();

            //remove IMPLICIT TAG (A0), insert SET OF TAG (0x31)
            auth_bytes[0] = 0x31;
            //auth_bytes.drain(0..1);
            let auth_source = auth_captured.into_source();

            let auth_attributes = Constructed::decode(auth_source, Mode::Ber, |cons| {
                let auth_attrs = cons.take_opt_constructed_if(Tag::CTX_0, |cons| {
                    let mut attributes = Vec::new();
                    while let Ok(attr) = Attribute::take_from(cons) {
                        attributes.push(attr);
                    }
                    Ok(attributes)
                })?;
                Ok(auth_attrs)
            })
            .expect("failed to parse auth attributes");

            let signature_algorithm = AlgorithmIdentifier::take_from(cons)?;

            let signature_captured = cons.capture_all()?;
            let sign_source = signature_captured.as_slice().into_source();

            let signature = if signature_algorithm.algorithm.as_ref() == RSA_OID_BYTES {
                let rsa_signature = Constructed::decode(sign_source, Mode::Ber, |cons| {
                    let sign = cons.take_value(|_, content| {
                        let primitive_bytes = content.as_primitive()?;
                        let bytes = primitive_bytes.slice_all()?.to_vec();
                        _ = primitive_bytes.skip_all();
                        Ok(bytes)
                    })?;
                    _ = cons.skip_all();
                    Ok(sign)
                })
                .expect("failed to parse rsa signature");

                _ = cons.skip_all();
                rsa_signature  //return rsa_signature value

            } else if signature_algorithm.algorithm.as_ref() == ECDSA_SIGN_OID_BYTES {
                let signature = Constructed::decode(sign_source, Mode::Ber, |cons| {
                    cons.take_value(|_, content| {
                        let signature_bytes = {
                            let primitive_content = content.as_primitive()?;
                            primitive_content.slice_all()?.to_vec()
                        };
                        _ = content.as_primitive()?.skip_all();
            
                        // More flexible signature handling
                        if signature_bytes.len() < 8 {
                            return Err(DecodeError::content(
                                ContentError::from("ECDSA signature too short"),
                                decode::Pos::default(),
                            ));
                        }
            
                        // Find r and s within reasonable bounds
                        let total_len = signature_bytes.len();
                        let r_start = 5.min(total_len - 1);
                        let r_end = (r_start + 32).min(total_len);
                        let s_start = (r_end + 3).min(total_len - 1);
                        let s_end = (s_start + 32).min(total_len);
            
                        let mut signature = vec![0u8; 64];
                        
                        // Copy available r bytes
                        let r_len = r_end - r_start;
                        signature[32-r_len..32].copy_from_slice(&signature_bytes[r_start..r_end]);
                        
                        // Copy available s bytes
                        if s_end > s_start {
                            let s_len = s_end - s_start;
                            signature[64-s_len..64].copy_from_slice(&signature_bytes[s_start..s_end]);
                        }
            
                        Ok(signature)
                    })
                }).expect("Failed to parse ECDSA signature");

                _ = cons.skip_all();
                signature
            } else {
                return Err(DecodeError::content(
                    "Unsupported signature algorithm",
                    decode::Pos::default(),
                ));
            };

            /*let unauthenticated_attributes = cons.take_opt_constructed_if(Tag::CTX_1, |cons| {
                AuthenticatedAttributes::take_from(cons)
            })?;*/

            _ = cons.skip_all();
            //let unauthenticated_attributes = None;
            Ok(SignerInfo {
                version,
                signer_identifier,
                digest_algorithm,
                auth_attributes,
                auth_bytes,
                signature_algorithm,
                signature,
                //unauthenticated_attributes,
            })
        })
    }

    pub fn to_string(&self) -> String {
        format!(
            "SignerInfo {{\n  version: {},\n  digest_algorithm: {},\n  encrypted_digest: {:?}\n}}",
            self.version,
            self.digest_algorithm.to_string(),
            self.signature,
        )
    }
}

impl SignerIdentifier {
    pub fn take_from<S: decode::Source>(
        cons: &mut Constructed<S>,
    ) -> Result<Self, DecodeError<S::Error>> {
        let signer_identifier = cons.take_sequence(|cons| {
            // Capture the issuer bytes as needed
            /*let issuer = cons.take_sequence(|cons|{
                let issuer_bytes = cons.capture_all()?.as_slice().to_vec();
                Ok(issuer_bytes)
            })?;*/

            let issuer = Name::take_from(cons)?;

            let serial_number = cons.take_primitive(|_, content| {
                let sn = content.slice_all()?.to_vec();
                _ = content.skip_all();
                let sn_hex = hex::encode(&sn);
                Ok(sn_hex)
            })?;

            Ok(SignerIdentifier {
                issuer,
                serial_number,
            })
        })?;

        Ok(signer_identifier)
    }
}

impl Name {
    pub fn take_from<S: decode::Source>(
        cons: &mut Constructed<S>,
    ) -> Result<Self, DecodeError<S::Error>> {
        //println!("name cons: {:?}\n",cons);
        let mut rdn_sequence = Vec::new();
        let name_captured = cons.capture_one()?;
        let name_bytes = name_captured.as_slice().to_vec();
        let name_source = name_captured.into_source();

        let name = Constructed::decode(name_source, Mode::Der, |cons| {
            cons.take_sequence(|cons| {
                while let Ok(rdn) = RelativeDistinguishedName::take_from(cons) {
                    rdn_sequence.push(rdn);
                }
                Ok(Name {
                    rdn_sequence,
                    name_bytes,
                })
            })
        })
        .expect("failed to parse name");
        Ok(name)
    }

    pub fn to_der(&self) -> Vec<u8> {
        self.name_bytes.clone()
    }

    pub fn get_attribute_value(subject_bytes: &[u8], oid: &[u8]) -> Option<Vec<u8>> {
        if let Some(pos) = subject_bytes
            .windows(oid.len())
            .position(|window| window == oid)
        {
            let i = pos + oid.len();

            if i < subject_bytes.len() {
                let length = subject_bytes[i] as usize;
                let value_start = i + 1;

                if value_start + length <= subject_bytes.len() {
                    return Some(subject_bytes[value_start..value_start + length].to_vec());
                }
            }
        }
        None
    }

    pub fn get_common_name(subject_bytes: Vec<u8>) -> Vec<u8> {
        let common_name_oid: [u8; 3] = [0x55, 0x04, 0x03];
        Self::get_attribute_value(&subject_bytes, &common_name_oid).unwrap_or_else(Vec::new)
    }
}
impl PartialEq for Name {
    fn eq(&self, other: &Self) -> bool {
        self.rdn_sequence == other.rdn_sequence
    }
}
impl fmt::Display for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut parts = Vec::new();

        for rdn in &self.rdn_sequence {
            let oid_str = match rdn.attribute.oid.to_string().as_str() {
                "2.5.4.6" => "countryName",
                "2.5.4.8" => "stateOrProvinceName",
                "2.5.4.7" => "localityName",
                "2.5.4.10" => "organizationName",
                "2.5.4.11" => "organizationalUnitName",
                "2.5.4.3" => "commonName",
                _ => "unknown",
            };

            // Convert the value from Vec<u8> to a UTF-8 string
            let value_str = String::from_utf8(rdn.attribute.value.clone())
                .unwrap_or_else(|_| "invalid UTF-8".to_string());

            parts.push(format!("{} = {}", oid_str, value_str));
        }

        write!(f, "{}", parts.join(", "))
    }
}

impl RelativeDistinguishedName {
    pub fn take_from<S: decode::Source>(
        cons: &mut Constructed<S>,
    ) -> Result<Self, DecodeError<S::Error>> {
        let attribute = cons.take_set(|cons| {
            let attr = cons.take_sequence(|cons| {
                let oid = Oid::take_from(cons)?;
                let value = cons.take_value(|_, content| {
                    let val = content.as_primitive()?.slice_all()?.to_vec();
                    _ = content.as_primitive()?.skip_all();
                    Ok(val)
                })?;
                Ok(Attribute { oid, value })
            })?;
            _ = cons.skip_all();
            Ok(attr)
        })?;
        Ok(RelativeDistinguishedName { attribute })
    }
}

impl PartialEq for RelativeDistinguishedName {
    fn eq(&self, other: &Self) -> bool {
        (self.attribute.oid == other.attribute.oid)
            && (self.attribute.value == other.attribute.value)
    }
}


impl Attribute {
    pub fn take_from<S: decode::Source>(
        cons: &mut Constructed<S>,
    ) -> Result<Self, DecodeError<S::Error>> {
        //println!("cons: {:?}",cons.capture_all()?.as_slice());
        cons.take_sequence(|cons| {
            let oid = Oid::take_from(cons)?;
            //println!("parsed attr with OID {:?}",oid.as_ref().to_vec());

            //value = vec di bytes (AttributeValue senza i 2 byte di Tag)
            let value = cons.take_set(|cons| {
                let mut bytes_value = cons.capture_all()?.as_slice().to_vec();
                bytes_value.drain(0..2);
                //println!("bytes_value: {:?}\n",bytes_value);
                Ok(bytes_value)
                /*let mut attr_values = Vec::new();
                if let Ok(attr_value) = AttributeValue::take_from(cons){
                    attr_values.push(attr_value);
                }
                Ok(attr_values)*/
            })?;

            Ok(Attribute { oid, value })
        })
    }

    pub fn to_string(&self) -> String {
        format!(
            "Attribute {{\n  oid: {},\n  value: {:?}\n}}",
            self.oid.to_string(),
            self.value
        )
    }
}

/* useless data for now, bytes are sufficient (only need the digest value)
impl AttributeValue {
    pub fn take_from<S: decode::Source>(cons: &mut Constructed<S>) -> Result<Self, DecodeError<S::Error>> {

    }
}*/

impl ContentInfo {
    pub fn take_from<S: decode::Source>(
        cons: &mut Constructed<S>,
    ) -> Result<Self, DecodeError<S::Error>> {
        cons.take_sequence(|cons| {
            let content_type = Oid::take_from(cons)?;

            let _e_content: Vec<u8> = Vec::new();
            let e_content = cons.take_constructed_if(Tag::CTX_0, |content| {
                let bytes = content.take_primitive(|_, content| {
                    let content_bytes = content.slice_all()?.to_vec();
                    _ = content.skip_all();
                    Ok(content_bytes)
                })?;
                Ok(bytes)
            })?;
            //_=cons.skip_all();

            Ok(ContentInfo {
                content_type,
                e_content,
            })
        })
    }

    pub fn to_string(&self) -> String {
        format!(
            "ContentInfo {{\n  content_type: {},\n  content: {:?}\n}}",
            self.content_type.to_string(),
            self.e_content
        )
    }
}

impl Certificate {
    pub fn take_from<S: decode::Source>(
        cons: &mut Constructed<S>,
    ) -> Result<Self, DecodeError<S::Error>> {
        cons.take_sequence(|cons| {
            let tbs_certificate = TbsCertificate::take_from(cons)?;
            let signature_algorithm = AlgorithmIdentifier::take_from(cons)?;
            let signature_value = cons.take_value(|_, content| {
                let sign = content.as_primitive().map_err(|e| {
                    DecodeError::content(
                        format!("Expected constructed content: {}", e),
                        decode::Pos::default(),
                    )
                })?;

                let mut sign_bytes = sign.slice_all()?.to_vec();
                sign_bytes.drain(0..1);
                //let hex_bytes = hex::encode(&sign_bytes);
                _ = sign.skip_all();
                Ok(sign_bytes)
            })?;

            //println!("parsing certificate, sig : {:?}",signature_algorithm.to_string());
            Ok(Certificate {
                tbs_certificate,
                signature_algorithm,
                signature_value,
            })
        })
    }

    pub fn extract_data(&self, issuer_cert: &Certificate) -> CertificateData {
        CertificateData {
            subject: self.tbs_certificate.subject.to_der(),
            issuer: self.tbs_certificate.issuer.to_der(),
            issuer_pk: issuer_cert
                .tbs_certificate
                .subject_public_key_info
                .subject_public_key
                .clone(),
            signature: self.signature_value.clone(),
            tbs_bytes: self.tbs_certificate.tbs_bytes.clone(),
            serial_number: self.tbs_certificate.serial_number.clone(),
            not_before: self.tbs_certificate.validity.not_before,
            not_after: self.tbs_certificate.validity.not_after,
        }
    }


    pub fn is_revoked(&self, crls: &[CertificateList]) -> bool {
        // Find the CRL issued by this certificate's issuer
        if let Some(crl) = crls.iter().find(|crl| crl.tbs_cert_list.issuer == self.tbs_certificate.issuer) {
            // Check if the certificate's serial number is in the revoked certificates list
            let cert_serial = &self.tbs_certificate.serial_number;
            
            let is_revoked = crl.tbs_cert_list.revoked_certificates.iter()
                .any(|rev_cert| &rev_cert.serial_number == cert_serial);

            // Check if CRL is still valid
            let current_time = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();

            let crl_valid = current_time >= crl.tbs_cert_list.this_update && 
                           crl.tbs_cert_list.next_update
                               .map(|next| current_time <= next)
                               .unwrap_or(true);

            is_revoked && crl_valid
        } else {
            // No CRL found for this issuer
            false
        }
    }

    pub fn to_string(&self) -> String {
        format!(
            "Certificate {{\n  tbs_certificate: {},\n  signature_algorithm: {},\n  signature_value: {:?}\n}}",
            self.tbs_certificate.to_string(),
            self.signature_algorithm.to_string(),
            self.signature_value,
        )
    }
}

impl TbsCertificate {
    pub fn take_from<S: decode::Source>(
        cons: &mut Constructed<S>,
    ) -> Result<Self, DecodeError<S::Error>> {
        let tbs_captured = cons.capture_one()?;
        let tbs_bytes = tbs_captured.as_slice().to_vec();
        let tbs_source = tbs_captured.into_source();

        //let mut tbs_bytes: Vec<u8> = Vec::new();
        //let tbs_certificate = cons.take_sequence(|cons| {
        let tbs_certificate = Constructed::decode(tbs_source, Mode::Der, |cons| {
            cons.take_sequence(|cons| {
                //version = optional field
                let version = cons.take_opt_constructed_if(Tag::CTX_0, |cons| {
                    cons.take_primitive_if(Tag::INTEGER, |content| {
                        let v = content.to_u8()?;
                        //tbs_bytes.push(v);
                        Ok(v)
                    })
                    //println!("[tbs] version {:?}",version);
                })?;

                let serial_number = cons.take_primitive(|_, content| {
                    let bytes = content.slice_all()?.to_vec();
                    let hex_bytes = hex::encode(&bytes);
                    _ = content.skip_all();
                    Ok(hex_bytes)
                })?;

                let signature_algorithm = AlgorithmIdentifier::take_from(cons)?;
                let issuer = Name::take_from(cons)?;
                //asn1 format YYMMDDHHMMSSZ
                let validity = Validity::take_from(cons)?;
                let subject = Name::take_from(cons)?;
                let subject_public_key_info = SubjectPublicKeyInfo::take_from(cons)?;
                _ = cons.skip_all();

                Ok(TbsCertificate {
                    tbs_bytes,
                    version,
                    serial_number,
                    signature_algorithm,
                    issuer,
                    validity,
                    subject,
                    subject_public_key_info,
                })
            })
        })
        .expect("failed to parse tbs certificate");

        Ok(tbs_certificate)
    }

    pub fn to_string(&self) -> String {
        format!(
            "TbsCertificate {{\n    version: {:?},\n    serial_number: {:?},\n    signature_algorithm: {},\n    issuer: {:?},\n    validity: {},\n    subject: {:?},\n    subject_public_key_info: {}\n  }}",
            self.version,
            self.serial_number,
            self.signature_algorithm.to_string(),
            self.issuer,
            self.validity.to_string(),
            self.subject,
            self.subject_public_key_info.to_string()
        )
    }
}

impl AlgorithmIdentifier {
    pub fn take_from<S: decode::Source>(
        cons: &mut Constructed<S>,
        
    ) -> Result<Self, DecodeError<S::Error>> {
        cons.take_sequence(|cons| {
            let algorithm = Oid::take_from(cons)?;
            /*let parameters = cons.take_opt_primitive(|_,content|{
                let p = content.slice_all()?.to_vec();
                println!("p {:?}\n",p);
                Ok(p)
            })?;*/
            let parameters = cons.capture_all()?.to_vec();
            _ = cons.skip_all();
            Ok(AlgorithmIdentifier {
                algorithm,
                parameters,
            })
        })
    }
    pub fn to_string(&self) -> String {
        format!(
            "AlgorithmIdentifier {{    algorithm: {},\n    parameters: {:?}\n  }}",
            self.algorithm.to_string(),
            self.parameters
        )
    }
}

impl Validity {
    pub fn take_from<S: decode::Source>(
        cons: &mut Constructed<S>,
    ) -> Result<Self, DecodeError<S::Error>> {
        cons.take_sequence(|cons| {
            let not_before_str = cons.take_primitive(|_, content| {
                let bytes = content.slice_all()?;
                let time_str = String::from_utf8(bytes.to_vec()).map_err(|_| {
                    DecodeError::content("Invalid UTF-8 sequence", decode::Pos::default())
                })?;
                _ = content.skip_all();
                Ok(time_str)
            })?;

            let not_after_str = cons.take_primitive(|_, content| {
                let bytes = content.slice_all()?;
                let time_str = String::from_utf8(bytes.to_vec()).map_err(|_| {
                    DecodeError::content("Invalid UTF-8 sequence", decode::Pos::default())
                })?;
                _ = content.skip_all();
                Ok(time_str)
            })?;

            // converts string into UNIX epoch time
            let not_before = Validity::parse_asn1_to_timestamp(&not_before_str).map_err(|_| {
                DecodeError::content(
                    "Failed to parse not_before timestamp",
                    decode::Pos::default(),
                )
            })?;
            let not_after = Validity::parse_asn1_to_timestamp(&not_after_str).map_err(|_| {
                DecodeError::content(
                    "Failed to parse not_after timestamp",
                    decode::Pos::default(),
                )
            })?;

            Ok(Validity {
                not_before,
                not_after,
            })
        })
    }

    fn parse_asn1_to_timestamp(
        date_str: &str,
    ) -> Result<u64, DecodeError<std::string::FromUtf8Error>> {
        let naive_time = NaiveDateTime::parse_from_str(date_str, "%y%m%d%H%M%SZ")
            .map_err(|_| DecodeError::content("Invalid date format", decode::Pos::default()))?;

        let timestamp = Utc.from_utc_datetime(&naive_time).timestamp() as u64;

        Ok(timestamp)
    }

    pub fn to_string(&self) -> String {
        format!(
            "Validity {{\n    not_before: {},\n    not_after: {}\n  }}",
            self.not_before, self.not_after
        )
    }
}

impl SubjectPublicKeyInfo {
    pub fn take_from<S: decode::Source>(
        cons: &mut Constructed<S>,
    ) -> Result<Self, DecodeError<S::Error>> {
        cons.take_sequence(|cons| {
            let algorithm = AlgorithmIdentifier::take_from(cons)?;

            let subject_public_key = cons.take_primitive(|_, content| {
                let key_bytes = content.slice_all()?;

                let pk = if algorithm.algorithm.as_ref() == RSA_OID_BYTES {
                    let key_source = key_bytes[1..].into_source();
                    //let  = key_bytes_trimmed.into_source();
                    let public_key = Constructed::decode(key_source, Mode::Der, |cons| {
                        cons.take_sequence(|cons| {
                            let modulus = cons.take_value(|_, content| {
                                let mod_bytes = content.as_primitive()?;
                                let mut modu = mod_bytes.slice_all()?.to_vec();
                                //remove initial 0 (positive/negative number in complement2 )
                                modu.drain(0..1);
                                _ = mod_bytes.skip_all();
                                Ok(modu)
                            })?;

                            let exponent = cons.take_value(|_, content| {
                                let exp_bytes = content.as_primitive()?;
                                let expp = exp_bytes.slice_all()?.to_vec();
                                _ = exp_bytes.skip_all();
                                Ok(expp)
                            })?;

                            _ = cons.skip_all();
                            //println!("\n[*] parsed RSA key: mod: {:?}\nexp:{:?}",modulus,exponent);
                            Ok(PublicKey::Rsa { modulus, exponent })
                        })
                    })
                    .expect("failed to parse public key modulus and exponent");

                    _ = content.skip_all();
                    public_key //return to pk
                } else if algorithm.algorithm.as_ref() == ECDSA_OID_BYTES {
                    // TODO: invece che [1..] si dovrebbe creare una source e fare take_value(..){}
                    let point_bytes = &key_bytes[1..];
                    //println!("\n[*] parsed ECDSA key. point: {:?}",point_bytes);

                    PublicKey::Ecdsa {
                        point: point_bytes.to_vec(),
                    } //return to pk
                } else {
                    return Err(DecodeError::content(
                        "Unsupported algorithm",
                        decode::Pos::default(),
                    ));
                };

                _ = content.skip_all();
                Ok(pk)
            })?;

            _ = cons.capture_all();

            Ok(SubjectPublicKeyInfo {
                algorithm,
                subject_public_key,
            })
        })
    }

    pub fn to_string(&self) -> String {
        format!(
            "SubjectPublicKeyInfo {{\n    algorithm: {},\n    subject_public_key: {:?}\n  }}",
            self.algorithm.to_string(),
            self.subject_public_key
        )
    }
}