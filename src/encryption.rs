use crate::{try_attribute, try_child};
use failure::Error;
use roxmltree::Node;
use try_from::{TryFrom, TryInto};

// https://www.w3.org/TR/2002/REC-xmlenc-core-20021210/Overview.html
#[derive(Debug, PartialEq)]
pub struct EncryptedData {
    pub encryption_method: EncryptionMethod,
    pub key_info: KeyInfo,
    pub cipher_data: CipherData,
}

impl<'a, 'd: 'a> TryFrom<Node<'a, 'd>> for EncryptedData {
    type Err = Error;

    fn try_from(n: Node) -> Result<Self, Self::Err> {
        Ok(EncryptedData {
            encryption_method: try_child(n, "EncryptionMethod")?.try_into()?,
            key_info: try_child(n, "KeyInfo")?.try_into()?,
            cipher_data: try_child(n, "CipherData")?.try_into()?,
        })
    }
}

#[derive(Debug, PartialEq)]
pub struct KeyInfo {
    pub encrypted_key: EncryptedKey,
}

impl<'a, 'd: 'a> TryFrom<Node<'a, 'd>> for KeyInfo {
    type Err = Error;

    fn try_from(n: Node) -> Result<Self, Self::Err> {
        Ok(KeyInfo {
            encrypted_key: try_child(n, "EncryptedKey")?.try_into()?,
        })
    }
}

#[derive(Debug, PartialEq)]
pub struct EncryptedKey {
    pub encryption_method: EncryptionMethod,
    pub cipher_data: CipherData,
}

impl<'a, 'd: 'a> TryFrom<Node<'a, 'd>> for EncryptedKey {
    type Err = Error;

    fn try_from(n: Node) -> Result<Self, Self::Err> {
        Ok(EncryptedKey {
            encryption_method: try_child(n, "EncryptionMethod")?.try_into()?,
            cipher_data: try_child(n, "CipherData")?.try_into()?,
        })
    }
}

#[derive(Debug, PartialEq)]
pub struct CipherData {
    pub cipher_value: String,
}

impl<'a, 'd: 'a> TryFrom<Node<'a, 'd>> for CipherData {
    type Err = Error;

    fn try_from(n: Node) -> Result<Self, Self::Err> {
        Ok(CipherData {
            cipher_value: try_child(n, "CipherValue")?.text().unwrap().into(),
        })
    }
}

#[derive(Debug, PartialEq)]
pub struct EncryptionMethod {
    pub algorithm: String,
    // extension: T,
}

impl<'a, 'd: 'a> TryFrom<Node<'a, 'd>> for EncryptionMethod {
    type Err = Error;

    fn try_from(n: Node) -> Result<Self, Self::Err> {
        Ok(EncryptionMethod {
            algorithm: try_attribute(n, "Algorithm")?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use failure::Error;
    use roxmltree::Document;
    use std::fs::read;
    use std::string::String;
    use try_from::TryInto;

    #[test]
    fn parse_dh_1024() -> Result<(), Error> {
        let path = "tests/fixtures/encryption/cipherText__DH-1024__aes128-gcm__kw-aes128__dh-es__pbkdf2.xml";
        parse_encrypted_file(path)?;

        Ok(())
    }

    #[test]
    fn parse_ec_p256_concat_kdf() -> Result<(), Error> {
        let path = "tests/fixtures/encryption/cipherText__EC-P256__aes128-gcm__kw-aes128__ECDH-ES__ConcatKDF.xml";
        parse_encrypted_file(path)?;

        Ok(())
    }

    #[test]
    fn parse_ec_p256() -> Result<(), Error> {
        let path = "tests/fixtures/encryption/cipherText__EC-P256__aes128-gcm__kw-aes256__ECDH-ES__pbkdf2.xml";
        parse_encrypted_file(path)?;

        Ok(())
    }

    #[test]
    fn parse_ec_p384() -> Result<(), Error> {
        let path = "tests/fixtures/encryption/cipherText__EC-P384__aes192-gcm__kw-aes192__ECDH-ES__ConcatKDF.xml";
        parse_encrypted_file(path)?;

        Ok(())
    }

    #[test]
    fn parse_ec_p521() -> Result<(), Error> {
        let path = "tests/fixtures/encryption/cipherText__EC-P521__aes256-gcm__kw-aes256__ECDH-ES__ConcatKDF.xml";
        parse_encrypted_file(path)?;

        Ok(())
    }

    #[test]
    fn parse_rsa_2048() -> Result<(), Error> {
        let path = "tests/fixtures/encryption/cipherText__RSA-2048__aes128-gcm__rsa-oaep-mgf1p.xml";
        parse_encrypted_file(path)?;

        Ok(())
    }

    #[test]
    fn parse_rsa_3072_mgf1p() -> Result<(), Error> {
        let path = "tests/fixtures/encryption/cipherText__RSA-3072__aes192-gcm__rsa-oaep-mgf1p__Sha256.xml";
        parse_encrypted_file(path)?;

        Ok(())
    }

    #[test]
    fn parse_rsa_3072() -> Result<(), Error> {
        let path = "tests/fixtures/encryption/cipherText__RSA-3072__aes256-gcm__rsa-oaep__Sha384-MGF_Sha1.xml";
        parse_encrypted_file(path)?;

        Ok(())
    }

    #[test]
    fn parse_rsa_4096() -> Result<(), Error> {
        let path = "tests/fixtures/encryption/cipherText__RSA-4096__aes256-gcm__rsa-oaep__Sha512-MGF_Sha1_PSource.xml";
        parse_encrypted_file(path)?;

        Ok(())
    }

    fn parse_encrypted_file(path: &str) -> Result<EncryptedData, Error> {
        let bytes = read(path)?;
        let text = String::from_utf8_lossy(&bytes);
        let res: EncryptedData = Document::parse(&text)?.root_element().try_into()?;
        Ok(res)
    }
}
