use crate::{try_attribute, try_child};
use failure::{bail, Error};
use roxmltree::Node;
use try_from::{TryFrom, TryInto};

#[derive(Debug, PartialEq)]
// http://www.w3.org/2000/09/xmldsig#
// https://www.w3.org/TR/xmldsig-core/#sec-Signature
pub struct Signature {
    pub signed_info: SignedInfo,
    pub signature_value: String,
    pub key_info: Option<KeyInfo>,
    pub objects: Vec<Object>,
    pub id: Option<String>,
}

impl<'a, 'd: 'a> TryFrom<Node<'a, 'd>> for Signature {
    type Err = Error;

    fn try_from(n: Node) -> Result<Self, Self::Err> {
        Ok(Signature {
            signed_info: try_child(n, "SignedInfo")?.try_into()?,
            signature_value: try_child(n, "SignatureValue")?.text().unwrap().into(),
            key_info: n
                .children()
                .find(|c| c.tag_name().name() == "KeyInfo")
                .map(|c| c.try_into())
                .transpose()?,
            objects: n
                .children()
                .filter(|c| c.tag_name().name() == "Object")
                .map(|c| c.try_into())
                .collect::<Result<Vec<_>, _>>()?,
            id: n.attribute("Id").map(|a| a.into()),
        })
    }
}

#[derive(Debug, PartialEq)]
pub struct SignatureValue {
    pub id: Option<String>,
    pub value: String,
}

impl<'a, 'd: 'a> TryFrom<Node<'a, 'd>> for SignatureValue {
    type Err = Error;

    fn try_from(n: Node) -> Result<Self, Self::Err> {
        Ok(SignatureValue {
            id: n.attribute("Id").map(|a| a.into()),
            value: n.text().unwrap().into(),
        })
    }
}

#[derive(Debug, PartialEq)]
pub struct SignedInfo {
    pub canonicalization_method: CanonicalizationMethod,
    pub signature_method: SignatureMethod,
    pub reference: Reference,
}

impl<'a, 'd: 'a> TryFrom<Node<'a, 'd>> for SignedInfo {
    type Err = Error;

    fn try_from(n: Node) -> Result<Self, Self::Err> {
        Ok(SignedInfo {
            canonicalization_method: try_child(n, "CanonicalizationMethod")?.try_into()?,
            signature_method: try_child(n, "SignatureMethod")?.try_into()?,
            reference: try_child(n, "Reference")?.try_into()?,
        })
    }
}

#[derive(Debug, PartialEq)]
pub struct CanonicalizationMethod {
    pub algorithm: String,
    // extension: T,
}

impl<'a, 'd: 'a> TryFrom<Node<'a, 'd>> for CanonicalizationMethod {
    type Err = Error;

    fn try_from(n: Node) -> Result<Self, Self::Err> {
        Ok(CanonicalizationMethod {
            algorithm: try_attribute(n, "Algorithm")?,
        })
    }
}

#[derive(Debug, PartialEq)]
pub struct SignatureMethod {
    pub algorithm: String,
    pub hmac_output_length: Option<u64>,
    // extension: T,
}

impl<'a, 'd: 'a> TryFrom<Node<'a, 'd>> for SignatureMethod {
    type Err = Error;

    fn try_from(n: Node) -> Result<Self, Self::Err> {
        Ok(SignatureMethod {
            algorithm: try_attribute(n, "Algorithm")?,
            hmac_output_length: n
                .children()
                .find(|c| c.tag_name().name() == "HMACOutputLength")
                .map(|c| c.text().unwrap().parse())
                .transpose()?,
        })
    }
}

#[derive(Debug, PartialEq)]
pub struct Reference {
    pub id: Option<String>,
    pub uri: Option<String>,
    pub _type: Option<String>,
    pub transforms: Vec<Transform>,
    pub digest_method: DigestMethod,
    pub digest_value: String,
}

impl<'a, 'd: 'a> TryFrom<Node<'a, 'd>> for Reference {
    type Err = Error;

    fn try_from(n: Node) -> Result<Self, Self::Err> {
        Ok(Reference {
            id: n.attribute("Id").map(|a| a.into()),
            uri: n.attribute("URI").map(|a| a.into()),
            _type: n.attribute("Type").map(|a| a.into()),
            transforms: n
                .children()
                .find(|c| c.tag_name().name() == "Transforms")
                .unwrap()
                .children()
                .filter(|c| c.tag_name().name() == "Transform")
                .map(|c| c.try_into())
                .collect::<Result<Vec<_>, _>>()?,
            digest_method: try_child(n, "DigestMethod")?.try_into()?,
            digest_value: try_child(n, "DigestValue")?.text().unwrap().into(),
        })
    }
}

#[derive(Debug, PartialEq)]
pub struct Transform {
    pub algorithm: String,
    pub xpath: Option<String>,
    // extension: T,
}

impl<'a, 'd: 'a> TryFrom<Node<'a, 'd>> for Transform {
    type Err = Error;

    fn try_from(n: Node) -> Result<Self, Self::Err> {
        Ok(Transform {
            algorithm: try_attribute(n, "Algorithm")?,
            xpath: n
                .children()
                .find(|c| c.tag_name().name() == "XPath")
                .map(|c| c.text().unwrap().into()),
        })
    }
}

#[derive(Debug, PartialEq)]
pub struct DigestMethod {
    pub algorithm: String,
    // extension: T,
}

impl<'a, 'd: 'a> TryFrom<Node<'a, 'd>> for DigestMethod {
    type Err = Error;

    fn try_from(n: Node) -> Result<Self, Self::Err> {
        Ok(DigestMethod {
            algorithm: try_attribute(n, "Algorithm")?,
        })
    }
}

#[derive(Debug, PartialEq)]
pub struct KeyInfo {
    pub id: Option<String>,
    pub value: KeyInfos,
}

impl<'a, 'd: 'a> TryFrom<Node<'a, 'd>> for KeyInfo {
    type Err = Error;

    fn try_from(n: Node) -> Result<Self, Self::Err> {
        Ok(KeyInfo {
            id: n.attribute("Id").map(|a| a.into()),
            value: n.children().filter(|c| c.is_element()).try_into()?,
        })
    }
}

#[derive(Debug, PartialEq)]
pub enum KeyInfos {
    KeyNames(Vec<String>),
    KeyValues(Vec<KeyValue>),
    RetrievalMethods(Vec<RetrievalMethod>),
    X509Datas(Vec<X509Datas>),
    PgpDatas(Vec<PgpData>),
    SpkiDatas(Vec<SpkiData>),
    MgmtDatas(Vec<String>),
    None,
}

impl<'a, 'd: 'a, I> TryFrom<I> for KeyInfos
where
    I: Iterator<Item = Node<'a, 'd>>,
{
    type Err = Error;

    fn try_from(iterator: I) -> Result<Self, Self::Err> {
        let mut iterator = iterator.peekable();

        match iterator.peek() {
            None => Ok(KeyInfos::None),
            Some(n) if n.tag_name().name() == "KeyName" => Ok(KeyInfos::KeyNames(
                iterator.map(|n| n.text().unwrap().into()).collect(),
            )),
            Some(n) if n.tag_name().name() == "KeyValue" => Ok(KeyInfos::KeyValues(
                iterator
                    .map(|n| n.try_into())
                    .collect::<Result<Vec<_>, _>>()?,
            )),
            Some(n) if n.tag_name().name() == "RetrievalMethod" => Ok(KeyInfos::RetrievalMethods(
                iterator
                    .map(|n| n.try_into())
                    .collect::<Result<Vec<_>, _>>()?,
            )),
            Some(n) if n.tag_name().name() == "X509Data" => Ok(KeyInfos::X509Datas(
                iterator
                    .map(|n| n.children().filter(|c| c.is_element()).try_into())
                    .collect::<Result<Vec<_>, _>>()?,
            )),
            Some(n) if n.tag_name().name() == "PGPData" => Ok(KeyInfos::PgpDatas(
                iterator
                    .map(|n| n.try_into())
                    .collect::<Result<Vec<_>, _>>()?,
            )),
            Some(n) if n.tag_name().name() == "SpkiData" => Ok(KeyInfos::SpkiDatas(
                iterator
                    .map(|n| n.try_into())
                    .collect::<Result<Vec<_>, _>>()?,
            )),
            Some(n) if n.tag_name().name() == "MgmtData" => Ok(KeyInfos::MgmtDatas(
                iterator.map(|n| n.text().unwrap().into()).collect(),
            )),
            Some(n) => bail!("Unsupported KeyInfo {:?} at {}", n, n.node_pos()),
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum KeyValue {
    Dsa {
        p: Option<String>,
        q: Option<String>,
        g: Option<String>,
        y: String,
        j: Option<String>,
        seed: Option<String>,
        pgen_counter: Option<String>,
    },
    Rsa {
        modulus: String,
        exponent: String,
    },
    Unsupported,
}

impl<'a, 'd: 'a> TryFrom<Node<'a, 'd>> for KeyValue {
    type Err = Error;

    fn try_from(n: Node) -> Result<Self, Self::Err> {
        match n.tag_name().name() {
            "DSAKeyValue" => Ok(KeyValue::Dsa {
                p: n.children()
                    .find(|c| c.tag_name().name() == "P")
                    .map(|c| c.text().unwrap().into()),
                q: n.children()
                    .find(|c| c.tag_name().name() == "Q")
                    .map(|c| c.text().unwrap().into()),
                g: n.children()
                    .find(|c| c.tag_name().name() == "G")
                    .map(|c| c.text().unwrap().into()),
                y: try_child(n, "Y")?.text().unwrap().into(),
                j: n.children()
                    .find(|c| c.tag_name().name() == "J")
                    .map(|c| c.text().unwrap().into()),
                seed: n
                    .children()
                    .find(|c| c.tag_name().name() == "Seed")
                    .map(|c| c.text().unwrap().into()),
                pgen_counter: n
                    .children()
                    .find(|c| c.tag_name().name() == "PgenCounter")
                    .map(|c| c.text().unwrap().into()),
            }),
            "RSAKeyValue" => Ok(KeyValue::Rsa {
                modulus: try_child(n, "Modulus")?.text().unwrap().into(),
                exponent: try_child(n, "Exponent")?.text().unwrap().into(),
            }),
            _ => Ok(KeyValue::Unsupported),
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct RetrievalMethod {
    pub transforms: Vec<Transform>,
    pub uri: String,
    pub _type: Option<String>,
}

impl<'a, 'd: 'a> TryFrom<Node<'a, 'd>> for RetrievalMethod {
    type Err = Error;

    fn try_from(n: Node) -> Result<Self, Self::Err> {
        Ok(RetrievalMethod {
            transforms: n
                .children()
                .find(|c| c.tag_name().name() == "Transforms")
                .unwrap()
                .children()
                .filter(|c| c.tag_name().name() == "Transform")
                .map(|c| c.try_into())
                .collect::<Result<Vec<_>, _>>()?,
            uri: try_attribute(n, "URI")?.into(),
            _type: n.attribute("Type").map(|a| a.into()),
        })
    }
}

#[derive(Debug, PartialEq)]
pub enum X509Datas {
    IssuerSerials(Vec<X509IssuerSerial>),
    Skis(Vec<String>),
    SubjectNames(Vec<String>),
    Certificates(Vec<String>),
    Crls(Vec<String>),
    Unsupported,
    None,
}

impl<'a, 'd: 'a, I> TryFrom<I> for X509Datas
where
    I: Iterator<Item = Node<'a, 'd>>,
{
    type Err = Error;

    fn try_from(iterator: I) -> Result<Self, Self::Err> {
        let mut iterator = iterator.peekable();

        match iterator.peek() {
            None => Ok(X509Datas::None),
            Some(n) if n.tag_name().name() == "X509IssuerSerial" => Ok(X509Datas::IssuerSerials(
                iterator
                    .map(|n| n.try_into())
                    .collect::<Result<Vec<_>, _>>()?,
            )),
            Some(n) if n.tag_name().name() == "X509SKI" => Ok(X509Datas::Skis(
                iterator.map(|n| n.text().unwrap().into()).collect(),
            )),
            Some(n) if n.tag_name().name() == "X509SubjectName" => Ok(X509Datas::SubjectNames(
                iterator.map(|n| n.text().unwrap().into()).collect(),
            )),
            Some(n) if n.tag_name().name() == "X509Certificate" => Ok(X509Datas::Certificates(
                iterator.map(|n| n.text().unwrap().into()).collect(),
            )),
            Some(n) if n.tag_name().name() == "X509CRL" => Ok(X509Datas::Crls(
                iterator.map(|n| n.text().unwrap().into()).collect(),
            )),
            Some(_) => Ok(X509Datas::Unsupported),
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct X509IssuerSerial {
    pub issuer_name: String,
    pub serial_number: u64,
}

impl<'a, 'd: 'a> TryFrom<Node<'a, 'd>> for X509IssuerSerial {
    type Err = Error;

    fn try_from(n: Node) -> Result<Self, Self::Err> {
        Ok(X509IssuerSerial {
            issuer_name: try_child(n, "X509IssuerName")?.text().unwrap().into(),
            serial_number: try_child(n, "X509SerialNumber")?.text().unwrap().parse()?,
        })
    }
}

#[derive(Debug, PartialEq)]
pub struct PgpData {
    pub key_id: Option<String>,
    pub key_packet: Option<String>,
}

impl<'a, 'd: 'a> TryFrom<Node<'a, 'd>> for PgpData {
    type Err = Error;

    fn try_from(n: Node) -> Result<Self, Self::Err> {
        Ok(PgpData {
            key_id: n
                .children()
                .find(|c| c.tag_name().name() == "PGPKeyID")
                .map(|c| c.text().unwrap().into()),
            key_packet: n
                .children()
                .find(|c| c.tag_name().name() == "PGPKeyPacket")
                .map(|c| c.text().unwrap().into()),
        })
    }
}

#[derive(Debug, PartialEq)]
pub struct SpkiData {
    pub sexps: Vec<String>,
}

impl<'a, 'd: 'a> TryFrom<Node<'a, 'd>> for SpkiData {
    type Err = Error;

    fn try_from(n: Node) -> Result<Self, Self::Err> {
        Ok(SpkiData {
            sexps: n
                .children()
                .filter(|c| c.tag_name().name() == "SPKISexp")
                .map(|c| c.text().unwrap().into())
                .collect::<Vec<_>>(),
        })
    }
}

#[derive(Debug, PartialEq)]
pub struct Object {
    pub id: Option<String>,
    pub mime_type: Option<String>,
    pub encoding: Option<String>,
}

impl<'a, 'd: 'a> TryFrom<Node<'a, 'd>> for Object {
    type Err = Error;

    fn try_from(n: Node) -> Result<Self, Self::Err> {
        Ok(Object {
            id: n.attribute("Id").map(|a| a.into()),
            mime_type: n.attribute("MimeType").map(|a| a.into()),
            encoding: n.attribute("Encoding").map(|a| a.into()),
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
    fn parse_response() -> Result<(), Error> {
        let path = "tests/fixtures/signature/example-2.xml";
        parse_signature_file(path)?;

        Ok(())
    }

    fn parse_signature_file(path: &str) -> Result<Signature, Error> {
        let bytes = read(path)?;
        let text = String::from_utf8_lossy(&bytes);
        let res: Signature = Document::parse(&text)?.root_element().try_into()?;
        Ok(res)
    }
}
