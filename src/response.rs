use crate::signature::Signature;
use crate::{try_attribute, try_child};
use failure::{bail, format_err, Error};
use roxmltree::Node;
use std::str::FromStr;
use try_from::{TryFrom, TryInto};

#[derive(Debug, PartialEq)]
// https://docs.oasis-open.org/security/saml/v2.0/saml-schema-protocol-2.0.xsd
// http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
struct Response {
    id: String,
    in_response_to: Option<String>,
    version: String,
    issue_instant: String,
    destination: Option<String>,
    consent: Option<String>,
    issuer: String,
    signature: Option<Signature>,
    status: Status,
    assertions: Assertions,
}

impl<'a, 'd: 'a> TryFrom<Node<'a, 'd>> for Response {
    type Err = Error;

    fn try_from(n: Node) -> Result<Self, Self::Err> {
        Ok(Response {
            id: try_attribute(n, "ID")?.into(),
            in_response_to: n.attribute("InResponseTo").map(|a| a.into()),
            version: try_attribute(n, "Version")?.into(),
            issue_instant: try_attribute(n, "IssueInstant")?.into(),
            destination: n.attribute("Destination").map(|a| a.into()),
            consent: n.attribute("Consent").map(|a| a.into()),
            issuer: try_child(n, "Issuer")?.text().unwrap().into(),
            signature: n
                .children()
                .find(|c| c.tag_name().name() == "Signature")
                .map(|c| c.try_into())
                .transpose()?,
            status: try_child(n, "Status")?.try_into()?,
            assertions: n
                .children()
                .filter(|c| c.is_element())
                .filter(|c| {
                    c.tag_name().name() == "Assertion"
                        || c.tag_name().name() == "EncryptedAssertion"
                })
                .try_into()?,
        })
    }
}

#[derive(Debug, PartialEq)]
struct Status {
    code: StatusCode,
    message: Option<String>,
    detail: Option<String>,
}

impl<'a, 'd: 'a> TryFrom<Node<'a, 'd>> for Status {
    type Err = Error;

    fn try_from(n: Node) -> Result<Self, Self::Err> {
        Ok(Status {
            code: try_child(n, "StatusCode")?.try_into()?,
            message: n
                .children()
                .find(|c| c.tag_name().name() == "StatusMessage")
                .map(|c| c.text().unwrap().into()),
            detail: n
                .children()
                .find(|c| c.tag_name().name() == "StatusDetail")
                .map(|c| c.text().unwrap().into()),
        })
    }
}

#[derive(Debug, PartialEq)]
struct StatusCode {
    primary: PrimaryStatusCode,
    secondary: Option<SecondaryStatusCode>,
}

impl<'a, 'd: 'a> TryFrom<Node<'a, 'd>> for StatusCode {
    type Err = Error;

    fn try_from(n: Node) -> Result<Self, Self::Err> {
        Ok(StatusCode {
            primary: try_attribute(n, "Value")?.parse()?,
            secondary: n
                .children()
                .find(|c| c.tag_name().name() == "StatusCode")
                .map(|c| try_attribute(c, "Value"))
                .transpose()?
                .map(|c| c.parse())
                .transpose()?,
        })
    }
}

#[derive(Debug, PartialEq)]
enum PrimaryStatusCode {
    Success,
    Requester,
    Responder,
    VersionMismatch,
}

impl FromStr for PrimaryStatusCode {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "urn:oasis:names:tc:SAML:2.0:status:Success" => Ok(PrimaryStatusCode::Success),
            "urn:oasis:names:tc:SAML:2.0:status:Requester" => Ok(PrimaryStatusCode::Requester),
            "urn:oasis:names:tc:SAML:2.0:status:Responder" => Ok(PrimaryStatusCode::Responder),
            "urn:oasis:names:tc:SAML:2.0:status:VersionMismatch" => {
                Ok(PrimaryStatusCode::VersionMismatch)
            }
            e => bail!("{} not recognised as a SAML status code", e),
        }
    }
}

#[derive(Debug, PartialEq)]
enum SecondaryStatusCode {
    AuthnFailed,
    InvalidAttrNameOrValue,
    InvalidNameIDPolicy,
    NoAuthnContext,
    NoAvailableIDP,
    NoPassive,
    NoSupportedIDP,
    PartialLogout,
    ProxyCountExceeded,
    RequestDenied,
    RequestUnsupported,
    RequestVersionDeprecated,
    RequestVersionTooHigh,
    RequestVersionTooLow,
    ResourceNotRecognized,
    TooManyResponses,
    UnknownAttrProfile,
    UnknownPrincipal,
    UnsupportedBinding,
}

impl FromStr for SecondaryStatusCode {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "urn:oasis:names:tc:SAML:2.0:status:AuthnFailed" => {
                Ok(SecondaryStatusCode::AuthnFailed)
            }
            "urn:oasis:names:tc:SAML:2.0:status:InvalidAttrNameOrValue" => {
                Ok(SecondaryStatusCode::InvalidAttrNameOrValue)
            }
            "urn:oasis:names:tc:SAML:2.0:status:InvalidNameIDPolicy" => {
                Ok(SecondaryStatusCode::InvalidNameIDPolicy)
            }
            "urn:oasis:names:tc:SAML:2.0:status:NoAuthnContext" => {
                Ok(SecondaryStatusCode::NoAuthnContext)
            }
            "urn:oasis:names:tc:SAML:2.0:status:NoAvailableIDP" => {
                Ok(SecondaryStatusCode::NoAvailableIDP)
            }
            "urn:oasis:names:tc:SAML:2.0:status:NoPassive" => Ok(SecondaryStatusCode::NoPassive),
            "urn:oasis:names:tc:SAML:2.0:status:NoSupportedIDP" => {
                Ok(SecondaryStatusCode::NoSupportedIDP)
            }
            "urn:oasis:names:tc:SAML:2.0:status:PartialLogout" => {
                Ok(SecondaryStatusCode::PartialLogout)
            }
            "urn:oasis:names:tc:SAML:2.0:status:ProxyCountExceeded" => {
                Ok(SecondaryStatusCode::ProxyCountExceeded)
            }
            "urn:oasis:names:tc:SAML:2.0:status:RequestDenied" => {
                Ok(SecondaryStatusCode::RequestDenied)
            }
            "urn:oasis:names:tc:SAML:2.0:status:RequestUnsupported" => {
                Ok(SecondaryStatusCode::RequestUnsupported)
            }
            "urn:oasis:names:tc:SAML:2.0:status:RequestVersionDeprecated" => {
                Ok(SecondaryStatusCode::RequestVersionDeprecated)
            }
            "urn:oasis:names:tc:SAML:2.0:status:RequestVersionTooHigh" => {
                Ok(SecondaryStatusCode::RequestVersionTooHigh)
            }
            "urn:oasis:names:tc:SAML:2.0:status:RequestVersionTooLow" => {
                Ok(SecondaryStatusCode::RequestVersionTooLow)
            }
            "urn:oasis:names:tc:SAML:2.0:status:ResourceNotRecognized" => {
                Ok(SecondaryStatusCode::ResourceNotRecognized)
            }
            "urn:oasis:names:tc:SAML:2.0:status:TooManyResponses" => {
                Ok(SecondaryStatusCode::TooManyResponses)
            }
            "urn:oasis:names:tc:SAML:2.0:status:UnknownAttrProfile" => {
                Ok(SecondaryStatusCode::UnknownAttrProfile)
            }
            "urn:oasis:names:tc:SAML:2.0:status:UnknownPrincipal" => {
                Ok(SecondaryStatusCode::UnknownPrincipal)
            }
            "urn:oasis:names:tc:SAML:2.0:status:UnsupportedBinding" => {
                Ok(SecondaryStatusCode::UnsupportedBinding)
            }
            e => bail!("{} not recognised as a SAML status code", e),
        }
    }
}

#[derive(Debug, PartialEq)]
enum Assertions {
    Plaintexts(Vec<PlaintextAssertion>),
    Encrypteds(Vec<EncryptedAssertion>),
    None,
}

impl<'a, 'd: 'a, I> TryFrom<I> for Assertions
where
    I: Iterator<Item = Node<'a, 'd>>,
{
    type Err = Error;

    fn try_from(iterator: I) -> Result<Self, Self::Err> {
        let mut iterator = iterator.peekable();

        match iterator.peek() {
            None => Ok(Assertions::None),
            Some(n) if n.tag_name().name() == "Assertion" => Ok(Assertions::Plaintexts(
                iterator
                    .map(|n| n.try_into())
                    .collect::<Result<Vec<_>, _>>()?,
            )),
            Some(n) if n.tag_name().name() == "EncryptedAssertion" => Ok(Assertions::Encrypteds(
                iterator
                    .map(|n| n.try_into())
                    .collect::<Result<Vec<_>, _>>()?,
            )),
            Some(n) => bail!("Unsupported Assertion {:?} at {}", n, n.node_pos()),
        }
    }
}

#[derive(Debug, PartialEq)]
struct PlaintextAssertion {
    issuer: String,
    signature: Option<Signature>,
    subject: Subject,
    conditions: Conditions,
    authn_statement: AuthnStatement,
    attribute_statement: AttributeStatement,
}

impl<'a, 'd: 'a> TryFrom<Node<'a, 'd>> for PlaintextAssertion {
    type Err = Error;

    fn try_from(n: Node) -> Result<Self, Self::Err> {
        Ok(PlaintextAssertion {
            issuer: n
                .children()
                .find(|c| c.tag_name().name() == "Issuer")
                .ok_or_else(|| format_err!("Issuer element not found within Assertion"))?
                .text()
                .unwrap()
                .into(),
            signature: n
                .children()
                .find(|c| c.tag_name().name() == "Signature")
                .map(|c| c.try_into())
                .transpose()?,
            subject: n
                .children()
                .find(|c| c.tag_name().name() == "Subject")
                .ok_or_else(|| format_err!("Subject element not found within Assertion"))?
                .try_into()?,
            conditions: n
                .children()
                .find(|c| c.tag_name().name() == "Conditions")
                .ok_or_else(|| format_err!("Conditions element not found within Assertion"))?
                .try_into()?,
            authn_statement: n
                .children()
                .find(|c| c.tag_name().name() == "AuthnStatement")
                .ok_or_else(|| format_err!("AuthnStatement element not found within Assertion"))?
                .try_into()?,
            attribute_statement: n
                .children()
                .find(|c| c.tag_name().name() == "AttributeStatement")
                .ok_or_else(|| {
                    format_err!("AttributeStatement element not found within Assertion")
                })?
                .try_into()?,
        })
    }
}

#[derive(Debug, PartialEq)]
struct EncryptedAssertion {
    encrypted_data: EncryptedData,
}

impl<'a, 'd: 'a> TryFrom<Node<'a, 'd>> for EncryptedAssertion {
    type Err = Error;

    fn try_from(n: Node) -> Result<Self, Self::Err> {
        Ok(EncryptedAssertion {
            encrypted_data: n
                .children()
                .find(|c| c.tag_name().name() == "EncryptedData")
                .ok_or_else(|| {
                    format_err!("EncryptedData element not found within EncryptedAssertion")
                })?
                .try_into()?,
        })
    }
}

#[derive(Debug, PartialEq)]
struct EncryptedData {
    encryption_method: EncryptionMethod,
    key_info: KeyInfo,
    cipher_data: CipherData,
}

impl<'a, 'd: 'a> TryFrom<Node<'a, 'd>> for EncryptedData {
    type Err = Error;

    fn try_from(n: Node) -> Result<Self, Self::Err> {
        Ok(EncryptedData {
            encryption_method: n
                .children()
                .find(|c| c.tag_name().name() == "EncryptionMethod")
                .ok_or_else(|| {
                    format_err!("EncryptionMethod element not found within EncryptedData")
                })?
                .try_into()?,
            key_info: n
                .children()
                .find(|c| c.tag_name().name() == "KeyInfo")
                .ok_or_else(|| format_err!("KeyInfo element not found within EncryptedData"))?
                .try_into()?,
            cipher_data: n
                .children()
                .find(|c| c.tag_name().name() == "CipherData")
                .ok_or_else(|| format_err!("CipherData element not found within EncryptedData"))?
                .try_into()?,
        })
    }
}

#[derive(Debug, PartialEq)]
struct EncryptionMethod {
    algorithm: String,
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

#[derive(Debug, PartialEq)]
struct KeyInfo {
    encrypted_key: EncryptedKey,
}

impl<'a, 'd: 'a> TryFrom<Node<'a, 'd>> for KeyInfo {
    type Err = Error;

    fn try_from(n: Node) -> Result<Self, Self::Err> {
        Ok(KeyInfo {
            encrypted_key: n
                .children()
                .find(|c| c.tag_name().name() == "EncryptedKey")
                .ok_or_else(|| format_err!("EncryptedKey element not found within KeyInfo"))?
                .try_into()?,
        })
    }
}

#[derive(Debug, PartialEq)]
struct EncryptedKey {
    encryption_method: EncryptionMethod,
    cipher_data: CipherData,
}

impl<'a, 'd: 'a> TryFrom<Node<'a, 'd>> for EncryptedKey {
    type Err = Error;

    fn try_from(n: Node) -> Result<Self, Self::Err> {
        Ok(EncryptedKey {
            encryption_method: n
                .children()
                .find(|c| c.tag_name().name() == "EncryptionMethod")
                .ok_or_else(|| {
                    format_err!("EncryptionMethod element not found within EncryptedKey")
                })?
                .try_into()?,
            cipher_data: n
                .children()
                .find(|c| c.tag_name().name() == "CipherData")
                .ok_or_else(|| format_err!("CipherData element not found within EncryptedKey"))?
                .try_into()?,
        })
    }
}

#[derive(Debug, PartialEq)]
struct CipherData {
    cipher_value: String,
}

impl<'a, 'd: 'a> TryFrom<Node<'a, 'd>> for CipherData {
    type Err = Error;

    fn try_from(n: Node) -> Result<Self, Self::Err> {
        Ok(CipherData {
            cipher_value: n
                .children()
                .find(|c| c.tag_name().name() == "CipherValue")
                .ok_or_else(|| format_err!("CipherValue element not found within CipherData"))?
                .text()
                .unwrap()
                .into(),
        })
    }
}

#[derive(Debug, PartialEq)]
struct Subject {
    name_id: String,
    subject_confirmation: SubjectConfirmation,
}

impl<'a, 'd: 'a> TryFrom<Node<'a, 'd>> for Subject {
    type Err = Error;

    fn try_from(n: Node) -> Result<Self, Self::Err> {
        Ok(Subject {
            name_id: n
                .children()
                .find(|c| c.tag_name().name() == "NameID")
                .ok_or_else(|| format_err!("NameID element not found within Subject"))?
                .text()
                .unwrap()
                .into(),
            subject_confirmation: n
                .children()
                .find(|c| c.tag_name().name() == "SubjectConfirmation")
                .ok_or_else(|| format_err!("SubjectConfirmation element not found within Subject"))?
                .try_into()?,
        })
    }
}

#[derive(Debug, PartialEq)]
struct SubjectConfirmation {
    method: String,
    subject_confirmation_data: SubjectConfirmationData,
}

impl<'a, 'd: 'a> TryFrom<Node<'a, 'd>> for SubjectConfirmation {
    type Err = Error;

    fn try_from(n: Node) -> Result<Self, Self::Err> {
        Ok(SubjectConfirmation {
            method: n
                .attribute("Method")
                .ok_or_else(|| {
                    format_err!("Method attribute not found within SubjectConfirmation")
                })?
                .into(),
            subject_confirmation_data: n
                .children()
                .find(|c| c.tag_name().name() == "SubjectConfirmationData")
                .ok_or_else(|| {
                    format_err!(
                        "SubjectConfirmationData element not found within SubjectConfirmation"
                    )
                })?
                .try_into()?,
        })
    }
}

#[derive(Debug, PartialEq)]
struct SubjectConfirmationData {
    not_on_or_after: String,
    recipient: String,
    in_response_to: String,
}

impl<'a, 'd: 'a> TryFrom<Node<'a, 'd>> for SubjectConfirmationData {
    type Err = Error;

    fn try_from(n: Node) -> Result<Self, Self::Err> {
        Ok(SubjectConfirmationData {
            not_on_or_after: n
                .attribute("NotOnOrAfter")
                .ok_or_else(|| {
                    format_err!("NotOnOrAfter attribute not found within SubjectConfirmationData")
                })?
                .into(),
            recipient: n
                .attribute("Recipient")
                .ok_or_else(|| {
                    format_err!("Recipient attribute not found within SubjectConfirmationData")
                })?
                .into(),
            in_response_to: n
                .attribute("InResponseTo")
                .ok_or_else(|| {
                    format_err!("InResponseTo attribute not found within SubjectConfirmationData")
                })?
                .into(),
        })
    }
}

#[derive(Debug, PartialEq)]
struct Conditions {
    not_before: String,
    not_on_or_after: String,
    audience_restriction: AudienceRestriction,
}

impl<'a, 'd: 'a> TryFrom<Node<'a, 'd>> for Conditions {
    type Err = Error;

    fn try_from(n: Node) -> Result<Self, Self::Err> {
        Ok(Conditions {
            not_before: n
                .attribute("NotBefore")
                .ok_or_else(|| format_err!("NotBefore attribute not found within Conditions"))?
                .into(),
            not_on_or_after: n
                .attribute("NotOnOrAfter")
                .ok_or_else(|| format_err!("NotOnOrAfter attribute not found within Conditions"))?
                .into(),
            audience_restriction: n
                .children()
                .find(|c| c.tag_name().name() == "AudienceRestriction")
                .ok_or_else(|| {
                    format_err!("AudienceRestriction element not found within Conditions")
                })?
                .try_into()?,
        })
    }
}

#[derive(Debug, PartialEq)]
struct AudienceRestriction {
    audience: String,
}

impl<'a, 'd: 'a> TryFrom<Node<'a, 'd>> for AudienceRestriction {
    type Err = Error;

    fn try_from(n: Node) -> Result<Self, Self::Err> {
        Ok(AudienceRestriction {
            audience: n
                .children()
                .find(|c| c.tag_name().name() == "Audience")
                .ok_or_else(|| {
                    format_err!("Audience element not found within AudienceRestriction")
                })?
                .text()
                .unwrap()
                .into(),
        })
    }
}

#[derive(Debug, PartialEq)]
struct AuthnStatement {
    authn_instant: String,
    session_not_on_or_after: String,
    session_index: String,
    authn_context: AuthnContext,
}

impl<'a, 'd: 'a> TryFrom<Node<'a, 'd>> for AuthnStatement {
    type Err = Error;

    fn try_from(n: Node) -> Result<Self, Self::Err> {
        Ok(AuthnStatement {
            authn_instant: n
                .attribute("AuthnInstant")
                .ok_or_else(|| {
                    format_err!("AuthnInstant attribute not found within AuthnStatement")
                })?
                .into(),
            session_not_on_or_after: n
                .attribute("SessionNotOnOrAfter")
                .ok_or_else(|| {
                    format_err!("SessionNotOnOrAfter attribute not found within AuthnStatement")
                })?
                .into(),
            session_index: n
                .attribute("SessionIndex")
                .ok_or_else(|| {
                    format_err!("SessionIndex attribute not found within AuthnStatement")
                })?
                .into(),
            authn_context: n
                .children()
                .find(|c| c.tag_name().name() == "AuthnContext")
                .ok_or_else(|| {
                    format_err!("AuthnContext attribute not found within AuthnStatement")
                })?
                .try_into()?,
        })
    }
}

#[derive(Debug, PartialEq)]
struct AuthnContext {
    authn_context_class_ref: String,
}

impl<'a, 'd: 'a> TryFrom<Node<'a, 'd>> for AuthnContext {
    type Err = Error;

    fn try_from(n: Node) -> Result<Self, Self::Err> {
        Ok(AuthnContext {
            authn_context_class_ref: n
                .children()
                .find(|c| c.tag_name().name() == "AuthnContextClassRef")
                .ok_or_else(|| {
                    format_err!("AuthnContextClassRef element not found within AuthnContext")
                })?
                .text()
                .unwrap()
                .into(),
        })
    }
}

#[derive(Debug, PartialEq)]
struct AttributeStatement {
    attributes: Vec<Attribute>,
}

impl<'a, 'd: 'a> TryFrom<Node<'a, 'd>> for AttributeStatement {
    type Err = Error;

    fn try_from(n: Node) -> Result<Self, Self::Err> {
        Ok(AttributeStatement {
            attributes: n
                .children()
                .filter(|c| c.tag_name().name() == "Attribute")
                .map(|c| c.try_into())
                .collect::<Result<Vec<_>, _>>()?,
        })
    }
}

#[derive(Debug, PartialEq)]
struct Attribute {
    name: String,
    name_format: String,
    values: Vec<String>,
}

impl<'a, 'd: 'a> TryFrom<Node<'a, 'd>> for Attribute {
    type Err = Error;

    fn try_from(n: Node) -> Result<Self, Self::Err> {
        Ok(Attribute {
            name: n
                .attribute("Name")
                .ok_or_else(|| format_err!("Name element not found within Attribute"))?
                .into(),
            name_format: n.attribute("NameFormat").unwrap().into(),
            values: n
                .children()
                .filter(|c| c.tag_name().name() == "AttributeValue")
                .map(|c| c.text().unwrap().into())
                .collect::<Vec<_>>(),
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
    fn parse_response_encrypted_assertion() -> Result<(), Error> {
        let path = "tests/fixtures/responses/response-encrypted-assertion.xml";
        parse_response_file(path)?;

        Ok(())
    }

    #[test]
    fn parse_response_signed_assertion_signed_message() -> Result<(), Error> {
        let path = "tests/fixtures/responses/response-signed-assertion-signed-message.xml";
        parse_response_file(path)?;

        Ok(())
    }

    #[test]
    fn parse_response_signed_assertion() -> Result<(), Error> {
        let path = "tests/fixtures/responses/response-signed-assertion.xml";
        parse_response_file(path)?;

        Ok(())
    }

    #[test]
    fn parse_response_signed_encrypted_assertion() -> Result<(), Error> {
        let path = "tests/fixtures/responses/response-signed-encrypted-assertion.xml";
        parse_response_file(path)?;

        Ok(())
    }

    #[test]
    fn parse_response_signed_message_encrypted_assertion() -> Result<(), Error> {
        let path = "tests/fixtures/responses/response-signed-message-encrypted-assertion.xml";
        parse_response_file(path)?;

        Ok(())
    }

    #[test]
    fn parse_response_signed_message_signed_encrypted_assertion() -> Result<(), Error> {
        let path =
            "tests/fixtures/responses/response-signed-message-signed-encrypted-assertion.xml";
        parse_response_file(path)?;

        Ok(())
    }

    #[test]
    fn parse_response_signed_message() -> Result<(), Error> {
        let path = "tests/fixtures/responses/response-signed-message.xml";
        parse_response_file(path)?;

        Ok(())
    }

    #[test]
    fn parse_response() -> Result<(), Error> {
        let path = "tests/fixtures/responses/response.xml";
        parse_response_file(path)?;

        Ok(())
    }

    fn parse_response_file(path: &str) -> Result<Response, Error> {
        let bytes = read(path)?;
        let text = String::from_utf8_lossy(&bytes);
        let res: Response = Document::parse(&text)?.root_element().try_into()?;
        Ok(res)
    }
}
