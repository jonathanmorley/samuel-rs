use crate::assertion::Assertions;
use crate::signature::Signature;
use crate::{maybe_child, try_attribute, try_child};
use failure::{bail, Error};
use roxmltree::Node;
use std::str::FromStr;
use try_from::{TryFrom, TryInto};

#[derive(Debug, PartialEq)]
// https://docs.oasis-open.org/security/saml/v2.0/saml-schema-protocol-2.0.xsd
// http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
pub struct Response {
    pub id: String,
    pub in_response_to: Option<String>,
    pub version: String,
    pub issue_instant: String,
    pub destination: Option<String>,
    pub consent: Option<String>,
    pub issuer: String,
    pub signature: Option<Signature>,
    pub status: Status,
    pub assertions: Assertions,
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
            signature: maybe_child(n, "Signature")?,
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
pub struct Status {
    pub code: StatusCode,
    pub message: Option<String>,
    pub detail: Option<String>,
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
pub struct StatusCode {
    pub primary: PrimaryStatusCode,
    pub secondary: Option<SecondaryStatusCode>,
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
pub enum PrimaryStatusCode {
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
pub enum SecondaryStatusCode {
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
    fn parse_response_wiki() -> Result<(), Error> {
        let path = "tests/fixtures/responses/response-wiki.xml";
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
