use crate::encryption::EncryptedData;
use crate::signature::Signature;
use crate::{maybe_child, try_attribute, try_child};
use failure::{bail, format_err, Error};
use roxmltree::Node;
use std::str::FromStr;
use try_from::{TryFrom, TryInto};

#[derive(Debug, PartialEq)]
pub enum Assertions {
    Plaintexts(Vec<PlaintextAssertion>),
    Encrypteds(Vec<EncryptedElement>),
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

// https://docs.oasis-open.org/security/saml/v2.0/saml-schema-assertion-2.0.xsd
#[derive(Debug, PartialEq)]
pub struct PlaintextAssertion {
    pub issuer: String,
    pub signature: Option<Signature>,
    pub subject: Option<Subject>,
    pub conditions: Option<Conditions>,
    pub advice: Option<Advice>,
    pub statement: Option<Statement>,
    pub authn_statement: Vec<AuthnStatement>,
    pub authz_decision_statement: Vec<AuthzDecisionStatement>,
    pub attribute_statement: Vec<AttributeStatement>,
    pub version: String,
    pub id: String,
    pub issue_instant: String,
}

impl<'a, 'd: 'a> TryFrom<Node<'a, 'd>> for PlaintextAssertion {
    type Err = Error;

    fn try_from(n: Node) -> Result<Self, Self::Err> {
        Ok(PlaintextAssertion {
            issuer: try_child(n, "Issuer")?.text().unwrap().into(),
            signature: maybe_child(n, "Signature")?,
            subject: maybe_child(n, "Subject")?,
            conditions: maybe_child(n, "Conditions")?,
            advice: maybe_child(n, "Advice")?,
            statement: maybe_child(n, "Statement")?,
            authn_statement: n
                .children()
                .filter(|c| c.tag_name().name() == "AuthnStatement")
                .map(|c| c.try_into())
                .collect::<Result<Vec<_>, _>>()?,
            authz_decision_statement: n
                .children()
                .filter(|c| c.tag_name().name() == "AuthzDecisionStatement")
                .map(|c| c.try_into())
                .collect::<Result<Vec<_>, _>>()?,
            attribute_statement: n
                .children()
                .filter(|c| c.tag_name().name() == "AttributeStatement")
                .map(|c| c.children().filter(|c| c.is_element()).try_into())
                .collect::<Result<Vec<_>, _>>()?,
            version: try_attribute(n, "Version")?,
            id: try_attribute(n, "ID")?,
            issue_instant: try_attribute(n, "IssueInstant")?,
        })
    }
}

#[derive(Debug, PartialEq)]
pub struct Subject {
    pub id: Id,
    pub subject_confirmation: Vec<SubjectConfirmation>,
}

impl<'a, 'd: 'a> TryFrom<Node<'a, 'd>> for Subject {
    type Err = Error;

    fn try_from(n: Node) -> Result<Self, Self::Err> {
        Ok(Subject {
            id: n
                .children()
                .find(|c| c.tag_name().name().ends_with("ID"))
                .ok_or_else(|| {
                    format_err!(
                        "{} element not found within {} at {}",
                        "ID",
                        n.tag_name().name(),
                        n.node_pos()
                    )
                })?
                .try_into()?,
            subject_confirmation: n
                .children()
                .filter(|c| c.tag_name().name() == "SubjectConfirmation")
                .map(|c| c.try_into())
                .collect::<Result<Vec<_>, _>>()?,
        })
    }
}

#[derive(Debug, PartialEq)]
pub enum Id {
    BaseId {
        name_qualifier: Option<String>,
        sp_name_qualifier: Option<String>,
    },
    NameId {
        name_qualifier: Option<String>,
        sp_name_qualifier: Option<String>,
        format: Option<String>,
        sp_provided_id: Option<String>,
    },
    EncryptedId {
        encrypted_data: String,
        encrypted_key: Vec<String>,
    },
}

impl<'a, 'd: 'a> TryFrom<Node<'a, 'd>> for Id {
    type Err = Error;

    fn try_from(n: Node) -> Result<Self, Self::Err> {
        match n.tag_name().name() {
            "BaseID" => Ok(Id::BaseId {
                name_qualifier: n.attribute("NameQualifier").map(|a| a.into()),
                sp_name_qualifier: n.attribute("SPNameQualifier").map(|a| a.into()),
            }),
            "NameID" => Ok(Id::NameId {
                name_qualifier: n.attribute("NameQualifier").map(|a| a.into()),
                sp_name_qualifier: n.attribute("SPNameQualifier").map(|a| a.into()),
                format: n.attribute("Format").map(|a| a.into()),
                sp_provided_id: n.attribute("SPProvidedID").map(|a| a.into()),
            }),
            "EncryptedID" => Ok(Id::EncryptedId {
                encrypted_data: try_child(n, "EncryptedData")?.text().unwrap().into(),
                encrypted_key: n
                    .children()
                    .filter(|c| c.tag_name().name() == "EncryptedKey")
                    .map(|c| c.text().unwrap().into())
                    .collect::<Vec<_>>(),
            }),
            _ => bail!("Unsupported Assertion {:?} at {}", n, n.node_pos()),
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct SubjectConfirmation {
    pub id: Option<Id>,
    pub method: String,
    pub subject_confirmation_data: Option<SubjectConfirmationData>,
}

impl<'a, 'd: 'a> TryFrom<Node<'a, 'd>> for SubjectConfirmation {
    type Err = Error;

    fn try_from(n: Node) -> Result<Self, Self::Err> {
        Ok(SubjectConfirmation {
            id: n
                .children()
                .find(|c| c.tag_name().name().ends_with("ID"))
                .map(|c| c.try_into())
                .transpose()?,
            method: try_attribute(n, "Method")?.into(),
            subject_confirmation_data: maybe_child(n, "SubjectConfirmationData")?,
        })
    }
}

#[derive(Debug, PartialEq)]
pub struct SubjectConfirmationData {
    pub not_before: Option<String>,
    pub not_on_or_after: Option<String>,
    pub recipient: Option<String>,
    pub in_response_to: Option<String>,
    pub address: Option<String>,
}

impl<'a, 'd: 'a> TryFrom<Node<'a, 'd>> for SubjectConfirmationData {
    type Err = Error;

    fn try_from(n: Node) -> Result<Self, Self::Err> {
        Ok(SubjectConfirmationData {
            not_before: n.attribute("NotBefore").map(|a| a.into()),
            not_on_or_after: n.attribute("NotOnOrAfter").map(|a| a.into()),
            recipient: n.attribute("Recipient").map(|a| a.into()),
            in_response_to: n.attribute("InResponseTo").map(|a| a.into()),
            address: n.attribute("Address").map(|a| a.into()),
        })
    }
}

#[derive(Debug, PartialEq)]
pub struct Conditions {
    pub not_before: Option<String>,
    pub not_on_or_after: Option<String>,
    pub restrictions: Restrictions,
}

impl<'a, 'd: 'a> TryFrom<Node<'a, 'd>> for Conditions {
    type Err = Error;

    fn try_from(n: Node) -> Result<Self, Self::Err> {
        Ok(Conditions {
            not_before: try_attribute(n, "NotBefore")?.into(),
            not_on_or_after: try_attribute(n, "NotOnOrAfter")?.into(),
            restrictions: n.children().filter(|c| c.is_element()).try_into()?,
        })
    }
}

#[derive(Debug, PartialEq)]
pub enum Restrictions {
    AudienceRestrictions(Vec<AudienceRestriction>),
    OneTimeUses,
    ProxyRestrictions(Vec<ProxyRestriction>),
}

impl<'a, 'd: 'a, I> TryFrom<I> for Restrictions
where
    I: Iterator<Item = Node<'a, 'd>>,
{
    type Err = Error;

    fn try_from(iterator: I) -> Result<Self, Self::Err> {
        let mut iterator = iterator.peekable();

        match iterator.peek() {
            None => Ok(Restrictions::OneTimeUses),
            Some(n) if n.tag_name().name() == "AudienceRestriction" => {
                Ok(Restrictions::AudienceRestrictions(
                    iterator
                        .map(|n| n.try_into())
                        .collect::<Result<Vec<_>, _>>()?,
                ))
            }
            Some(n) if n.tag_name().name() == "ProxyRestrictions" => {
                Ok(Restrictions::ProxyRestrictions(
                    iterator
                        .map(|n| n.try_into())
                        .collect::<Result<Vec<_>, _>>()?,
                ))
            }
            Some(n) => bail!("Unsupported Restriction {:?} at {}", n, n.node_pos()),
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct AudienceRestriction {
    pub audience: Vec<String>,
}

impl<'a, 'd: 'a> TryFrom<Node<'a, 'd>> for AudienceRestriction {
    type Err = Error;

    fn try_from(n: Node) -> Result<Self, Self::Err> {
        Ok(AudienceRestriction {
            audience: n
                .children()
                .filter(|c| c.tag_name().name() == "Audience")
                .map(|c| c.text().unwrap().into())
                .collect::<Vec<_>>(),
        })
    }
}

#[derive(Debug, PartialEq)]
pub struct ProxyRestriction {
    pub audience: Vec<String>,
    pub count: Option<u64>,
}

impl<'a, 'd: 'a> TryFrom<Node<'a, 'd>> for ProxyRestriction {
    type Err = Error;

    fn try_from(n: Node) -> Result<Self, Self::Err> {
        Ok(ProxyRestriction {
            audience: n
                .children()
                .filter(|c| c.tag_name().name() == "Audience")
                .map(|c| c.text().unwrap().into())
                .collect::<Vec<_>>(),
            count: n.attribute("Count").map(|a| a.parse()).transpose()?,
        })
    }
}

#[derive(Debug, PartialEq)]
pub enum Advice {
    AssertionIdRefs(Vec<String>),
    AssertionUriRefs(Vec<String>),
    PlaintextAssertions(Vec<Box<PlaintextAssertion>>),
    EncryptedAssertions(Vec<Box<EncryptedElement>>),
}

impl<'a, 'd: 'a> TryFrom<Node<'a, 'd>> for Advice {
    type Err = Error;

    fn try_from(n: Node) -> Result<Self, Self::Err> {
        unimplemented!()
    }
}

#[derive(Debug, PartialEq)]
pub struct Statement {}

impl<'a, 'd: 'a> TryFrom<Node<'a, 'd>> for Statement {
    type Err = Error;

    fn try_from(n: Node) -> Result<Self, Self::Err> {
        unimplemented!()
    }
}

#[derive(Debug, PartialEq)]
pub struct AuthnStatement {
    pub subject_locality: Option<SubjectLocality>,
    pub authn_context: AuthnContext,
    pub authn_instant: String,
    pub session_index: Option<String>,
    pub session_not_on_or_after: Option<String>,
}

impl<'a, 'd: 'a> TryFrom<Node<'a, 'd>> for AuthnStatement {
    type Err = Error;

    fn try_from(n: Node) -> Result<Self, Self::Err> {
        Ok(AuthnStatement {
            subject_locality: maybe_child(n, "SubjectLocality")?,
            authn_context: try_child(n, "AuthnContext")?.try_into()?,
            authn_instant: try_attribute(n, "AuthnInstant")?.into(),
            session_index: n.attribute("SessionIndex").map(|a| a.into()),
            session_not_on_or_after: n.attribute("SessionNotOnOrAfter").map(|a| a.into()),
        })
    }
}

#[derive(Debug, PartialEq)]
pub struct SubjectLocality {
    pub address: Option<String>,
    pub dns_name: Option<String>,
}

impl<'a, 'd: 'a> TryFrom<Node<'a, 'd>> for SubjectLocality {
    type Err = Error;

    fn try_from(n: Node) -> Result<Self, Self::Err> {
        Ok(SubjectLocality {
            address: n.attribute("Address").map(|a| a.into()),
            dns_name: n.attribute("AuthnInstant").map(|a| a.into()),
        })
    }
}

#[derive(Debug, PartialEq)]
pub struct EncryptedElement {
    pub encrypted_data: EncryptedData,
    pub encrypted_key: Option<String>,
}

impl<'a, 'd: 'a> TryFrom<Node<'a, 'd>> for EncryptedElement {
    type Err = Error;

    fn try_from(n: Node) -> Result<Self, Self::Err> {
        Ok(EncryptedElement {
            encrypted_data: try_child(n, "EncryptedData")?.try_into()?,
            encrypted_key: n
                .children()
                .find(|c| c.tag_name().name() == "EncryptedKey")
                .map(|c| c.text().unwrap().into()),
        })
    }
}

#[derive(Debug, PartialEq)]
pub struct AuthnContext {
    pub authn_context_class_ref: Option<String>,
    pub authn_context_decl: Option<String>,
    pub authn_context_decl_ref: Option<String>,
    pub authenticating_authority: Vec<String>,
}

impl<'a, 'd: 'a> TryFrom<Node<'a, 'd>> for AuthnContext {
    type Err = Error;

    fn try_from(n: Node) -> Result<Self, Self::Err> {
        Ok(AuthnContext {
            authn_context_class_ref: n
                .children()
                .find(|c| c.tag_name().name() == "AuthnContextClassRef")
                .map(|c| c.text().unwrap().into()),
            authn_context_decl: n
                .children()
                .find(|c| c.tag_name().name() == "AuthnContextDecl")
                .map(|c| c.text().unwrap().into()),
            authn_context_decl_ref: n
                .children()
                .find(|c| c.tag_name().name() == "AuthnContextDeclRef")
                .map(|c| c.text().unwrap().into()),
            authenticating_authority: n
                .children()
                .filter(|c| c.tag_name().name() == "AuthnContextDeclRef")
                .map(|c| c.text().unwrap().into())
                .collect(),
        })
    }
}

#[derive(Debug, PartialEq)]
pub struct AuthzDecisionStatement {
    pub action: Vec<Action>,
    pub evidence: Option<Evidence>,
    pub resource: String,
    pub decision: Decision,
}

impl<'a, 'd: 'a> TryFrom<Node<'a, 'd>> for AuthzDecisionStatement {
    type Err = Error;

    fn try_from(n: Node) -> Result<Self, Self::Err> {
        Ok(AuthzDecisionStatement {
            action: n
                .children()
                .filter(|c| c.tag_name().name() == "Action")
                .map(|c| c.try_into())
                .collect::<Result<Vec<_>, _>>()?,
            evidence: n
                .children()
                .find(|c| c.tag_name().name() == "Evidence")
                .map(|c| c.children().try_into())
                .transpose()?,
            resource: try_attribute(n, "Resource")?.into(),
            decision: n
                .attribute("Decision")
                .ok_or_else(|| {
                    format_err!(
                        "{} attribute not found within {} at {}",
                        "Decision",
                        n.tag_name().name(),
                        n.node_pos()
                    )
                })?
                .parse()?,
        })
    }
}

#[derive(Debug, PartialEq)]
pub struct Action {
    pub namespace: String,
}

impl<'a, 'd: 'a> TryFrom<Node<'a, 'd>> for Action {
    type Err = Error;

    fn try_from(n: Node) -> Result<Self, Self::Err> {
        Ok(Action {
            namespace: try_attribute(n, "Namespace")?,
        })
    }
}

#[derive(Debug, PartialEq)]
pub enum Evidence {
    AssertionIdRefs(Vec<String>),
    AssertionUriRefs(Vec<String>),
    PlaintextAssertions(Vec<Box<PlaintextAssertion>>),
    EncryptedAssertions(Vec<Box<EncryptedElement>>),
    None,
}

impl<'a, 'd: 'a, I> TryFrom<I> for Evidence
where
    I: Iterator<Item = Node<'a, 'd>>,
{
    type Err = Error;

    fn try_from(iterator: I) -> Result<Self, Self::Err> {
        let mut iterator = iterator.peekable();

        match iterator.peek() {
            None => Ok(Evidence::None),
            Some(n) if n.tag_name().name() == "AssertionIDRef" => Ok(Evidence::AssertionIdRefs(
                iterator
                    .map(|n| n.text().unwrap().into())
                    .collect::<Vec<_>>(),
            )),
            Some(n) if n.tag_name().name() == "AssertionURIRef" => Ok(Evidence::AssertionUriRefs(
                iterator
                    .map(|n| n.text().unwrap().into())
                    .collect::<Vec<_>>(),
            )),
            Some(n) if n.tag_name().name() == "Assertion" => Ok(Evidence::PlaintextAssertions(
                iterator
                    .map(|n| n.try_into())
                    .collect::<Result<Vec<_>, _>>()?
                    .into_iter()
                    .map(|n| Box::new(n))
                    .collect::<Vec<_>>(),
            )),
            Some(n) if n.tag_name().name() == "EncryptedAssertion" => {
                Ok(Evidence::EncryptedAssertions(
                    iterator
                        .map(|n| n.try_into())
                        .collect::<Result<Vec<_>, _>>()?
                        .into_iter()
                        .map(|n| Box::new(n))
                        .collect::<Vec<_>>(),
                ))
            }
            Some(n) => bail!("Unsupported Evidence {:?} at {}", n, n.node_pos()),
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum Decision {
    Permit,
    Deny,
    Indeterminate,
}

impl FromStr for Decision {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "Permit" => Ok(Decision::Permit),
            "Deny" => Ok(Decision::Deny),
            "Indeterminate" => Ok(Decision::Indeterminate),
            e => bail!("{} not recognised as a SAML decision", e),
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum AttributeStatement {
    PlaintextAttributes(Vec<Attribute>),
    EncryptedAttributes(Vec<EncryptedElement>),
    None,
}

impl<'a, 'd: 'a, I> TryFrom<I> for AttributeStatement
where
    I: Iterator<Item = Node<'a, 'd>>,
{
    type Err = Error;

    fn try_from(iterator: I) -> Result<Self, Self::Err> {
        let mut iterator = iterator.peekable();

        match iterator.peek() {
            None => Ok(AttributeStatement::None),
            Some(n) if n.tag_name().name() == "Attribute" => {
                Ok(AttributeStatement::PlaintextAttributes(
                    iterator
                        .map(|n| n.try_into())
                        .collect::<Result<Vec<_>, _>>()?,
                ))
            }
            Some(n) if n.tag_name().name() == "EncryptedAttribute" => {
                Ok(AttributeStatement::EncryptedAttributes(
                    iterator
                        .map(|n| n.try_into())
                        .collect::<Result<Vec<_>, _>>()?,
                ))
            }
            Some(n) => bail!("Unsupported Attribute {:?} at {}", n, n.node_pos()),
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct Attribute {
    pub name: String,
    pub name_format: Option<String>,
    pub friendly_name: Option<String>,
    pub values: Vec<String>,
}

impl<'a, 'd: 'a> TryFrom<Node<'a, 'd>> for Attribute {
    type Err = Error;

    fn try_from(n: Node) -> Result<Self, Self::Err> {
        Ok(Attribute {
            name: try_attribute(n, "Name")?.into(),
            name_format: n.attribute("NameFormat").map(|a| a.into()),
            friendly_name: n.attribute("FriendlyName").map(|a| a.into()),
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
    fn parse_response() -> Result<(), Error> {
        let path = "tests/fixtures/assertions/assertion.xml";
        parse_plaintext_assertion_file(path)?;

        Ok(())
    }

    fn parse_plaintext_assertion_file(path: &str) -> Result<PlaintextAssertion, Error> {
        let bytes = read(path)?;
        let text = String::from_utf8_lossy(&bytes);
        let res: PlaintextAssertion = Document::parse(&text)?.root_element().try_into()?;
        Ok(res)
    }
}
