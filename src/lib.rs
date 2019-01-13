#![feature(transpose_result)]

use failure::{format_err, Error};
use roxmltree::Node;

pub mod response;
pub mod signature;

pub(crate) fn try_child<'a, 'd: 'a>(
    node: Node<'a, 'd>,
    element_name: &str,
) -> Result<Node<'a, 'd>, Error> {
    node.children()
        .find(|c| c.tag_name().name() == element_name)
        .ok_or_else(|| {
            format_err!(
                "{} element not found within {} at {}",
                element_name,
                node.tag_name().name(),
                node.node_pos()
            )
        })
}

pub(crate) fn try_attribute<'a, 'd: 'a>(
    node: Node<'a, 'd>,
    attribute_name: &str,
) -> Result<String, Error> {
    node.attribute(attribute_name)
        .map(|a| a.into())
        .ok_or_else(|| {
            format_err!(
                "{} attribute not found within {} at {}",
                attribute_name,
                node.tag_name().name(),
                node.node_pos()
            )
        })
}
