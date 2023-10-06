use std::fmt::Debug;

use netlink_sys::{AsyncSocket, Socket};
use rustables_macros::nfnetlink_struct;

use crate::chain::Chain;
use crate::error::{BuilderError, QueryError};
use crate::expr::{ExpressionList, RawExpression};
use crate::nlmsg::NfNetlinkObject;
use crate::query::{list_objects_with_data, list_objects_with_data_async};
use crate::sys::{
    NFTA_RULE_CHAIN, NFTA_RULE_EXPRESSIONS, NFTA_RULE_HANDLE, NFTA_RULE_ID, NFTA_RULE_POSITION,
    NFTA_RULE_TABLE, NFTA_RULE_USERDATA, NFT_MSG_DELRULE, NFT_MSG_NEWRULE, NLM_F_APPEND,
    NLM_F_CREATE,
};
use crate::util;
use crate::{Batch, ProtocolFamily};

/// A nftables firewall rule.
#[derive(Clone, PartialEq, Eq, Default, Debug, Hash)]
#[nfnetlink_struct(derive_deserialize = false)]
pub struct Rule {
    family: ProtocolFamily,
    #[field(NFTA_RULE_TABLE)]
    table: String,
    #[field(NFTA_RULE_CHAIN)]
    chain: String,
    #[field(NFTA_RULE_HANDLE)]
    handle: u64,
    #[field(NFTA_RULE_EXPRESSIONS)]
    expressions: ExpressionList,
    #[field(NFTA_RULE_POSITION)]
    position: u64,
    #[field(NFTA_RULE_USERDATA)]
    userdata: Vec<u8>,
    #[field(NFTA_RULE_ID)]
    id: u32,
}

impl Rule {
    /// Creates a new rule object in the given [`Chain`].
    ///
    /// [`Chain`]: struct.Chain.html
    pub fn new(chain: &Chain) -> Result<Rule, BuilderError> {
        Ok(Rule::default()
            .with_family(chain.get_family())
            .with_table(
                chain
                    .get_table()
                    .ok_or(BuilderError::MissingChainInformationError)?,
            )
            .with_chain(
                chain
                    .get_name()
                    .ok_or(BuilderError::MissingChainInformationError)?,
            ))
    }

    pub fn add_expr(&mut self, e: impl Into<RawExpression>) {
        let exprs = match self.get_mut_expressions() {
            Some(x) => x,
            None => {
                self.set_expressions(ExpressionList::default());
                self.get_mut_expressions().unwrap()
            }
        };
        exprs.add_value(e);
    }

    pub fn with_expr(mut self, e: impl Into<RawExpression>) -> Self {
        self.add_expr(e);
        self
    }

    /// Appends this rule to `batch`
    pub fn add_to_batch(self, batch: &mut Batch) -> Self {
        batch.add(&self, crate::MsgType::Add);
        self
    }
}

impl util::Essence for Rule {
    fn essentialize(&mut self) {
        self.handle = None;
        self.position = None;
        self.id = None;
    }
}

impl NfNetlinkObject for Rule {
    const MSG_TYPE_ADD: u32 = NFT_MSG_NEWRULE;
    const MSG_TYPE_DEL: u32 = NFT_MSG_DELRULE;

    fn get_family(&self) -> ProtocolFamily {
        self.family
    }

    fn set_family(&mut self, family: ProtocolFamily) {
        self.family = family;
    }

    // append at the end of the chain, instead of the beginning
    fn get_add_flags(&self) -> u32 {
        NLM_F_CREATE | NLM_F_APPEND
    }
}

pub fn list_rules_for_chain(chain: &Chain, sock: &mut Socket) -> anyhow::Result<Vec<Rule>> {
    let mut result = Vec::new();
    list_objects_with_data(
        libc::NFT_MSG_GETRULE as u16,
        &|rule: Rule, rules: &mut Vec<Rule>| {
            rules.push(rule);
            Ok(())
        },
        // only retrieve rules from the currently targetted chain
        Some(&Rule::new(chain)?),
        &mut result,
        sock,
    )?;
    Ok(result)
}

#[allow(non_snake_case)]
pub async fn list_rules_for_chain_async<S: AsyncSocket>(
    chain: &Chain,
    S: &mut S,
) -> anyhow::Result<Vec<Rule>> {
    let mut result = Vec::new();
    list_objects_with_data_async(
        libc::NFT_MSG_GETRULE as u16,
        &|rule: Rule, rules: &mut Vec<Rule>| {
            rules.push(rule);
            Ok(())
        },
        // only retrieve rules from the currently targetted chain
        Some(&Rule::new(chain)?),
        &mut result,
        S,
    )
    .await?;
    Ok(result)
}
