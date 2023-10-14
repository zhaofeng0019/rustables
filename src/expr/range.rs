use rustables_macros::nfnetlink_struct;

use crate::parser_impls::NfNetlinkData;

use super::{CmpOp, Expression, Register};

const NFTA_RANGE_SREG: u32 = 1;
const NFTA_RANGE_OP: u32 = 2;
const NFTA_RANGE_FROM_DATA: u32 = 3;
const NFTA_RANGE_TO_DATA: u32 = 4;

// Range expression. Available in kernel 4.9.
#[derive(Default, Debug, Clone, PartialEq, Eq)]
#[nfnetlink_struct]
pub struct Range {
    #[field(NFTA_RANGE_SREG)]
    sreg: Register,
    #[field(NFTA_RANGE_OP)]
    op: CmpOp,
    #[field(NFTA_RANGE_FROM_DATA)]
    from: NfNetlinkData,
    #[field(NFTA_RANGE_TO_DATA)]
    to: NfNetlinkData,
}

impl Range {
    pub fn new(op: CmpOp, from: impl Into<Vec<u8>>, to: impl Into<Vec<u8>>) -> Self {
        Range {
            sreg: Some(Register::Reg1),
            op: Some(op),
            from: Some(NfNetlinkData::default().with_value(from.into())),
            to: Some(NfNetlinkData::default().with_value(to.into())),
        }
    }
}

impl Expression for Range {
    fn get_name() -> &'static str {
        "range"
    }
}
