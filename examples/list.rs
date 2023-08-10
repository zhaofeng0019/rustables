use ipnetwork::{IpNetwork, Ipv4Network};
use rustables::{
    data_type::ip_to_vec,
    expr::{
        self, Bitwise, Cmp, CmpOp, Counter, HighLevelPayload, ICMPv6HeaderField, IPv4HeaderField,
        IcmpCode, Immediate, Meta, MetaType, NetworkHeaderField, Register, TransportHeaderField,
        VerdictKind,
    },
    iface_index, list_chains_for_table, list_rules_for_chain, list_tables, Batch, Chain,
    ChainPolicy, Hook, HookClass, MsgType, ProtocolFamily, Rule, Table, util::Essence,
};
use std::{collections::HashSet, net::Ipv4Addr};

fn main() {
    // let tables = list_tables().unwrap();
    // dbg!(&tables);
    let table = Table::new(ProtocolFamily::Inet).with_name("filter");

    let t2 = Table::new(ProtocolFamily::Ipv6).with_name("filter");
    let chain1 = Chain::new(&t2).with_name("ufw6-user-limit-accept");

    let chains: Vec<Chain> = list_chains_for_table(&table).unwrap();
    dbg!(&chains.len());

    let rules: Vec<Rule> = list_rules_for_chain(&chains[2]).unwrap();
    dbg!(&rules);

    let mut rules: Vec<Rule> = list_rules_for_chain(&chain1).unwrap();
    dbg!(&rules);

    let rule1 = Rule::new(&chain1)
        .unwrap()
        .with_expr(
            expr::Counter::default()
                .with_nb_bytes(0 as u64)
                .with_nb_packets(0 as u64),
        )
        .with_expr(
            expr::Immediate::new_verdict(VerdictKind::Accept),
        );
    dbg!(&rule1);
    dbg!(rule1 == rules[0]); // false

    rules[0].essentialize();
    dbg!(rule1 == rules[0]); // true

}
