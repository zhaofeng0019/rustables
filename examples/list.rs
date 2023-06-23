use ipnetwork::{IpNetwork, Ipv4Network};
use rustables::{
    data_type::ip_to_vec,
    expr::{
        Bitwise, Cmp, CmpOp, Counter, HighLevelPayload, ICMPv6HeaderField, IPv4HeaderField,
        IcmpCode, Immediate, Meta, MetaType, NetworkHeaderField, TransportHeaderField, VerdictKind,
    },
    iface_index, list_chains_for_table, list_rules_for_chain, list_tables, Batch, Chain,
    ChainPolicy, Hook, HookClass, MsgType, ProtocolFamily, Rule, Table,
};
use std::{collections::HashSet, net::Ipv4Addr};

fn main() {
    let tables = list_tables().unwrap();
    dbg!(&tables);
    let netnsp = Table::new(ProtocolFamily::Inet).with_name("netnsp");
    let chains: Vec<Chain> = list_chains_for_table(&netnsp).unwrap();
    dbg!(&chains);
    let rules: Vec<Rule> = list_rules_for_chain(&chains[0]).unwrap();
    dbg!(&rules);

    let mut r: Rule = Rule::new(&chains[0]).unwrap();
    let i = iface_index("base_p_vh").unwrap();

    r = r
        .with_expr(Meta::new(MetaType::Iif))
        .with_expr(Cmp::new(CmpOp::Eq, i.to_le_bytes()))
        .with_expr(Immediate::new_verdict(VerdictKind::Drop));

    dbg!(&r);
    for rx in rules {
        println!("c {}", rx.get_expressions() == r.get_expressions());
    }

    let mut set = HashSet::new();
    set.insert(r.clone());

    dbg!(set.contains(&r));
}
