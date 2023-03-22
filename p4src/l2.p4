/*
Copyright 2013-present Barefoot Networks, Inc. 

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

/*
 * Layer-2 processing
 */
/*****************************************************************************/
/* Spanning tree lookup                                                      */
/*****************************************************************************/

control process_spanning_tree(inout metadata meta) 
{
#ifndef L2_DISABLE
    action set_stp_state(bit<3> stp_state) 
    {
        meta.l2_metadata.stp_state = stp_state;
    }
    table spanning_tree 
    {
        key = {
            meta.ingress_metadata.ifindex : exact;
            meta.l2_metadata.stp_group    : exact;
        }
        actions = {
            set_stp_state;
        }
        size = SPANNING_TREE_TABLE_SIZE;
    }
#endif /* L2_DISABLE */

    apply
    {
#ifndef L2_DISABLE
        if ((meta.ingress_metadata.port_type == PORT_TYPE_NORMAL) &&
            (meta.l2_metadata.stp_group != STP_GROUP_NONE)) {
            spanning_tree.apply();
        }
#endif /* L2_DISABLE */
    }
}

// #ifndef L2_DISABLE
/*****************************************************************************/
/* Source MAC lookup                                                         */
/*****************************************************************************/
control process_smac(inout metadata meta)
{
#ifndef L2_DISABLE
    action nop() {}
    action smac_miss() 
    {
        meta.l2_metadata.l2_src_miss = TRUE;
    }
    action smac_hit(bit<16> ifindex) 
    {
        meta.l2_metadata.l2_src_move = (bit<16>)meta.ingress_metadata.ifindex ^ ifindex;
    }
    table smac {
        key = {
            meta.ingress_metadata.bd    : exact;
            meta.l2_metadata.lkp_mac_sa : exact;
        }
        actions = {
            nop;
            smac_miss;
            smac_hit;
        }
        size = MAC_TABLE_SIZE;
    }
#endif /* L2_DISABLE */

    apply
    {
#ifndef L2_DISABLE
        smac.apply();
#endif /* L2_DISABLE */
    }
}

/*****************************************************************************/
/* Destination MAC lookup                                                    */
/*****************************************************************************/
control process_dmac(inout metadata meta, inout standard_metadata_t standard_metadata)
{
#ifndef L2_DISABLE
    action nop() {}
    action dmac_hit(bit<16> ifindex)
    {
        meta.ingress_metadata.egress_ifindex = ifindex;
        meta.l2_metadata.same_if_check = meta.l2_metadata.same_if_check ^ (bit<16>)ifindex;
    }
    action dmac_multicast_hit(bit<16> mc_index)
    {
        meta.intrinsic_metadata.mcast_grp = mc_index;
        meta.fabric_metadata.dst_device = FABRIC_DEVICE_MULTICAST;
    }
    action dmac_miss()
    {
        meta.ingress_metadata.egress_ifindex = IFINDEX_FLOOD;
        meta.fabric_metadata.dst_device = FABRIC_DEVICE_MULTICAST;
    }
    action dmac_redirect_nexthop(bit<16> nexthop_index)
    {
        meta.l2_metadata.l2_redirect = TRUE;
        meta.l2_metadata.l2_nexthop = nexthop_index;
        meta.l2_metadata.l2_nexthop_type = NEXTHOP_TYPE_SIMPLE;
    }
    action dmac_redirect_ecmp(bit<16> ecmp_index)
    {
        meta.l2_metadata.l2_redirect = TRUE;
        meta.l2_metadata.l2_nexthop = ecmp_index;
        meta.l2_metadata.l2_nexthop_type = NEXTHOP_TYPE_ECMP;
    }
    action dmac_drop()
    {
        mark_to_drop(standard_metadata);
    }
    table dmac {
        key = {
            meta.ingress_metadata.bd    : exact;
            meta.l2_metadata.lkp_mac_da : exact;
        }
        actions = {
#ifdef OPENFLOW_ENABLE
            openflow_apply;
            openflow_miss;
#endif /* OPENFLOW_ENABLE */
            nop;
            dmac_hit;
            dmac_multicast_hit;
            dmac_miss;
            dmac_redirect_nexthop;
            dmac_redirect_ecmp;
            dmac_drop;
        }
        size = MAC_TABLE_SIZE;
        support_timeout = true;
    }
#endif /* L2_DISABLE */

    apply
    {
#ifndef L2_DISABLE
        dmac.apply();
#endif /* L2_DISABLE */
    }
}


/*****************************************************************************/
/* MAC lookup                                                         */
/*****************************************************************************/
control process_mac(inout metadata meta, inout standard_metadata_t standard_metadata)
{
    apply
    {
#ifndef L2_DISABLE
        if (DO_LOOKUP(SMAC_CHK) &&
           (meta.ingress_metadata.port_type == PORT_TYPE_NORMAL))
        {
            process_smac.apply(meta);
        }
        if (DO_LOOKUP(L2))
        {
            process_dmac.apply(meta, standard_metadata);
        }
#endif /* L2_DISABLE */
    }
}

/*****************************************************************************/
/* MAC learn notification                                                    */
/*****************************************************************************/
#ifndef L2_DISABLE
struct mac_learn_digest 
{
    bit<16> bd;
    bit<48> lkp_mac_sa;
    bit<16> ifindex;
}
#endif /* L2_DISABLE */

control process_mac_learning(inout metadata meta)
{
#ifndef L2_DISABLE
    action nop() {}
    action generate_learn_notify() 
    {
        digest<mac_learn_digest>((bit<32>)MAC_LEARN_RECEIVER, { meta.ingress_metadata.bd,
                                                                meta.l2_metadata.lkp_mac_sa,
                                                                meta.ingress_metadata.ifindex });
    }
    table learn_notify 
    {
        key = {
            meta.l2_metadata.l2_src_miss: ternary;
            meta.l2_metadata.l2_src_move: ternary;
            meta.l2_metadata.stp_state  : ternary;
        }
        actions = {
            nop;
            generate_learn_notify;
        }
        size = LEARN_NOTIFY_TABLE_SIZE;
    }
#endif /* L2_DISABLE */

    apply 
    {
#ifndef L2_DISABLE
        if (meta.l2_metadata.learning_enabled == TRUE)
        {
            learn_notify.apply();
        }
#endif /* L2_DISABLE */
    }
}

/*****************************************************************************/
/* Validate packet                                                           */
/*****************************************************************************/
control process_validate_packet(inout metadata meta)
{
    action nop() {}
    action set_unicast() 
    {
        meta.l2_metadata.lkp_pkt_type = L2_UNICAST;
    }
    action set_unicast_and_ipv6_src_is_link_local()
    {
        meta.l2_metadata.lkp_pkt_type = L2_UNICAST;
        meta.ipv6_metadata.ipv6_src_is_link_local = TRUE;
    }
    action set_multicast()
    {
        meta.l2_metadata.lkp_pkt_type = L2_MULTICAST;
        meta.l2_metadata.bd_stats_idx = meta.l2_metadata.bd_stats_idx + 16w1;
    }
    action set_multicast_and_ipv6_src_is_link_local()
    {
        meta.l2_metadata.lkp_pkt_type = L2_MULTICAST;
        meta.ipv6_metadata.ipv6_src_is_link_local = 1w1;
        meta.l2_metadata.bd_stats_idx = meta.l2_metadata.bd_stats_idx + 16w1;
    }
    action set_broadcast()
    {
        meta.l2_metadata.lkp_pkt_type = L2_BROADCAST;
        meta.l2_metadata.bd_stats_idx = meta.l2_metadata.bd_stats_idx + 16w2;
    }
    action set_malformed_packet(bit<8> drop_reason)
    {
        meta.ingress_metadata.drop_flag = TRUE;
        meta.ingress_metadata.drop_reason = drop_reason;
    }
    table validate_packet 
    {
        actions = {
            nop;
            set_unicast;
            set_multicast;
#ifndef IPV6_DISABLE
            set_unicast_and_ipv6_src_is_link_local;
            set_multicast_and_ipv6_src_is_link_local;
#endif /* IPV6_DISABLE */
            set_broadcast;
            set_malformed_packet;
        }
        key = {
            meta.l2_metadata.lkp_mac_sa            : ternary;
            meta.l2_metadata.lkp_mac_da            : ternary;
            meta.l3_metadata.lkp_ip_type           : ternary;
            meta.l3_metadata.lkp_ip_ttl            : ternary;
            meta.l3_metadata.lkp_ip_version        : ternary;
            meta.ipv4_metadata.lkp_ipv4_sa[31:24]  : ternary;
#ifndef IPV6_DISABLE
            meta.ipv6_metadata.lkp_ipv6_sa[127:112]: ternary;
#endif /* IPV6_DISABLE */
        }
        size = VALIDATE_PACKET_TABLE_SIZE;
    }

    apply 
    {
        if (DO_LOOKUP(PKT_VALIDATION) && (meta.ingress_metadata.drop_flag == FALSE)) 
        {
            validate_packet.apply();
        }
    }
}

/*****************************************************************************/
/* Egress BD lookup                                                          */
/*****************************************************************************/
control process_egress_bd_stats(inout metadata meta)
{
#ifndef STATS_DISABLE
    @min_width(32) direct_counter(CounterType.packets_and_bytes) egress_bd_stats_conter;
    action nop() 
    {
        egress_bd_stats_conter.count();
    }
    table egress_bd_stats 
    {
        key = {
            meta.egress_metadata.bd      : exact;
            meta.l2_metadata.lkp_pkt_type: exact;
        }
        actions = {
            nop;
        }
        size = EGRESS_BD_STATS_TABLE_SIZE;
        counters = egress_bd_stats_conter;
    }
#endif /* STATS_DISABLE */

    apply 
    {
#ifndef STATS_DISABLE
        egress_bd_stats.apply();
#endif /* STATS_DISABLE */
    }
}


control process_egress_bd(inout metadata meta)
{
    action nop() {}
    action set_egress_bd_properties(bit<9> smac_idx, bit<2> nat_mode, bit<16> bd_label)
    {
        meta.egress_metadata.smac_idx = smac_idx;
        meta.nat_metadata.egress_nat_mode = nat_mode;
        meta.acl_metadata.egress_bd_label = bd_label;
    }

    table egress_bd_map 
    {
        key = {
            meta.egress_metadata.bd : exact;
        }
        actions = {
            nop;
            set_egress_bd_properties;
        }
        size = EGRESS_BD_MAPPING_TABLE_SIZE;
    }

    apply
    {
        egress_bd_map.apply();
    }
}

/*****************************************************************************/
/* Egress VLAN decap                                                         */
/*****************************************************************************/
control process_vlan_decap(inout headers_t headers) 
{
    action nop() {}
    action remove_vlan_single_tagged()
    {
        headers.ethernet.etherType = (bit<16>)headers.vlan_tag[0].etherType;
        headers.vlan_tag[0].setInvalid();
    }
    action remove_vlan_double_tagged()
    {
        headers.ethernet.etherType = (bit<16>)headers.vlan_tag[1].etherType;
        headers.vlan_tag[0].setInvalid();
        headers.vlan_tag[1].setInvalid();
    }
    table vlan_decap
    {
        key = {
            headers.vlan_tag[0].isValid(): exact;
            headers.vlan_tag[1].isValid(): exact;
        }
        actions = {
            nop;
            remove_vlan_single_tagged;
            remove_vlan_double_tagged;
        }
        size = VLAN_DECAP_TABLE_SIZE;
    }

    apply
    {
        vlan_decap.apply();
    }
}