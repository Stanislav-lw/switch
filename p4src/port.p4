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
 * Input processing - port and packet related
 */


/*****************************************************************************/
/* Ingress port lookup                                                       */
/*****************************************************************************/
control process_ingress_port_mapping(inout metadata meta,
                                     inout standard_metadata_t standard_metadata) 
{
    action set_ifindex(bit<16> ifindex, bit<2> port_type)
    {
        meta.ingress_metadata.ifindex = ifindex;
        meta.ingress_metadata.port_type = port_type;
    }
    table ingress_port_mapping
    {
        key = {
            standard_metadata.ingress_port : exact;
        }
        actions = {
            set_ifindex;
        }
        size = PORTMAP_TABLE_SIZE;
    }

    action set_ingress_port_properties(bit<16> if_label,
                                       bit<5> qos_group,
                                       bit<5> tc_qos_group,
                                       bit<8> tc,
                                       bit<2> color,
                                       bit<1> trust_dscp,
                                       bit<1> trust_pcp)
    {
        meta.acl_metadata.if_label = if_label;
        meta.qos_metadata.ingress_qos_group = qos_group;
        meta.qos_metadata.tc_qos_group = tc_qos_group;
        meta.qos_metadata.lkp_tc = tc;
        meta.meter_metadata.packet_color = color;
        meta.qos_metadata.trust_dscp = trust_dscp;
        meta.qos_metadata.trust_pcp = trust_pcp;
    }
    table ingress_port_properties
    {
        key = {
            standard_metadata.ingress_port : exact;
        }
        actions = {
            set_ingress_port_properties;
        }
        size = PORTMAP_TABLE_SIZE;
    }

    apply
    {
        ingress_port_mapping.apply();
        ingress_port_properties.apply();
    }
}


/*****************************************************************************/
/* Validate outer packet header                                              */
/*****************************************************************************/
control process_validate_outer_header(inout headers_t headers,
                                      inout metadata meta,
                                      inout standard_metadata_t standard_metadata)
{
    action malformed_outer_ethernet_packet(bit<8> drop_reason)
    {
        meta.ingress_metadata.drop_flag = TRUE;
        meta.ingress_metadata.drop_reason = drop_reason;
    }
    action set_valid_outer_unicast_packet_untagged()
    {
        meta.l2_metadata.lkp_pkt_type = L2_UNICAST;
        meta.l2_metadata.lkp_mac_type = (bit<16>)headers.ethernet.etherType;
    }
    action set_valid_outer_unicast_packet_single_tagged()
    {
        meta.l2_metadata.lkp_pkt_type = L2_UNICAST;
        meta.l2_metadata.lkp_mac_type = (bit<16>)headers.vlan_tag[0].etherType;
        meta.l2_metadata.lkp_pcp = (bit<3>)headers.vlan_tag[0].pcp;
    }
    action set_valid_outer_unicast_packet_double_tagged()
    {
        meta.l2_metadata.lkp_pkt_type = L2_UNICAST;
        meta.l2_metadata.lkp_mac_type = (bit<16>)headers.vlan_tag[1].etherType;
        meta.l2_metadata.lkp_pcp = (bit<3>)headers.vlan_tag[0].pcp;
    }
    action set_valid_outer_unicast_packet_qinq_tagged()
    {
        meta.l2_metadata.lkp_pkt_type = L2_UNICAST;
        meta.l2_metadata.lkp_mac_type = (bit<16>)headers.ethernet.etherType;
        meta.l2_metadata.lkp_pcp = (bit<3>)headers.vlan_tag[0].pcp;
    }
    action set_valid_outer_multicast_packet_untagged()
    {
        meta.l2_metadata.lkp_pkt_type = L2_MULTICAST;
        meta.l2_metadata.lkp_mac_type = (bit<16>)headers.ethernet.etherType;
    }
    action set_valid_outer_multicast_packet_single_tagged()
    {
        meta.l2_metadata.lkp_pkt_type = L2_MULTICAST;
        meta.l2_metadata.lkp_mac_type = (bit<16>)headers.vlan_tag[0].etherType;
        meta.l2_metadata.lkp_pcp = (bit<3>)headers.vlan_tag[0].pcp;
    }
    action set_valid_outer_multicast_packet_double_tagged()
    {
        meta.l2_metadata.lkp_pkt_type = L2_MULTICAST;
        meta.l2_metadata.lkp_mac_type = (bit<16>)headers.vlan_tag[1].etherType;
        meta.l2_metadata.lkp_pcp = (bit<3>)headers.vlan_tag[0].pcp;
    }
    action set_valid_outer_multicast_packet_qinq_tagged()
    {
        meta.l2_metadata.lkp_pkt_type = L2_MULTICAST;
        meta.l2_metadata.lkp_mac_type = (bit<16>)headers.ethernet.etherType;
        meta.l2_metadata.lkp_pcp = (bit<3>)headers.vlan_tag[0].pcp;
    }
    action set_valid_outer_broadcast_packet_untagged()
    {
        meta.l2_metadata.lkp_pkt_type = L2_BROADCAST;
        meta.l2_metadata.lkp_mac_type = (bit<16>)headers.ethernet.etherType;
    }
    action set_valid_outer_broadcast_packet_single_tagged()
    {
        meta.l2_metadata.lkp_pkt_type = L2_BROADCAST;
        meta.l2_metadata.lkp_mac_type = (bit<16>)headers.vlan_tag[0].etherType;
        meta.l2_metadata.lkp_pcp = (bit<3>)headers.vlan_tag[0].pcp;
    }
    action set_valid_outer_broadcast_packet_double_tagged()
    {
        meta.l2_metadata.lkp_pkt_type = L2_BROADCAST;
        meta.l2_metadata.lkp_mac_type = (bit<16>)headers.vlan_tag[1].etherType;
        meta.l2_metadata.lkp_pcp = (bit<3>)headers.vlan_tag[0].pcp;
    }
    action set_valid_outer_broadcast_packet_qinq_tagged()
    {
        meta.l2_metadata.lkp_pkt_type = L2_BROADCAST;
        meta.l2_metadata.lkp_mac_type = (bit<16>)headers.ethernet.etherType;
        meta.l2_metadata.lkp_pcp = (bit<3>)headers.vlan_tag[0].pcp;
    }
    table validate_outer_ethernet 
    {
        key = {
            headers.ethernet.srcAddr     : ternary;
            headers.ethernet.dstAddr     : ternary;
            headers.vlan_tag[0].isValid(): exact;
            headers.vlan_tag[1].isValid(): exact;
        }
        actions = {
            malformed_outer_ethernet_packet;
            set_valid_outer_unicast_packet_untagged;
            set_valid_outer_unicast_packet_single_tagged;
            set_valid_outer_unicast_packet_double_tagged;
            set_valid_outer_unicast_packet_qinq_tagged;
            set_valid_outer_multicast_packet_untagged;
            set_valid_outer_multicast_packet_single_tagged;
            set_valid_outer_multicast_packet_double_tagged;
            set_valid_outer_multicast_packet_qinq_tagged;
            set_valid_outer_broadcast_packet_untagged;
            set_valid_outer_broadcast_packet_single_tagged;
            set_valid_outer_broadcast_packet_double_tagged;
            set_valid_outer_broadcast_packet_qinq_tagged;
        }
        size = VALIDATE_PACKET_TABLE_SIZE;
    }

    apply 
    {
        /* validate the ethernet header */
        switch (validate_outer_ethernet.apply().action_run) 
        {
            malformed_outer_ethernet_packet: {}
            default:
            {
                if (headers.ipv4.isValid()) {
//                     validate_outer_ipv4_header.apply();
                } else {
                    if (headers.ipv6.isValid()) {
//                         validate_outer_ipv6_header.apply();
                    } else {
#ifndef MPLS_DISABLE
                        if (headers.mpls[0].isValid()) {
//                             validate_mpls_header.apply();
                        }
#endif
                    }
                }
            }
        }
    }
}

/*****************************************************************************/
/* Ingress port-vlan mapping lookup                                          */
/*****************************************************************************/
control process_port_vlan_mapping(inout headers_t headers,
                                  inout metadata meta)
{
    action set_bd_properties(bit<16> bd, bit<16> vrf, bit<10> stp_group, bit<1> learning_enabled,
                             bit<16> bd_label, bit<16> stats_idx, bit<10> rmac_group,
                             bit<1> ipv4_unicast_enabled, bit<1> ipv6_unicast_enabled,
                             bit<2> ipv4_urpf_mode, bit<2> ipv6_urpf_mode,
                             bit<1> igmp_snooping_enabled, bit<1> mld_snooping_enabled,
                             bit<1> ipv4_multicast_enabled, bit<1> ipv6_multicast_enabled,
                             bit<16> mrpf_group,
                             bit<16> ipv4_mcast_key, bit<1> ipv4_mcast_key_type,
                             bit<16> ipv6_mcast_key, bit<1> ipv6_mcast_key_type) 
    {
        meta.ingress_metadata.bd = bd;
        meta.ingress_metadata.outer_bd = (bit<16>)bd;
        meta.acl_metadata.bd_label = bd_label;
        meta.l2_metadata.stp_group = stp_group;
        meta.l2_metadata.bd_stats_idx = stats_idx;
        meta.l2_metadata.learning_enabled = learning_enabled;
        
        meta.l3_metadata.vrf = vrf;
        meta.ipv4_metadata.ipv4_unicast_enabled = ipv4_unicast_enabled;
        meta.ipv6_metadata.ipv6_unicast_enabled = ipv6_unicast_enabled;
        meta.ipv4_metadata.ipv4_urpf_mode = ipv4_urpf_mode;
        meta.ipv6_metadata.ipv6_urpf_mode = ipv6_urpf_mode;
        meta.l3_metadata.rmac_group = rmac_group;
        
        meta.multicast_metadata.igmp_snooping_enabled = igmp_snooping_enabled;
        meta.multicast_metadata.mld_snooping_enabled = mld_snooping_enabled;
        meta.multicast_metadata.ipv4_multicast_enabled = ipv4_multicast_enabled;
        meta.multicast_metadata.ipv6_multicast_enabled = ipv6_multicast_enabled;
        meta.multicast_metadata.bd_mrpf_group = mrpf_group;
        meta.multicast_metadata.ipv4_mcast_key_type = ipv4_mcast_key_type;
        meta.multicast_metadata.ipv4_mcast_key = ipv4_mcast_key;
        meta.multicast_metadata.ipv6_mcast_key_type = ipv6_mcast_key_type;
        meta.multicast_metadata.ipv6_mcast_key = ipv6_mcast_key;
    }
    action port_vlan_mapping_miss() 
    {
        meta.l2_metadata.port_vlan_mapping_miss = TRUE;
    }
    action_profile(BD_TABLE_SIZE) bd_action_profile;
    table port_vlan_mapping 
    {
        key = {
            meta.ingress_metadata.ifindex   : exact;
            headers.vlan_tag[0].isValid()   : exact;
            headers.vlan_tag[0].vid         : exact;
            headers.vlan_tag[1].isValid()   : exact;
            headers.vlan_tag[1].vid         : exact;
        }
        actions = {
            set_bd_properties;
            port_vlan_mapping_miss;
        }
        implementation = bd_action_profile;
        size = PORT_VLAN_TABLE_SIZE;
    }

#ifdef TUNNEL_DISABLE
    action non_ip_lkp()
    {
        meta.l2_metadata.lkp_mac_sa = (bit<48>)headers.ethernet.srcAddr;
        meta.l2_metadata.lkp_mac_da = (bit<48>)headers.ethernet.dstAddr;
    }
    action ipv4_lkp()
    {
        meta.l2_metadata.lkp_mac_sa = (bit<48>)headers.ethernet.srcAddr;
        meta.l2_metadata.lkp_mac_da = (bit<48>)headers.ethernet.dstAddr;
        meta.ipv4_metadata.lkp_ipv4_sa = (bit<32>)headers.ipv4.srcAddr;
        meta.ipv4_metadata.lkp_ipv4_da = (bit<32>)headers.ipv4.dstAddr;
        meta.l3_metadata.lkp_ip_proto = (bit<8>)headers.ipv4.protocol;
        meta.l3_metadata.lkp_ip_ttl = (bit<8>)headers.ipv4.ttl;
        meta.l3_metadata.lkp_l4_sport = (bit<16>)meta.l3_metadata.lkp_outer_l4_sport;
        meta.l3_metadata.lkp_l4_dport = (bit<16>)meta.l3_metadata.lkp_outer_l4_dport;
    }
    action ipv6_lkp() 
    {
        meta.l2_metadata.lkp_mac_sa = (bit<48>)headers.ethernet.srcAddr;
        meta.l2_metadata.lkp_mac_da = (bit<48>)headers.ethernet.dstAddr;
        meta.ipv6_metadata.lkp_ipv6_sa = (bit<128>)headers.ipv6.srcAddr;
        meta.ipv6_metadata.lkp_ipv6_da = (bit<128>)headers.ipv6.dstAddr;
        meta.l3_metadata.lkp_ip_proto = (bit<8>)headers.ipv6.nextHdr;
        meta.l3_metadata.lkp_ip_ttl = (bit<8>)headers.ipv6.hopLimit;
        meta.l3_metadata.lkp_l4_sport = (bit<16>)meta.l3_metadata.lkp_outer_l4_sport;
        meta.l3_metadata.lkp_l4_dport = (bit<16>)meta.l3_metadata.lkp_outer_l4_dport;
    }    
    table adjust_lkp_fields {
        key = {
            headers.ipv4.isValid()  : exact;
            headers.ipv6.isValid()  : exact;
        }
        actions = {
            non_ip_lkp;
            ipv4_lkp;
            ipv6_lkp;
        }
    }
#endif

    apply 
    {
        port_vlan_mapping.apply();
#ifdef TUNNEL_DISABLE
        adjust_lkp_fields.apply();
#endif
    }
}


/*****************************************************************************/
/* Ingress BD stats based on packet type                                     */
/*****************************************************************************/
control process_ingress_bd_stats(inout metadata meta)
{
#ifndef STATS_DISABLE
    @min_width(32) counter<bit<10>>(BD_STATS_TABLE_SIZE, CounterType.packets_and_bytes) ingress_bd_stats_counter;
    action update_ingress_bd_stats() 
    {
        ingress_bd_stats_counter.count((bit<10>)meta.l2_metadata.bd_stats_idx);
    }
#endif /* STATS_DISABLE */

    apply
    {
#ifndef STATS_DISABLE
        update_ingress_bd_stats();
#endif /* STATS_DISABLE */
    }
}


/*****************************************************************************/
/* LAG lookup/resolution                                                     */
/*****************************************************************************/


control process_lag(inout metadata meta,
                    inout standard_metadata_t standard_metadata)
{
    @mode("fair") action_selector(HashAlgorithm.identity, BD_STATS_TABLE_SIZE, LAG_BIT_WIDTH) lag_action_profile;
    action set_lag_miss() {}
    action set_lag_port(bit<9> port) 
    {
        standard_metadata.egress_spec = port;
    }
#ifdef FABRIC_ENABLE
    action set_lag_remote_port(bit<8> device, bit<16> port) 
    {
        meta.fabric_metadata.dst_device = device;
        meta.fabric_metadata.dst_port = port;
    }
#endif /* FABRIC_ENABLE */
    table lag_group 
    {
        actions = {
            set_lag_miss;
            set_lag_port;
#ifdef FABRIC_ENABLE
            set_lag_remote_port;
#endif /* FABRIC_ENABLE */
        }
        key = {
            meta.ingress_metadata.egress_ifindex    : exact;
            meta.hash_metadata.hash2                : selector;
        }
        size = LAG_GROUP_TABLE_SIZE;
        implementation = lag_action_profile;
    }
    apply 
    {
        lag_group.apply();
    }
}

/*****************************************************************************/
/* Egress VLAN translation                                                   */
/*****************************************************************************/
control process_vlan_xlate(inout headers_t headers, 
                           inout metadata meta)
{
    action set_egress_packet_vlan_untagged() {}
    action set_egress_packet_vlan_tagged(bit<12> vlan_id)
    {
        headers.vlan_tag[0].setValid();
        headers.vlan_tag[0].etherType = (bit<16>)headers.ethernet.etherType;
        headers.vlan_tag[0].vid = vlan_id;
        headers.ethernet.etherType = ETHERTYPE_VLAN;
    }
    action set_egress_packet_vlan_double_tagged(bit<12> s_tag, bit<12> c_tag)
    {
        headers.vlan_tag[1].setValid();
        headers.vlan_tag[0].setValid();
        headers.vlan_tag[1].etherType = (bit<16>)headers.ethernet.etherType;
        headers.vlan_tag[1].vid = c_tag;
        headers.vlan_tag[0].etherType = ETHERTYPE_VLAN;
        headers.vlan_tag[0].vid = s_tag;
        headers.ethernet.etherType = ETHERTYPE_QINQ;
    }
    table egress_vlan_xlate
    {
        key = {
            meta.egress_metadata.ifindex    : exact;
            meta.egress_metadata.bd         : exact;
        }
        actions = {
            set_egress_packet_vlan_untagged;
            set_egress_packet_vlan_tagged;
            set_egress_packet_vlan_double_tagged;
        }
        size = EGRESS_VLAN_XLATE_TABLE_SIZE;
    }

    apply
    {
        egress_vlan_xlate.apply();
    }
}