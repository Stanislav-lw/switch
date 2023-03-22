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
 * Tunnel processing
 */

/*****************************************************************************/
/* IPv4 source and destination VTEP lookups                                  */
/*****************************************************************************/
control process_ipv4_vtep(inout headers_t headers, inout metadata meta)
{
#ifndef TUNNEL_DISABLE
#ifndef IPV4_DISABLE
    action nop() {}
    action set_tunnel_termination_flag()
    {
        meta.tunnel_metadata.tunnel_terminate = TRUE;
    }
    action set_tunnel_vni_and_termination_flag(bit<24> tunnel_vni)
    {
        meta.tunnel_metadata.tunnel_vni = tunnel_vni;
        meta.tunnel_metadata.tunnel_terminate = TRUE;
    }
    table ipv4_dest_vtep
    {
        key = {
            meta.l3_metadata.vrf                     : exact;
            headers.ipv4.dstAddr                     : exact;
            meta.tunnel_metadata.ingress_tunnel_type : exact;
        }
        actions = {
            nop;
            set_tunnel_termination_flag;
            set_tunnel_vni_and_termination_flag;
        }
        size = DEST_TUNNEL_TABLE_SIZE;
    }
    action on_miss() {}
    action src_vtep_hit(bit<16> ifindex)
    {
        meta.ingress_metadata.ifindex = ifindex;
    }
    table ipv4_src_vtep
    {
        key = {
            meta.l3_metadata.vrf                     : exact;
            headers.ipv4.srcAddr                     : exact;
            meta.tunnel_metadata.ingress_tunnel_type : exact;
        }
        actions = {
            on_miss;
            src_vtep_hit;
        }
        size = IPV4_SRC_TUNNEL_TABLE_SIZE;
    }
#endif /* IPV4_DISABLE */
#endif /* TUNNEL_DISABLE */

    apply
    {
#if !defined(TUNNEL_DISABLE) && !defined(IPV4_DISABLE)
        switch (ipv4_src_vtep.apply().action_run)
        {
            src_vtep_hit: {
                ipv4_dest_vtep.apply();
            }
        }
#endif /* TUNNEL_DISABLE && IPV4_DISABLE */
    }
}

/*****************************************************************************/
/* IPv6 source and destination VTEP lookups                                  */
/*****************************************************************************/
control process_ipv6_vtep(inout headers_t headers, inout metadata meta)
{
#ifndef TUNNEL_DISABLE
#ifndef IPV6_DISABLE
    action nop() {}
    action set_tunnel_termination_flag()
    {
        meta.tunnel_metadata.tunnel_terminate = TRUE;
    }
    action set_tunnel_vni_and_termination_flag(bit<24> tunnel_vni)
    {
        meta.tunnel_metadata.tunnel_vni = tunnel_vni;
        meta.tunnel_metadata.tunnel_terminate = TRUE;
    }
    table ipv6_dest_vtep
    {
        key = {
            meta.l3_metadata.vrf                    : exact;
            headers.ipv6.dstAddr                        : exact;
            meta.tunnel_metadata.ingress_tunnel_type: exact;
        }
        actions = {
            nop;
            set_tunnel_termination_flag;
            set_tunnel_vni_and_termination_flag;
        }
        size = DEST_TUNNEL_TABLE_SIZE;
    }
    action on_miss() {}
    action src_vtep_hit(bit<16> ifindex)
    {
        meta.ingress_metadata.ifindex = ifindex;
    }
    table ipv6_src_vtep 
    {
        key = {
            meta.l3_metadata.vrf                     : exact;
            headers.ipv6.srcAddr                     : exact;
            meta.tunnel_metadata.ingress_tunnel_type : exact;
        }
        actions = {
            on_miss;
            src_vtep_hit;
        }
        size = IPV6_SRC_TUNNEL_TABLE_SIZE;
    }
#endif /* IPV6_DISABLE */
#endif /* TUNNEL_DISABLE */

    apply
    {
#if !defined(TUNNEL_DISABLE) && !defined(IPV6_DISABLE)
        switch (ipv6_src_vtep.apply().action_run)
        {
            src_vtep_hit: {
                ipv6_dest_vtep.apply();
            }
        }
#endif /* TUNNEL_DISABLE && IPV6_DISABLE */
    }
}
/*****************************************************************************/
/* MPLS lookup/forwarding                                                    */
/*****************************************************************************/
control process_mpls(inout headers_t headers, inout metadata meta)
{
#if !defined(TUNNEL_DISABLE) && !defined(MPLS_DISABLE)
    action terminate_eompls(bit<16> bd, bit<5> tunnel_type)
    {
        meta.tunnel_metadata.tunnel_terminate = TRUE;
        meta.tunnel_metadata.ingress_tunnel_type = tunnel_type;
        meta.ingress_metadata.bd = bd;
        
        meta.l2_metadata.lkp_mac_type = (bit<16>)headers.inner_ethernet.etherType;
    }
    action terminate_vpls(bit<16> bd, bit<5> tunnel_type)
    {
        meta.tunnel_metadata.tunnel_terminate = TRUE;
        meta.tunnel_metadata.ingress_tunnel_type = tunnel_type;
        meta.ingress_metadata.bd = bd;
        
        meta.l2_metadata.lkp_mac_type = (bit<16>)headers.inner_ethernet.etherType;
    }
#ifndef IPV4_DISABLE
    action terminate_ipv4_over_mpls(bit<16> vrf, bit<5> tunnel_type)
    {
        meta.tunnel_metadata.tunnel_terminate = TRUE;
        meta.tunnel_metadata.ingress_tunnel_type = tunnel_type;
        meta.l3_metadata.vrf = vrf;
        
        meta.l2_metadata.lkp_mac_sa = (bit<48>)headers.ethernet.srcAddr;
        meta.l2_metadata.lkp_mac_da = (bit<48>)headers.ethernet.dstAddr;
        meta.l3_metadata.lkp_ip_type = IPTYPE_IPV4;
        meta.l2_metadata.lkp_mac_type = (bit<16>)headers.inner_ethernet.etherType;
        meta.l3_metadata.lkp_ip_version = (bit<4>)headers.inner_ipv4.version;
#ifdef QOS_DISABLE
        meta.l3_metadata.lkp_dscp = headers.inner_ipv4.diffserv;
#endif /* QOS_DISABLE */
    }
#endif /* IPV4_DISABLE */
#ifndef IPV6_DISABLE
    action terminate_ipv6_over_mpls(bit<16> vrf, bit<5> tunnel_type)
    {
        meta.tunnel_metadata.tunnel_terminate = TRUE;
        meta.tunnel_metadata.ingress_tunnel_type = tunnel_type;
        meta.l3_metadata.vrf = vrf;
        
        meta.l2_metadata.lkp_mac_sa = (bit<48>)headers.ethernet.srcAddr;
        meta.l2_metadata.lkp_mac_da = (bit<48>)headers.ethernet.dstAddr;
        meta.l3_metadata.lkp_ip_type = IPTYPE_IPV6;
        meta.l2_metadata.lkp_mac_type = (bit<16>)headers.inner_ethernet.etherType;
        meta.l3_metadata.lkp_ip_version = (bit<4>)headers.inner_ipv6.version;
#ifdef QOS_DISABLE
        meta.l3_metadata.lkp_dscp = headers.inner_ipv4.diffserv;
#endif /* QOS_DISABLE */
    }
#endif /* IPV6_DISABLE */
    action terminate_pw(bit<16> ifindex)
    {
        meta.ingress_metadata.egress_ifindex = ifindex;
        
        meta.l2_metadata.lkp_mac_sa = (bit<48>)headers.ethernet.srcAddr;
        meta.l2_metadata.lkp_mac_da = (bit<48>)headers.ethernet.dstAddr;
    }
    action forward_mpls(bit<16> nexthop_index)
    {
        meta.l3_metadata.fib_nexthop = nexthop_index;
        meta.l3_metadata.fib_nexthop_type = NEXTHOP_TYPE_SIMPLE;
        meta.l3_metadata.fib_hit = TRUE;
        
        meta.l2_metadata.lkp_mac_sa = (bit<48>)headers.ethernet.srcAddr;
        meta.l2_metadata.lkp_mac_da = (bit<48>)headers.ethernet.dstAddr;
    }
    table mpls 
    {
        key = {
            meta.tunnel_metadata.mpls_label    : exact;
            headers.inner_ipv4.isValid()       : exact;
            headers.inner_ipv6.isValid()       : exact;
        }
        actions = {
            terminate_eompls;
            terminate_vpls;
            terminate_ipv4_over_mpls;
            terminate_ipv6_over_mpls;
            terminate_pw;
            forward_mpls;
        }
        size = MPLS_TABLE_SIZE;
    }
#endif /* TUNNEL_DISABLE && MPLS_DISABLE */
    
    apply
    {
#if !defined(TUNNEL_DISABLE) && !defined(MPLS_DISABLE)
        mpls.apply();
#endif /* TUNNEL_DISABLE && MPLS_DISABLE */
    }
}
/*****************************************************************************/
/* Ingress tunnel processing                                                 */
/*****************************************************************************/
control process_tunnel(inout headers_t headers, inout metadata meta, inout standard_metadata_t standard_metadata)
{
    action nop() {}
    action lookup_miss() {}
    action terminate_tunnel_inner_non_ip(bit<16> bd, bit<16> bd_label, bit<16> stats_idx)
    {
        meta.tunnel_metadata.tunnel_terminate = TRUE;
        meta.ingress_metadata.bd = bd;
        meta.acl_metadata.bd_label = bd_label;
        meta.l2_metadata.bd_stats_idx = stats_idx;

        meta.l3_metadata.lkp_ip_type = IPTYPE_NONE;
        meta.l2_metadata.lkp_mac_type = (bit<16>)headers.inner_ethernet.etherType;
    }
#ifndef IPV4_DISABLE
    action terminate_tunnel_inner_ethernet_ipv4(bit<16> bd, bit<16> vrf,
                                                bit<10> rmac_group, bit<16> bd_label,
                                                bit<1> ipv4_unicast_enabled, bit<2> ipv4_urpf_mode,
                                                bit<1> igmp_snooping_enabled, bit<16> stats_idx,
                                                bit<1> ipv4_multicast_enabled, bit<16> mrpf_group)
    {
        meta.tunnel_metadata.tunnel_terminate = TRUE;
        meta.ingress_metadata.bd = bd;
        meta.l3_metadata.vrf = vrf;
        meta.ipv4_metadata.ipv4_unicast_enabled = ipv4_unicast_enabled;
        meta.ipv4_metadata.ipv4_urpf_mode = ipv4_urpf_mode;
        meta.l3_metadata.rmac_group = rmac_group;
        meta.acl_metadata.bd_label = bd_label;
        meta.l2_metadata.bd_stats_idx = stats_idx;

        meta.l3_metadata.lkp_ip_type = IPTYPE_IPV4;
        meta.l2_metadata.lkp_mac_type = (bit<16>)headers.inner_ethernet.etherType;
        meta.l3_metadata.lkp_ip_version = (bit<4>)headers.inner_ipv4.version;
#ifdef QOS_DISABLE
        meta.l3_metadata.lkp_dscp = headers.inner_ipv4.diffserv
#endif /* QOS_DISABLE */
        meta.multicast_metadata.igmp_snooping_enabled = igmp_snooping_enabled;
        meta.multicast_metadata.ipv4_multicast_enabled = ipv4_multicast_enabled;
        meta.multicast_metadata.bd_mrpf_group = mrpf_group;
    }
    action terminate_tunnel_inner_ipv4(bit<16> vrf, bit<10> rmac_group,
                                       bit<2> ipv4_urpf_mode, bit<1> ipv4_unicast_enabled,
                                       bit<1> ipv4_multicast_enabled, bit<16> mrpf_group)
    {
        meta.tunnel_metadata.tunnel_terminate = TRUE;
        meta.l3_metadata.vrf = vrf;
        meta.ipv4_metadata.ipv4_unicast_enabled = ipv4_unicast_enabled;
        meta.ipv4_metadata.ipv4_urpf_mode = ipv4_urpf_mode;
        meta.l3_metadata.rmac_group = rmac_group;

        meta.l2_metadata.lkp_mac_sa = (bit<48>)headers.ethernet.srcAddr;
        meta.l2_metadata.lkp_mac_da = (bit<48>)headers.ethernet.dstAddr;
        meta.l3_metadata.lkp_ip_type = IPTYPE_IPV4;
        meta.l3_metadata.lkp_ip_version = (bit<4>)headers.inner_ipv4.version;
#ifdef QOS_DISABLE
        meta.l3_metadata.lkp_dscp = headers.inner_ipv4.diffserv
#endif /* QOS_DISABLE */

        meta.multicast_metadata.bd_mrpf_group = mrpf_group;
        meta.multicast_metadata.ipv4_multicast_enabled = ipv4_multicast_enabled;
    }
#endif /* IPV4_DISABLE */
#ifndef IPV6_DISABLE
    action terminate_tunnel_inner_ethernet_ipv6(bit<16> bd, bit<16> vrf,
                                                bit<10> rmac_group, bit<16> bd_label,
                                                bit<1> ipv6_unicast_enabled, bit<2> ipv6_urpf_mode,
                                                bit<1> mld_snooping_enabled, bit<16> stats_idx,
                                                bit<1> ipv6_multicast_enabled, bit<16> mrpf_group)
    {
        meta.tunnel_metadata.tunnel_terminate = TRUE;
        meta.ingress_metadata.bd = bd;
        meta.l3_metadata.vrf = vrf;
        meta.ipv6_metadata.ipv6_unicast_enabled = ipv6_unicast_enabled;
        meta.ipv6_metadata.ipv6_urpf_mode = ipv6_urpf_mode;
        meta.l3_metadata.rmac_group = rmac_group;
        meta.acl_metadata.bd_label = bd_label;
        meta.l2_metadata.bd_stats_idx = stats_idx;

        meta.l3_metadata.lkp_ip_type = IPTYPE_IPV6;
        meta.l2_metadata.lkp_mac_type = (bit<16>)headers.inner_ethernet.etherType;
        meta.l3_metadata.lkp_ip_version = (bit<4>)headers.inner_ipv6.version;
#ifdef QOS_DISABLE
        meta.l3_metadata.lkp_dscp = headers.inner_ipv6.diffserv
#endif /* QOS_DISABLE */

        meta.multicast_metadata.bd_mrpf_group = mrpf_group;
        meta.multicast_metadata.ipv6_multicast_enabled = ipv6_multicast_enabled;
        meta.multicast_metadata.mld_snooping_enabled = mld_snooping_enabled;
    }
    action terminate_tunnel_inner_ipv6(bit<16> vrf, bit<10> rmac_group,
                                       bit<1> ipv6_unicast_enabled, bit<2> ipv6_urpf_mode,
                                       bit<1> ipv6_multicast_enabled, bit<16> mrpf_group)
    {
        meta.tunnel_metadata.tunnel_terminate = TRUE;
        meta.l3_metadata.vrf = vrf;
        meta.ipv6_metadata.ipv6_unicast_enabled = ipv6_unicast_enabled;
        meta.ipv6_metadata.ipv6_urpf_mode = ipv6_urpf_mode;
        meta.l3_metadata.rmac_group = rmac_group;

        meta.l2_metadata.lkp_mac_sa = (bit<48>)headers.ethernet.srcAddr;
        meta.l2_metadata.lkp_mac_da = (bit<48>)headers.ethernet.dstAddr;
        meta.l3_metadata.lkp_ip_type = IPTYPE_IPV6;
        meta.l3_metadata.lkp_ip_version = (bit<4>)headers.inner_ipv6.version;
#ifdef QOS_DISABLE
        meta.l3_metadata.lkp_dscp = headers.inner_ipv6.diffserv
#endif /* QOS_DISABLE */

        meta.multicast_metadata.bd_mrpf_group = mrpf_group;
        meta.multicast_metadata.ipv6_multicast_enabled = ipv6_multicast_enabled;
    }
#endif /* IPV6_DISABLE */
    table tunnel
    {
        key = {
            meta.tunnel_metadata.tunnel_vni             : exact;
            meta.tunnel_metadata.ingress_tunnel_type    : exact;
            headers.inner_ipv4.isValid()                : exact;
            headers.inner_ipv6.isValid()                : exact;
        }
        actions = {
            nop;
            lookup_miss;
            terminate_tunnel_inner_non_ip;
#ifndef IPV4_DISABLE
            terminate_tunnel_inner_ethernet_ipv4;
            terminate_tunnel_inner_ipv4;
#endif /* IPV4_DISABLE */
#ifndef IPV6_DISABLE
            terminate_tunnel_inner_ethernet_ipv6;
            terminate_tunnel_inner_ipv6;
#endif /* IPV6_DISABLE */
        }
        size = VNID_MAPPING_TABLE_SIZE;
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
    action non_ip_lkp()
    {
        meta.l2_metadata.lkp_mac_sa = (bit<48>)headers.ethernet.srcAddr;
        meta.l2_metadata.lkp_mac_da = (bit<48>)headers.ethernet.dstAddr;
    }
    table adjust_lkp_fields 
    {
        key = {
            headers.ipv4.isValid()  : exact;
            headers.ipv6.isValid()  : exact;
        }
        actions = {
            non_ip_lkp;
            ipv4_lkp;
#ifndef IPV6_DISABLE
            ipv6_lkp;
#endif /* IPV6_DISABLE */
        }
    }
    table tunnel_lookup_miss
    {
        key = {
            headers.ipv4.isValid()  : exact;
            headers.ipv6.isValid()  : exact;
        }
        actions = {
            non_ip_lkp;
            ipv4_lkp;
#ifndef IPV6_DISABLE
            ipv6_lkp;
#endif /* IPV6_DISABLE */
        }
    }
#ifndef TUNNEL_DISABLE
    action on_miss() {}
    action outer_rmac_hit() {
        meta.l3_metadata.rmac_hit = TRUE;
    }
    table outer_rmac {
        key = {
            meta.l3_metadata.rmac_group : exact;
            headers.ethernet.dstAddr    : exact;
        }
        actions = {
            on_miss;
            outer_rmac_hit;
        }
        size = OUTER_ROUTER_MAC_TABLE_SIZE;
    }
#endif /* TUNNEL_DISABLE */

    apply
    {
        /* ingress fabric processing */
        process_ingress_fabric.apply(headers, meta, standard_metadata);
#ifndef TUNNEL_DISABLE 
        if (meta.tunnel_metadata.ingress_tunnel_type != INGRESS_TUNNEL_TYPE_NONE) {
            /* Outer router mac lookup */
            switch (outer_rmac.apply().action_run) {
                on_miss: {
                    process_outer_multicast.apply(headers, meta);
                }
                default: {
                    if (headers.ipv4.isValid()) {
                        process_ipv4_vtep.apply(headers, meta);
                    } else {
                        if (headers.ipv6.isValid()) {
                            process_ipv6_vtep.apply(headers, meta);
                        } else {
/* check for mpls tunnel termination */
#ifndef MPLS_DISABLE
                            if (headers.mpls[0].isValid()) {
                                process_mpls.apply(headers, meta);
                            }
#endif /* MPLS_DISABLE */
                        }
                    }
                }
            }
        }
        
        /* perform tunnel termination */
        if (meta.tunnel_metadata.tunnel_terminate == TRUE || 
            meta.multicast_metadata.outer_mcast_route_hit == TRUE &&
            (meta.multicast_metadata.outer_mcast_mode == MCAST_MODE_SM && 
             meta.multicast_metadata.mcast_rpf_group == 16w0 ||
             meta.multicast_metadata.outer_mcast_mode == MCAST_MODE_BIDIR &&
             meta.multicast_metadata.mcast_rpf_group != 16w0)) 
        {
            switch (tunnel.apply().action_run) {
                lookup_miss: {
                    tunnel_lookup_miss.apply();
                }
            }
        } else {
            adjust_lkp_fields.apply();
        }
#endif /* TUNNEL_DISABLE */
    }
}

/*****************************************************************************/
/* Validate MPLS header                                                      */
/*****************************************************************************/
control validate_mpls_header(inout headers_t headers, inout metadata meta)
{
#if !defined(TUNNEL_DISABLE) && !defined(MPLS_DISABLE)
    action set_valid_mpls_label1()
    {
        meta.tunnel_metadata.mpls_label = (bit<20>)headers.mpls[0].label;
        meta.tunnel_metadata.mpls_exp = (bit<3>)headers.mpls[0].exp;
    }
    action set_valid_mpls_label2()
    {
        meta.tunnel_metadata.mpls_label = (bit<20>)headers.mpls[1].label;
        meta.tunnel_metadata.mpls_exp = (bit<3>)headers.mpls[1].exp;
    }
    action set_valid_mpls_label3()
    {
        meta.tunnel_metadata.mpls_label = (bit<20>)headers.mpls[2].label;
        meta.tunnel_metadata.mpls_exp = (bit<3>)headers.mpls[2].exp;
    }
    table validate_mpls_packet
    {
        key = {
            headers.mpls[0].label    : ternary;
            headers.mpls[0].bos      : ternary;
            headers.mpls[0].isValid(): exact;
            headers.mpls[1].label    : ternary;
            headers.mpls[1].bos      : ternary;
            headers.mpls[1].isValid(): exact;
            headers.mpls[2].label    : ternary;
            headers.mpls[2].bos      : ternary;
            headers.mpls[2].isValid(): exact;
        }
        actions = {
            set_valid_mpls_label1;
            set_valid_mpls_label2;
            set_valid_mpls_label3;
            //TODO: Redirect to cpu if more than 5 labels
        }
        size = VALIDATE_MPLS_TABLE_SIZE;
    }
#endif /* TUNNEL_DISABLE && MPLS_DISABLE */

    apply 
    {
#if !defined(TUNNEL_DISABLE) && !defined(MPLS_DISABLE)
        validate_mpls_packet.apply();
#endif /* TUNNEL_DISABLE && MPLS_DISABLE */
    }
}
/*****************************************************************************/
/* Tunnel decap processing                                                   */
/*****************************************************************************/
control process_tunnel_decap(inout headers_t headers, inout metadata meta)
{
#ifndef TUNNEL_DISABLE
    action decap_vxlan_inner_ipv4()
    {
        headers.ethernet = headers.inner_ethernet;
        headers.ipv4 = headers.inner_ipv4;
        headers.vxlan.setInvalid();
        headers.ipv6.setInvalid();
        headers.inner_ethernet.setInvalid();
        headers.inner_ipv4.setInvalid();
    }
    action decap_vxlan_inner_ipv6()
    {
        headers.ethernet = headers.inner_ethernet;
        headers.ipv6 = headers.inner_ipv6;
        headers.vxlan.setInvalid();
        headers.ipv4.setInvalid();
        headers.inner_ethernet.setInvalid();
        headers.inner_ipv6.setInvalid();
    }
    action decap_vxlan_inner_non_ip()
    {
        headers.ethernet = headers.inner_ethernet;
        headers.vxlan.setInvalid();
        headers.ipv4.setInvalid();
        headers.ipv6.setInvalid();
        headers.inner_ethernet.setInvalid();
    }
    action decap_genv_inner_ipv4()
    {
        headers.ethernet = headers.inner_ethernet;
        headers.ipv4 = headers.inner_ipv4;
        headers.genv.setInvalid();
        headers.ipv6.setInvalid();
        headers.inner_ethernet.setInvalid();
        headers.inner_ipv4.setInvalid();
    }
    action decap_genv_inner_ipv6()
    {
        headers.ethernet = headers.inner_ethernet;
        headers.ipv6 = headers.inner_ipv6;
        headers.genv.setInvalid();
        headers.ipv4.setInvalid();
        headers.inner_ethernet.setInvalid();
        headers.inner_ipv6.setInvalid();
    }
    action decap_genv_inner_non_ip()
    {
        headers.ethernet = headers.inner_ethernet;
        headers.genv.setInvalid();
        headers.ipv4.setInvalid();
        headers.ipv6.setInvalid();
        headers.inner_ethernet.setInvalid();
    }
#ifndef NVGRE_DISABLE
    action decap_nvgre_inner_ipv4()
    {
        headers.ethernet = headers.inner_ethernet;
        headers.ipv4 = headers.inner_ipv4;
        headers.nvgre.setInvalid();
        headers.gre.setInvalid();
        headers.ipv6.setInvalid();
        headers.inner_ethernet.setInvalid();
        headers.inner_ipv4.setInvalid();
    }
    action decap_nvgre_inner_ipv6()
    {
        headers.ethernet = headers.inner_ethernet;
        headers.ipv6 = headers.inner_ipv6;
        headers.nvgre.setInvalid();
        headers.gre.setInvalid();
        headers.ipv4.setInvalid();
        headers.inner_ethernet.setInvalid();
        headers.inner_ipv6.setInvalid();
    }
    action decap_nvgre_inner_non_ip()
    {
        headers.ethernet = headers.inner_ethernet;
        headers.nvgre.setInvalid();
        headers.gre.setInvalid();
        headers.ipv4.setInvalid();
        headers.ipv6.setInvalid();
        headers.inner_ethernet.setInvalid();
    }
#endif /* NVGRE_DISABLE */
    action decap_gre_inner_ipv4()
    {
        headers.ipv4 = headers.inner_ipv4;
        headers.gre.setInvalid();
        headers.ipv6.setInvalid();
        headers.inner_ipv4.setInvalid();
        headers.ethernet.etherType = ETHERTYPE_IPV4;
    }
    action decap_gre_inner_ipv6()
    {
        headers.ipv6 = headers.inner_ipv6;
        headers.gre.setInvalid();
        headers.ipv4.setInvalid();
        headers.inner_ipv6.setInvalid();
        headers.ethernet.etherType = ETHERTYPE_IPV6;
    }
    action decap_gre_inner_non_ip()
    {
        headers.ethernet.etherType = (bit<16>)headers.gre.proto;
        headers.gre.setInvalid();
        headers.ipv4.setInvalid();
        headers.inner_ipv6.setInvalid();
    }
    action decap_ip_inner_ipv4()
    {
        headers.ipv4 = headers.inner_ipv4;
        headers.ipv6.setInvalid();
        headers.inner_ipv4.setInvalid();
        headers.ethernet.etherType = ETHERTYPE_IPV4;
    }
    action decap_ip_inner_ipv6()
    {
        headers.ipv6 = headers.inner_ipv6;
        headers.ipv4.setInvalid();
        headers.inner_ipv6.setInvalid();
        headers.ethernet.etherType = ETHERTYPE_IPV6;
    }
#ifndef MPLS_DISABLE
    action decap_mpls_inner_ipv4_pop1()
    {
        headers.mpls[0].setInvalid();
        headers.ipv4 = headers.inner_ipv4;
        headers.inner_ipv4.setInvalid();
        headers.ethernet.etherType = ETHERTYPE_IPV4;
    }
    action decap_mpls_inner_ipv6_pop1()
    {
        headers.mpls[0].setInvalid();
        headers.ipv6 = headers.inner_ipv6;
        headers.inner_ipv6.setInvalid();
        headers.ethernet.etherType = ETHERTYPE_IPV6;
    }
    action decap_mpls_inner_ethernet_ipv4_pop1()
    {
        headers.mpls[0].setInvalid();
        headers.ethernet = headers.inner_ethernet;
        headers.ipv4 = headers.inner_ipv4;
        headers.inner_ethernet.setInvalid();
        headers.inner_ipv4.setInvalid();
    }
    action decap_mpls_inner_ethernet_ipv6_pop1()
    {
        headers.mpls[0].setInvalid();
        headers.ethernet = headers.inner_ethernet;
        headers.ipv6 = headers.inner_ipv6;
        headers.inner_ethernet.setInvalid();
        headers.inner_ipv6.setInvalid();
    }
    action decap_mpls_inner_ethernet_non_ip_pop1()
    {
        headers.mpls[0].setInvalid();
        headers.ethernet = headers.inner_ethernet;
        headers.inner_ethernet.setInvalid();
    }
    action decap_mpls_inner_ipv4_pop2()
    {
        headers.mpls[0].setInvalid();
        headers.mpls[1].setInvalid();
        headers.ipv4 = headers.inner_ipv4;
        headers.inner_ipv4.setInvalid();
        headers.ethernet.etherType = ETHERTYPE_IPV4;
    }
    action decap_mpls_inner_ipv6_pop2()
    {
        headers.mpls[0].setInvalid();
        headers.mpls[1].setInvalid();
        headers.ipv6 = headers.inner_ipv6;
        headers.inner_ipv6.setInvalid();
        headers.ethernet.etherType = ETHERTYPE_IPV6;
    }
    action decap_mpls_inner_ethernet_ipv4_pop2()
    {
        headers.mpls[0].setInvalid();
        headers.mpls[1].setInvalid();
        headers.ethernet = headers.inner_ethernet;
        headers.ipv4 = headers.inner_ipv4;
        headers.inner_ethernet.setInvalid();
        headers.inner_ipv4.setInvalid();
    }
    action decap_mpls_inner_ethernet_ipv6_pop2()
    {
        headers.mpls[0].setInvalid();
        headers.mpls[1].setInvalid();
        headers.ethernet = headers.inner_ethernet;
        headers.ipv6 = headers.inner_ipv6;
        headers.inner_ethernet.setInvalid();
        headers.inner_ipv6.setInvalid();
    }
    action decap_mpls_inner_ethernet_non_ip_pop2()
    {
        headers.mpls[0].setInvalid();
        headers.mpls[1].setInvalid();
        headers.ethernet = headers.inner_ethernet;
        headers.inner_ethernet.setInvalid();
    }
    action decap_mpls_inner_ipv4_pop3()
    {
        headers.mpls[0].setInvalid();
        headers.mpls[1].setInvalid();
        headers.mpls[2].setInvalid();
        headers.ipv4 = headers.inner_ipv4;
        headers.inner_ipv4.setInvalid();
        headers.ethernet.etherType = ETHERTYPE_IPV4;
    }
    action decap_mpls_inner_ipv6_pop3()
    {
        headers.mpls[0].setInvalid();
        headers.mpls[1].setInvalid();
        headers.mpls[2].setInvalid();
        headers.ipv6 = headers.inner_ipv6;
        headers.inner_ipv6.setInvalid();
        headers.ethernet.etherType = ETHERTYPE_IPV6;
    }
    action decap_mpls_inner_ethernet_ipv4_pop3()
    {
        headers.mpls[0].setInvalid();
        headers.mpls[1].setInvalid();
        headers.mpls[2].setInvalid();
        headers.ethernet = headers.inner_ethernet;
        headers.ipv4 = headers.inner_ipv4;
        headers.inner_ethernet.setInvalid();
        headers.inner_ipv4.setInvalid();
    }
    action decap_mpls_inner_ethernet_ipv6_pop3()
    {
        headers.mpls[0].setInvalid();
        headers.mpls[1].setInvalid();
        headers.mpls[2].setInvalid();
        headers.ethernet = headers.inner_ethernet;
        headers.ipv6 = headers.inner_ipv6;
        headers.inner_ethernet.setInvalid();
        headers.inner_ipv6.setInvalid();
    }
    action decap_mpls_inner_ethernet_non_ip_pop3()
    {
        headers.mpls[0].setInvalid();
        headers.mpls[1].setInvalid();
        headers.mpls[2].setInvalid();
        headers.ethernet = headers.inner_ethernet;
        headers.inner_ethernet.setInvalid();
    }
#endif /* MPLS_DISABLE */
    table tunnel_decap_process_outer
    {
        key = {
            meta.tunnel_metadata.ingress_tunnel_type : exact;
            headers.inner_ipv4.isValid()             : exact;
            headers.inner_ipv6.isValid()             : exact;
        }
        actions = {
            decap_vxlan_inner_ipv4;
            decap_vxlan_inner_ipv6;
            decap_vxlan_inner_non_ip;
            decap_genv_inner_ipv4;
            decap_genv_inner_ipv6;
            decap_genv_inner_non_ip;
#ifndef NVGRE_DISABLE
            decap_nvgre_inner_ipv4;
            decap_nvgre_inner_ipv6;
            decap_nvgre_inner_non_ip;
#endif /* NVGRE_DISABLE */
            decap_gre_inner_ipv4;
            decap_gre_inner_ipv6;
            decap_gre_inner_non_ip;
            decap_ip_inner_ipv4;
            decap_ip_inner_ipv6;
#ifndef MPLS_DISABLE
            decap_mpls_inner_ipv4_pop1;
            decap_mpls_inner_ipv6_pop1;
            decap_mpls_inner_ethernet_ipv4_pop1;
            decap_mpls_inner_ethernet_ipv6_pop1;
            decap_mpls_inner_ethernet_non_ip_pop1;
            decap_mpls_inner_ipv4_pop2;
            decap_mpls_inner_ipv6_pop2;
            decap_mpls_inner_ethernet_ipv4_pop2;
            decap_mpls_inner_ethernet_ipv6_pop2;
            decap_mpls_inner_ethernet_non_ip_pop2;
            decap_mpls_inner_ipv4_pop3;
            decap_mpls_inner_ipv6_pop3;
            decap_mpls_inner_ethernet_ipv4_pop3;
            decap_mpls_inner_ethernet_ipv6_pop3;
            decap_mpls_inner_ethernet_non_ip_pop3;
#endif /* MPLS_DISABLE */
        }
        size = TUNNEL_DECAP_TABLE_SIZE;
    }
    action decap_inner_udp()
    {
        headers.udp = headers.inner_udp;
        headers.inner_udp.setInvalid();
    }
    action decap_inner_tcp()
    {
        headers.tcp = headers.inner_tcp;
        headers.inner_tcp.setInvalid();
        headers.udp.setInvalid();
    }
    action decap_inner_icmp()
    {
        headers.icmp = headers.inner_icmp;
        headers.inner_icmp.setInvalid();
        headers.udp.setInvalid();
    }
    action decap_inner_unknown()
    {
        headers.udp.setInvalid();
    }
    table tunnel_decap_process_inner
    {
        key = {
            headers.inner_tcp.isValid()  : exact;
            headers.inner_udp.isValid()  : exact;
            headers.inner_icmp.isValid() : exact;
        }
        actions = {
            decap_inner_udp;
            decap_inner_tcp;
            decap_inner_icmp;
            decap_inner_unknown;
        }
        size = TUNNEL_DECAP_TABLE_SIZE;
    }
#endif /* TUNNEL_DISABLE */

    apply
    {
#ifndef TUNNEL_DISABLE
        if (meta.tunnel_metadata.tunnel_terminate == TRUE) {
            if ((meta.multicast_metadata.inner_replica == TRUE) ||
                (meta.multicast_metadata.replica == FALSE)) {
                tunnel_decap_process_outer.apply();
                tunnel_decap_process_inner.apply();
            }
        }
#endif /* TUNNEL_DISABLE */
    }
}





control process_tunnel_encap(inout headers_t headers, inout metadata meta, inout standard_metadata_t standard_metadata)
{   
    action nop() {}
    action set_egress_tunnel_vni(bit<24> vnid)
    {
        meta.tunnel_metadata.vnid = vnid;
    }
    table egress_vni
    {
        key = {
            meta.egress_metadata.bd                 : exact;
            meta.tunnel_metadata.egress_tunnel_type : exact;
        }
        actions = {
            nop;
            set_egress_tunnel_vni;
        }
        size = EGRESS_VNID_MAPPING_TABLE_SIZE;
    }
    action inner_ipv4_udp_rewrite()
    {
        headers.inner_ipv4 = headers.ipv4;
        headers.inner_udp = headers.udp;
        meta.egress_metadata.payload_length = (bit<16>)headers.ipv4.totalLen;
        headers.udp.setInvalid();
        headers.ipv4.setInvalid();
        meta.tunnel_metadata.inner_ip_proto = IP_PROTOCOLS_IPV4;
    }
    action inner_ipv4_tcp_rewrite()
    {
        headers.inner_ipv4 = headers.ipv4;
        headers.inner_tcp = headers.tcp;
        meta.egress_metadata.payload_length = (bit<16>)headers.ipv4.totalLen;
        headers.tcp.setInvalid();
        headers.ipv4.setInvalid();
        meta.tunnel_metadata.inner_ip_proto = IP_PROTOCOLS_IPV4;
    }
    action inner_ipv4_icmp_rewrite()
    {
        headers.inner_ipv4 = headers.ipv4;
        headers.inner_icmp = headers.icmp;
        meta.egress_metadata.payload_length = (bit<16>)headers.ipv4.totalLen;
        headers.icmp.setInvalid();
        headers.ipv4.setInvalid();
        meta.tunnel_metadata.inner_ip_proto = IP_PROTOCOLS_IPV4;
    }
    action inner_ipv4_unknown_rewrite()
    {
        headers.inner_ipv4 = headers.ipv4;
        meta.egress_metadata.payload_length = (bit<16>)headers.ipv4.totalLen;
        headers.ipv4.setInvalid();
        meta.tunnel_metadata.inner_ip_proto = IP_PROTOCOLS_IPV4;
    }
    action inner_ipv6_udp_rewrite()
    {
        headers.inner_ipv6 = headers.ipv6;
        headers.inner_udp = headers.udp;
        meta.egress_metadata.payload_length = (bit<16>)headers.ipv6.payloadLen + 16w40;
        headers.ipv6.setInvalid();
        meta.tunnel_metadata.inner_ip_proto = IP_PROTOCOLS_IPV6;
    }
    action inner_ipv6_tcp_rewrite()
    {
        headers.inner_ipv6 = headers.ipv6;
        headers.inner_tcp = headers.tcp;
        meta.egress_metadata.payload_length = (bit<16>)headers.ipv6.payloadLen + 16w40;
        headers.tcp.setInvalid();
        headers.ipv6.setInvalid();
        meta.tunnel_metadata.inner_ip_proto = IP_PROTOCOLS_IPV6;
    }
    action inner_ipv6_icmp_rewrite()
    {
        headers.inner_ipv6 = headers.ipv6;
        headers.inner_icmp = headers.icmp;
        meta.egress_metadata.payload_length = (bit<16>)headers.ipv6.payloadLen + 16w40;
        headers.icmp.setInvalid();
        headers.ipv6.setInvalid();
        meta.tunnel_metadata.inner_ip_proto = IP_PROTOCOLS_IPV6;
    }
    action inner_ipv6_unknown_rewrite()
    {
        headers.inner_ipv6 = headers.ipv6;
        meta.egress_metadata.payload_length = (bit<16>)headers.ipv6.payloadLen + 16w40;
        headers.ipv6.setInvalid();
        meta.tunnel_metadata.inner_ip_proto = IP_PROTOCOLS_IPV6;
    }
    action inner_non_ip_rewrite()
    {
        meta.egress_metadata.payload_length = (bit<16>)standard_metadata.packet_length + 16w65522;
    }
    table tunnel_encap_process_inner
    {
       key = {
           headers.ipv4.isValid(): exact;
           headers.ipv6.isValid(): exact;
           headers.tcp.isValid() : exact;
           headers.udp.isValid() : exact;
           headers.icmp.isValid(): exact;
       }
       actions = {
           inner_ipv4_udp_rewrite;
           inner_ipv4_tcp_rewrite;
           inner_ipv4_icmp_rewrite;
           inner_ipv4_unknown_rewrite;
           inner_ipv6_udp_rewrite;
           inner_ipv6_tcp_rewrite;
           inner_ipv6_icmp_rewrite;
           inner_ipv6_unknown_rewrite;
           inner_non_ip_rewrite;
       }
       size = TUNNEL_HEADER_TABLE_SIZE;
    }
    action fabric_rewrite(bit<14> tunnel_index)
    {
        meta.tunnel_metadata.tunnel_index = tunnel_index;
    }
#ifndef TUNNEL_DISABLE
    action f_insert_vxlan_header()
    {
        headers.inner_ethernet = headers.ethernet;
        headers.udp.setValid();
        headers.vxlan.setValid();

        headers.udp.srcPort = (bit<16>)meta.hash_metadata.entropy_hash;
        headers.udp.dstPort = UDP_PORT_VXLAN;
        meta.l3_metadata.egress_l4_sport = (bit<16>)meta.hash_metadata.entropy_hash;
        meta.l3_metadata.egress_l4_dport = UDP_PORT_VXLAN;
        headers.udp.checksum = 16w0;
        headers.udp.length_ = (bit<16>)meta.egress_metadata.payload_length + 16w30;
        
        headers.vxlan.flags = 8w0x8;
        headers.vxlan.reserved = 24w0;
        headers.vxlan.vni = (bit<24>)meta.tunnel_metadata.vnid;
        headers.vxlan.reserved2 = 8w0;
    }
    action f_insert_ipv4_header(bit<8> proto)
    {
        headers.ipv4.setValid();
        headers.ipv4.protocol = (bit<8>)proto;
        headers.ipv4.ttl = 8w64;
        headers.ipv4.version = 4w0x4;
        headers.ipv4.ihl = 4w0x5;
        headers.ipv4.identification = 16w0;
    }
    action ipv4_vxlan_rewrite()
    {
        f_insert_vxlan_header();
        f_insert_ipv4_header(IP_PROTOCOLS_UDP);
        headers.ipv4.totalLen = (bit<16>)meta.egress_metadata.payload_length + 16w50;
        headers.ethernet.etherType = ETHERTYPE_IPV4;
    }
    action f_insert_genv_header()
    {
        headers.inner_ethernet = headers.ethernet;
        headers.udp.setValid();
        headers.genv.setValid();
        headers.udp.srcPort = (bit<16>)meta.hash_metadata.entropy_hash;
        headers.udp.dstPort = UDP_PORT_GENV;
        meta.l3_metadata.egress_l4_sport = (bit<16>)meta.hash_metadata.entropy_hash;
        meta.l3_metadata.egress_l4_dport = UDP_PORT_GENV;
        headers.udp.checksum = 16w0;
        headers.udp.length_ = (bit<16>)meta.egress_metadata.payload_length + 16w30;
        headers.genv.ver = 2w0;
        headers.genv.oam = 1w0;
        headers.genv.critical = 1w0;
        headers.genv.optLen = 6w0;
        headers.genv.protoType = ETHERTYPE_ETHERNET;
        headers.genv.vni = (bit<24>)meta.tunnel_metadata.vnid;
        headers.genv.reserved = 6w0;
        headers.genv.reserved2 = 8w0;
    }
    action ipv4_genv_rewrite() {
        f_insert_genv_header();
        f_insert_ipv4_header(IP_PROTOCOLS_UDP);
        headers.ipv4.totalLen = (bit<16>)meta.egress_metadata.payload_length + 16w50;
        headers.ethernet.etherType = ETHERTYPE_IPV4;
    }
#ifndef NVGRE_DISABLE
    action f_insert_nvgre_header()
    {
        headers.inner_ethernet = headers.ethernet;
        headers.gre.setValid();
        headers.nvgre.setValid();
        headers.gre.proto = ETHERTYPE_ETHERNET;
        headers.gre.recurse = 3w0;
        headers.gre.flags = 5w0;
        headers.gre.ver = 3w0;
        headers.gre.R = 1w0;
        headers.gre.K = 1w1;
        headers.gre.C = 1w0;
        headers.gre.S = 1w0;
        headers.gre.s = 1w0;
        headers.nvgre.tni = (bit<24>)meta.tunnel_metadata.vnid;
        headers.nvgre.flow_id[7:0] = ((bit<8>)meta.hash_metadata.entropy_hash)[7:0];
    }
    action ipv4_nvgre_rewrite() {
        f_insert_nvgre_header();
        f_insert_ipv4_header(IP_PROTOCOLS_GRE);
        headers.ipv4.totalLen = (bit<16>)meta.egress_metadata.payload_length + 16w42;
        headers.ethernet.etherType = ETHERTYPE_IPV4;
    }
#endif /* NVGRE_DISABLE */
    action f_insert_gre_header()
    {
        headers.gre.setValid();
    }
    action ipv4_gre_rewrite()
    {
        f_insert_gre_header();
        headers.gre.proto = (bit<16>)headers.ethernet.etherType;
        f_insert_ipv4_header(IP_PROTOCOLS_GRE);
        headers.ipv4.totalLen = (bit<16>)meta.egress_metadata.payload_length + 16w24;
        headers.ethernet.etherType = ETHERTYPE_IPV4;
    }
    action ipv4_ip_rewrite()
    {
        f_insert_ipv4_header(meta.tunnel_metadata.inner_ip_proto);
        headers.ipv4.totalLen = (bit<16>)meta.egress_metadata.payload_length + 16w20;
        headers.ethernet.etherType = ETHERTYPE_IPV4;
    }
#ifndef TUNNEL_OVER_IPV6_DISABLE
    action f_insert_ipv6_header(bit<8> proto) {
        headers.ipv6.setValid();
        headers.ipv6.version = 4w0x6;
        headers.ipv6.nextHdr = (bit<8>)proto;
        headers.ipv6.hopLimit = 8w64;
        headers.ipv6.trafficClass = 8w0;
        headers.ipv6.flowLabel = 20w0;
    }
    action ipv6_gre_rewrite()
    {
        f_insert_gre_header();
        headers.gre.proto = (bit<16>)headers.ethernet.etherType;
        f_insert_ipv6_header(IP_PROTOCOLS_GRE);
        headers.ipv6.payloadLen = (bit<16>)meta.egress_metadata.payload_length + 16w4;
        headers.ethernet.etherType = ETHERTYPE_IPV6;
    }
    action ipv6_ip_rewrite()
    {
        f_insert_ipv6_header(meta.tunnel_metadata.inner_ip_proto);
        headers.ipv6.payloadLen = (bit<16>)meta.egress_metadata.payload_length;
        headers.ethernet.etherType = 16w0x86dd;
    }
#ifndef NVGRE_DISABLE
    action ipv6_nvgre_rewrite()
    {
        f_insert_nvgre_header();
        f_insert_ipv6_header(IP_PROTOCOLS_GRE);
        headers.ipv6.payloadLen = (bit<16>)meta.egress_metadata.payload_length + 16w22;
        headers.ethernet.etherType = ETHERTYPE_IPV6;
    }
#endif /* NVGRE_DISABLE */
    action ipv6_vxlan_rewrite()
    {
        f_insert_vxlan_header();
        f_insert_ipv6_header(IP_PROTOCOLS_UDP);
        headers.ipv6.payloadLen = (bit<16>)meta.egress_metadata.payload_length + 16w30;
        headers.ethernet.etherType = ETHERTYPE_IPV6;
    }
    action ipv6_genv_rewrite()
    {
        f_insert_genv_header();
        f_insert_ipv6_header(IP_PROTOCOLS_UDP);
        headers.ipv6.payloadLen = (bit<16>)meta.egress_metadata.payload_length + 16w30;
        headers.ethernet.etherType = ETHERTYPE_IPV6;
    }
#endif /* TUNNEL_OVER_IPV6_DISABLE */
#ifndef MPLS_DISABLE
    action mpls_ethernet_push1_rewrite()
    {
        headers.inner_ethernet = headers.ethernet;
        headers.mpls.push_front(1);
        headers.mpls[0].setValid();
        headers.ethernet.etherType = ETHERTYPE_MPLS;
    }
    action mpls_ip_push1_rewrite()
    {
        headers.mpls.push_front(1);
        headers.mpls[0].setValid();
        headers.ethernet.etherType = ETHERTYPE_MPLS;
    }
    action mpls_ethernet_push2_rewrite()
    {
        headers.inner_ethernet = headers.ethernet;
        headers.mpls.push_front(2);
        headers.mpls[0].setValid();
        headers.mpls[1].setValid();
        headers.ethernet.etherType = ETHERTYPE_MPLS;
    }
    action mpls_ip_push2_rewrite()
    {
        headers.mpls.push_front(2);
        headers.mpls[0].setValid();
        headers.mpls[1].setValid();
        headers.ethernet.etherType = ETHERTYPE_MPLS;
    }
    action mpls_ethernet_push3_rewrite()
    {
        headers.inner_ethernet = headers.ethernet;
        headers.mpls.push_front(3);
        headers.mpls[0].setValid();
        headers.mpls[1].setValid();
        headers.mpls[2].setValid();
        headers.ethernet.etherType = ETHERTYPE_MPLS;
    }
    action mpls_ip_push3_rewrite()
    {
        headers.mpls.push_front(3);
        headers.mpls[0].setValid();
        headers.mpls[1].setValid();
        headers.mpls[2].setValid();
        headers.ethernet.etherType = ETHERTYPE_MPLS;
    }
#endif /* MPLS_DISABLE */
#endif /* TUNNEL_DISABLE */
#ifndef MIRROR_DISABLE
    action f_insert_erspan_common_header()
    {
        headers.inner_ethernet = headers.ethernet;
        headers.gre.setValid();
        headers.erspan_header_t3.setValid();
        headers.gre.C = 1w0;
        headers.gre.R = 1w0;
        headers.gre.K = 1w0;
        headers.gre.S = 1w0;
        headers.gre.s = 1w0;
        headers.gre.recurse = 3w0;
        headers.gre.flags = 5w0;
        headers.gre.ver = 3w0;
        headers.gre.proto = GRE_PROTOCOLS_ERSPAN_T3;
        headers.erspan_header_t3.timestamp = (bit<32>)meta.i2e_metadata.ingress_tstamp;
        headers.erspan_header_t3.span_id = (bit<10>)meta.i2e_metadata.mirror_session_id;
        headers.erspan_header_t3.version = 4w2;
        headers.erspan_header_t3.sgt = 16w0;
    }
    action f_insert_erspan_header_t3()
    {
        f_insert_erspan_common_header();
    }
    action ipv4_erspan_t3_rewrite()
    {
        f_insert_erspan_header_t3();
        f_insert_ipv4_header(IP_PROTOCOLS_GRE);
        headers.ipv4.totalLen = (bit<16>)meta.egress_metadata.payload_length + 16w50;
    }
    action ipv6_erspan_t3_rewrite()
    {
        f_insert_erspan_header_t3();
        f_insert_ipv6_header(IP_PROTOCOLS_GRE);
        headers.ipv6.payloadLen = (bit<16>)meta.egress_metadata.payload_length + 16w26;
    }
#endif /* MIRROR_DISABLE */
    table tunnel_encap_process_outer
    {
        key = {
            meta.tunnel_metadata.egress_tunnel_type  : exact;
            meta.tunnel_metadata.egress_header_count : exact;
            meta.multicast_metadata.replica          : exact;
        }
        actions = {
            nop;
            fabric_rewrite;
#ifndef TUNNEL_DISABLE
            ipv4_vxlan_rewrite;
            ipv4_genv_rewrite;
#ifndef NVGRE_DISABLE
            ipv4_nvgre_rewrite;
#endif /* NVGRE_DISABLE */
            ipv4_gre_rewrite;
            ipv4_ip_rewrite;
#ifndef TUNNEL_OVER_IPV6_DISABLE
            ipv6_gre_rewrite;
            ipv6_ip_rewrite;
#ifndef NVGRE_DISABLE
            ipv6_nvgre_rewrite;
#endif /* NVGRE_DISABLE */
            ipv6_vxlan_rewrite;
            ipv6_genv_rewrite;
#endif /* TUNNEL_OVER_IPV6_DISABLE */
#ifndef MPLS_DISABLE
            mpls_ethernet_push1_rewrite;
            mpls_ip_push1_rewrite;
            mpls_ethernet_push2_rewrite;
            mpls_ip_push2_rewrite;
            mpls_ethernet_push3_rewrite;
            mpls_ip_push3_rewrite;
#endif /* MPLS_DISABLE */
#endif /* TUNNEL_DISABLE */
#ifndef MIRROR_DISABLE
            ipv4_erspan_t3_rewrite;
            ipv6_erspan_t3_rewrite;
#endif /* MIRROR_DISABLE */
        }
        size = TUNNEL_HEADER_TABLE_SIZE;
    }
    action cpu_rx_rewrite()
    {
        headers.fabric_header.setValid();
        headers.fabric_header.headerVersion = 2w0;
        headers.fabric_header.packetVersion = 2w0;
        headers.fabric_header.pad1 = 1w0;
        headers.fabric_header.packetType = 3w5;
        headers.fabric_header_cpu.setValid();
        headers.fabric_header_cpu.ingressPort = (bit<16>)meta.ingress_metadata.ingress_port;
        headers.fabric_header_cpu.ingressIfindex = (bit<16>)meta.ingress_metadata.ifindex;
        headers.fabric_header_cpu.ingressBd = (bit<16>)meta.ingress_metadata.bd;
        headers.fabric_header_cpu.reasonCode = (bit<16>)meta.fabric_metadata.reason_code;
        headers.fabric_payload_header.setValid();
        headers.fabric_payload_header.etherType = (bit<16>)headers.ethernet.etherType;
        headers.ethernet.etherType = ETHERTYPE_BF_FABRIC;
    }
#if !defined(TUNNEL_DISABLE) || !defined(MIRROR_DISABLE)
    action set_tunnel_rewrite_details(bit<16> outer_bd, bit<9> smac_idx,
                                      bit<14> dmac_idx, bit<9> sip_index,
                                      bit<14> dip_index)
    {
        meta.egress_metadata.outer_bd = outer_bd;
        meta.tunnel_metadata.tunnel_smac_index = smac_idx;
        meta.tunnel_metadata.tunnel_dmac_index = dmac_idx;
        meta.tunnel_metadata.tunnel_src_index = sip_index;
        meta.tunnel_metadata.tunnel_dst_index = dip_index;
    }
#endif /* !TUNNEL_DISABLE || !MIRROR_DISABLE*/
#ifndef MPLS_DISABLE
    action set_mpls_rewrite_push1(bit<20> label1, bit<3> exp1,
                                  bit<8> ttl1, bit<9> smac_idx,
                                  bit<14> dmac_idx)
    {
        headers.mpls[0].label = label1;
        headers.mpls[0].exp = exp1;
        headers.mpls[0].bos = 1w0x1;
        headers.mpls[0].ttl = ttl1;
        meta.tunnel_metadata.tunnel_smac_index = smac_idx;
        meta.tunnel_metadata.tunnel_dmac_index = dmac_idx;
    }
    action set_mpls_rewrite_push2(bit<20> label1, bit<3> exp1,
                                  bit<8> ttl1, bit<20> label2,
                                  bit<3> exp2, bit<8> ttl2,
                                  bit<9> smac_idx, bit<14> dmac_idx)
    {
        headers.mpls[0].label = label1;
        headers.mpls[0].exp = exp1;
        headers.mpls[0].ttl = ttl1;
        headers.mpls[0].bos = 1w0x0;
        headers.mpls[1].label = label2;
        headers.mpls[1].exp = exp2;
        headers.mpls[1].ttl = ttl2;
        headers.mpls[1].bos = 1w0x1;
        meta.tunnel_metadata.tunnel_smac_index = smac_idx;
        meta.tunnel_metadata.tunnel_dmac_index = dmac_idx;
    }
    action set_mpls_rewrite_push3(bit<20> label1, bit<3> exp1,
                                  bit<8> ttl1, bit<20> label2, 
                                  bit<3> exp2, bit<8> ttl2,
                                  bit<20> label3, bit<3> exp3,
                                  bit<8> ttl3, bit<9> smac_idx, 
                                  bit<14> dmac_idx)
    {
        headers.mpls[0].label = label1;
        headers.mpls[0].exp = exp1;
        headers.mpls[0].ttl = ttl1;
        headers.mpls[0].bos = 1w0x0;
        headers.mpls[1].label = label2;
        headers.mpls[1].exp = exp2;
        headers.mpls[1].ttl = ttl2;
        headers.mpls[1].bos = 1w0x0;
        headers.mpls[2].label = label3;
        headers.mpls[2].exp = exp3;
        headers.mpls[2].ttl = ttl3;
        headers.mpls[2].bos = 1w0x1;
        meta.tunnel_metadata.tunnel_smac_index = smac_idx;
        meta.tunnel_metadata.tunnel_dmac_index = dmac_idx;
    }
#endif /* MPLS_DISABLE */
#ifdef FABRIC_ENABLE
    action fabric_unicast_rewrite()
    {
        headers.fabric_header.setValid();
        headers.fabric_header.headerVersion = 2w0;
        headers.fabric_header.packetVersion = 2w0;
        headers.fabric_header.pad1 = 1w0;
        headers.fabric_header.packetType = FABRIC_HEADER_TYPE_UNICAST;
        headers.fabric_header.dstDevice = (bit<8>)meta.fabric_metadata.dst_device;
        headers.fabric_header.dstPortOrGroup = (bit<16>)meta.fabric_metadata.dst_port;
        
        headers.fabric_header_unicast.setValid();
        headers.fabric_header_unicast.tunnelTerminate = (bit<1>)meta.tunnel_metadata.tunnel_terminate;
        headers.fabric_header_unicast.routed = (bit<1>)meta.l3_metadata.routed;
        headers.fabric_header_unicast.outerRouted = (bit<1>)meta.l3_metadata.outer_routed;
        headers.fabric_header_unicast.ingressTunnelType = (bit<5>)meta.tunnel_metadata.ingress_tunnel_type;
        headers.fabric_header_unicast.nexthopIndex = (bit<16>)meta.l3_metadata.nexthop_index;
        headers.fabric_payload_header.setValid();
        headers.fabric_payload_header.etherType = (bit<16>)headers.ethernet.etherType;
        headers.ethernet.etherType = ETHERTYPE_BF_FABRIC;
    }
#ifndef MULTICAST_DISABLE
    action fabric_multicast_rewrite(bit<16> fabric_mgid)
    {
        headers.fabric_header.setValid();
        headers.fabric_header.headerVersion = 2w0;
        headers.fabric_header.packetVersion = 2w0;
        headers.fabric_header.pad1 = 1w0;
        headers.fabric_header.packetType = FABRIC_HEADER_TYPE_MULTICAST;
        headers.fabric_header.dstDevice = FABRIC_DEVICE_MULTICAST;
        headers.fabric_header.dstPortOrGroup = fabric_mgid;
        headers.fabric_header_multicast.ingressIfindex = (bit<16>)meta.ingress_metadata.ifindex;
        headers.fabric_header_multicast.ingressBd = (bit<16>)meta.ingress_metadata.bd;
        
        headers.fabric_header_multicast.setValid();
        headers.fabric_header_multicast.tunnelTerminate = (bit<1>)meta.tunnel_metadata.tunnel_terminate;
        headers.fabric_header_multicast.routed = (bit<1>)meta.l3_metadata.routed;
        headers.fabric_header_multicast.outerRouted = (bit<1>)meta.l3_metadata.outer_routed;
        headers.fabric_header_multicast.ingressTunnelType = (bit<5>)meta.tunnel_metadata.ingress_tunnel_type;
        
        headers.fabric_header_multicast.mcastGrp = (bit<16>)meta.multicast_metadata.mcast_grp;
        
        headers.fabric_payload_header.setValid();
        headers.fabric_payload_header.etherType = (bit<16>)headers.ethernet.etherType;
        headers.ethernet.etherType = ETHERTYPE_BF_FABRIC;
    }
#endif /* MULTICAST_DISABLE */
#endif /* FABRIC_ENABLE */
    table tunnel_rewrite
    {
        key = {
            meta.tunnel_metadata.tunnel_index : exact;
        }
        actions = {
            nop;
            cpu_rx_rewrite;
#if !defined(TUNNEL_DISABLE) || !defined(MIRROR_DISABLE)
            set_tunnel_rewrite_details;
#endif /* !TUNNEL_DISABLE || !MIRROR_DISABLE*/
#ifndef MPLS_DISABLE
            set_mpls_rewrite_push1;
            set_mpls_rewrite_push2;
            set_mpls_rewrite_push3;
#endif /* MPLS_DISABLE */
#ifdef FABRIC_ENABLE
            fabric_unicast_rewrite;
#ifndef MULTICAST_DISABLE
            fabric_multicast_rewrite;
#endif /* MULTICAST_DISABLE */
#endif /* FABRIC_ENABLE */
        }
        size = TUNNEL_REWRITE_TABLE_SIZE;
    }
#if !defined(TUNNEL_DISABLE) || !defined(MIRROR_DISABLE)
    action tunnel_mtu_check(bit<16> l3_mtu)
    {
        meta.l3_metadata.l3_mtu_check = l3_mtu |-| (bit<16>)meta.egress_metadata.payload_length;
    }
    action tunnel_mtu_miss()
    {
        meta.l3_metadata.l3_mtu_check = 16w0xffff;
    }
    table tunnel_mtu
    {
        key = {
            meta.tunnel_metadata.tunnel_index : exact;
        }
        actions = {
            tunnel_mtu_check;
            tunnel_mtu_miss;
        }
        size = TUNNEL_REWRITE_TABLE_SIZE;
    }
    action rewrite_tunnel_ipv4_src(bit<32> ip)
    {
        headers.ipv4.srcAddr = ip;
    }
#ifndef IPV6_DISABLE
    action rewrite_tunnel_ipv6_src(bit<128> ip)
    {
        headers.ipv6.srcAddr = ip;
    }
#endif /* IPV6_DISABLE */
    table tunnel_src_rewrite
    {
        key = {
            meta.tunnel_metadata.tunnel_src_index: exact;
        }
        actions = {
            nop;
            rewrite_tunnel_ipv4_src;
#ifndef IPV6_DISABLE
            rewrite_tunnel_ipv6_src;
#endif /* IPV6_DISABLE */
        }
        size = TUNNEL_SRC_REWRITE_TABLE_SIZE;
    }
    action rewrite_tunnel_ipv4_dst(bit<32> ip)
    {
        headers.ipv4.dstAddr = ip;
    }
#ifndef IPV6_DISABLE
    action rewrite_tunnel_ipv6_dst(bit<128> ip)
    {
        headers.ipv6.dstAddr = ip;
    }
#endif /* IPV6_DISABLE */
    table tunnel_dst_rewrite
    {
        key = {
            meta.tunnel_metadata.tunnel_dst_index: exact;
        }
        actions = {
            nop;
            rewrite_tunnel_ipv4_dst;
#ifndef IPV6_DISABLE
            rewrite_tunnel_ipv6_dst;
#endif /* IPV6_DISABLE */
        }
        size = TUNNEL_DST_REWRITE_TABLE_SIZE;
    }    
    action rewrite_tunnel_smac(bit<48> smac)
    {
        headers.ethernet.srcAddr = smac;
    }
    table tunnel_smac_rewrite
    {
        key = {
            meta.tunnel_metadata.tunnel_smac_index : exact;
        }
        actions = {
            nop;
            rewrite_tunnel_smac;
        }
        size = TUNNEL_SMAC_REWRITE_TABLE_SIZE;
    }
    action rewrite_tunnel_dmac(bit<48> dmac)
    {
        headers.ethernet.dstAddr = dmac;
    }
    table tunnel_dmac_rewrite
    {
        key = {
            meta.tunnel_metadata.tunnel_dmac_index : exact;
        }
        actions = {
            nop;
            rewrite_tunnel_dmac;
        }
        size = TUNNEL_DMAC_REWRITE_TABLE_SIZE;
    }
#endif /* !TUNNEL_DISABLE || !MIRROR_DISABLE*/

    apply {
#ifndef TUNNEL_DISABLE
        if ((meta.fabric_metadata.fabric_header_present == FALSE) &&
            (meta.tunnel_metadata.egress_tunnel_type != EGRESS_TUNNEL_TYPE_NONE)) 
        {
            /* derive egress vni from egress bd */
            egress_vni.apply();

            /* tunnel rewrites */
            if ((meta.tunnel_metadata.egress_tunnel_type != EGRESS_TUNNEL_TYPE_FABRIC) &&
                (meta.tunnel_metadata.egress_tunnel_type != EGRESS_TUNNEL_TYPE_CPU)) 
            {
                tunnel_encap_process_inner.apply();
            }
            tunnel_encap_process_outer.apply();
            tunnel_rewrite.apply();
            tunnel_mtu.apply();
            /* rewrite tunnel src and dst ip */
            tunnel_src_rewrite.apply();
            tunnel_dst_rewrite.apply();
            /* rewrite tunnel src and dst ip */
            tunnel_smac_rewrite.apply();
            tunnel_dmac_rewrite.apply();
        }
#endif /* TUNNEL_DISABLE */
    }
}