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
 * Multicast processing
 */
/*****************************************************************************/
/* Outer IP multicast RPF check                                              */
/*****************************************************************************/
control process_outer_multicast_rpf(inout metadata meta)
{
#if !defined(TUNNEL_DISABLE) && !defined(MULTICAST_DISABLE)
    action nop() {}
    action outer_multicast_rpf_check_pass() 
    {
        meta.tunnel_metadata.tunnel_terminate = TRUE;
        meta.l3_metadata.outer_routed = TRUE;
    }

    table outer_multicast_rpf
    {
        key = {
            meta.multicast_metadata.mcast_rpf_group : exact;
            meta.multicast_metadata.bd_mrpf_group : exact;
        }
        actions = {
            nop;
            outer_multicast_rpf_check_pass;
        }
        size = OUTER_MCAST_RPF_TABLE_SIZE;
    }
#endif /* !TUNNEL_DISABLE && !MULTICAST_DISABLE */

    apply
    {
#if !defined(OUTER_PIM_BIDIR_OPTIMIZATION)
    /* outer mutlicast RPF check - sparse and bidir */
    if (meta.multicast_metadata.outer_mcast_route_hit == TRUE) {
        outer_multicast_rpf.apply();
    }
#endif /* !OUTER_PIM_BIDIR_OPTIMIZATION */
    }
}

/*****************************************************************************/
/* Outer IPv4 multicast lookup                                               */
/*****************************************************************************/
control process_outer_ipv4_multicast(inout headers_t headers, inout metadata meta)
{
#if  !defined(TUNNEL_DISABLE) && !defined(MULTICAST_DISABLE) && !defined(IPV4_DISABLE)
    action nop() {}
    action on_miss() {}
    action outer_multicast_route_s_g_hit(bit<16> mc_index, bit<16> mcast_rpf_group)
    {
        meta.intrinsic_metadata.mcast_grp = mc_index;
        meta.multicast_metadata.outer_mcast_route_hit = TRUE;
        meta.multicast_metadata.mcast_rpf_group = mcast_rpf_group ^ (bit<16>)meta.multicast_metadata.bd_mrpf_group;
#ifdef FABRIC_ENABLE
        meta.fabric_metadata.dst_device = FABRIC_DEVICE_MULTICAST;
#endif /* FABRIC_ENABLE */
    }
    action outer_multicast_bridge_s_g_hit(bit<16> mc_index)
    {
        meta.intrinsic_metadata.mcast_grp = mc_index;
        meta.tunnel_metadata.tunnel_terminate = TRUE;
#ifdef FABRIC_ENABLE
        meta.fabric_metadata.dst_device = FABRIC_DEVICE_MULTICAST;
#endif /* FABRIC_ENABLE */
    }
    table outer_ipv4_multicast
    {
        key = {
            meta.multicast_metadata.ipv4_mcast_key_type: exact;
            meta.multicast_metadata.ipv4_mcast_key     : exact;
            headers.ipv4.srcAddr                       : exact;
            headers.ipv4.dstAddr                       : exact;
        }
        actions = {
            nop;
            on_miss;
            outer_multicast_route_s_g_hit;
            outer_multicast_bridge_s_g_hit;
        }
        size = OUTER_MULTICAST_S_G_TABLE_SIZE;
    }
    action outer_multicast_route_sm_star_g_hit(bit<16> mc_index, bit<16> mcast_rpf_group)
    {
        meta.multicast_metadata.outer_mcast_mode = MCAST_MODE_SM;
        meta.intrinsic_metadata.mcast_grp = mc_index;
        meta.multicast_metadata.outer_mcast_route_hit = TRUE;
        meta.multicast_metadata.mcast_rpf_group = mcast_rpf_group ^ (bit<16>)meta.multicast_metadata.bd_mrpf_group;
#ifdef FABRIC_ENABLE
        meta.fabric_metadata.dst_device = FABRIC_DEVICE_MULTICAST;
#endif /* FABRIC_ENABLE */
    }
    action outer_multicast_route_bidir_star_g_hit(bit<16> mc_index, bit<16> mcast_rpf_group)
    {
        meta.multicast_metadata.outer_mcast_mode = MCAST_MODE_BIDIR;
        meta.intrinsic_metadata.mcast_grp = mc_index;
        meta.multicast_metadata.outer_mcast_route_hit = TRUE;
#ifdef OUTER_PIM_BIDIR_OPTIMIZATION
        meta.multicast_metadata.mcast_rpf_group = mcast_rpf_group | (bit<16>)meta.multicast_metadata.bd_mrpf_group;
#else
        meta.multicast_metadata.mcast_rpf_group = mcast_rpf_group;
#endif
#ifdef FABRIC_ENABLE
        meta.fabric_metadata.dst_device = FABRIC_DEVICE_MULTICAST;
#endif /* FABRIC_ENABLE */
    }
    action outer_multicast_bridge_star_g_hit(bit<16> mc_index)
    {
        meta.intrinsic_metadata.mcast_grp = mc_index;
        meta.tunnel_metadata.tunnel_terminate = TRUE;
#ifdef FABRIC_ENABLE
        meta.fabric_metadata.dst_device = FABRIC_DEVICE_MULTICAST;
#endif /* FABRIC_ENABLE */
    }
    table outer_ipv4_multicast_star_g
    {
        key = {
            meta.multicast_metadata.ipv4_mcast_key_type: exact;
            meta.multicast_metadata.ipv4_mcast_key     : exact;
            headers.ipv4.dstAddr                       : ternary;
        }
        actions = {
            nop;
            outer_multicast_route_sm_star_g_hit;
            outer_multicast_route_bidir_star_g_hit;
            outer_multicast_bridge_star_g_hit;
        }
        size = OUTER_MULTICAST_STAR_G_TABLE_SIZE;
    }
#endif /* !TUNNEL_DISABLE && !MULTICAST_DISABLE && !IPV4_DISABLE */

    apply
    {
#if  !defined(TUNNEL_DISABLE) && !defined(MULTICAST_DISABLE) && !defined(IPV4_DISABLE)
        /* check for ipv4 multicast tunnel termination  */
        switch (outer_ipv4_multicast.apply().action_run) {
            on_miss: {
                outer_ipv4_multicast_star_g.apply();
            }
        }
#endif /* !TUNNEL_DISABLE && !MULTICAST_DISABLE && !IPV4_DISABLE */
    }
}

/*****************************************************************************/
/* Outer IPv6 multicast lookup                                               */
/*****************************************************************************/
control process_outer_ipv6_multicast(inout headers_t headers, inout metadata meta)
{
#if !defined(TUNNEL_DISABLE) && !defined(MULTICAST_DISABLE) && !defined(IPV6_DISABLE)
    action nop() {}
    action on_miss() {}
    action outer_multicast_route_s_g_hit(bit<16> mc_index, bit<16> mcast_rpf_group)
    {
        meta.intrinsic_metadata.mcast_grp = mc_index;
        meta.multicast_metadata.outer_mcast_route_hit = TRUE;
        meta.multicast_metadata.mcast_rpf_group = mcast_rpf_group ^ (bit<16>)meta.multicast_metadata.bd_mrpf_group;
#ifdef FABRIC_ENABLE
        meta.fabric_metadata.dst_device = FABRIC_DEVICE_MULTICAST;
#endif /* FABRIC_ENABLE */
    }
    action outer_multicast_bridge_s_g_hit(bit<16> mc_index)
    {
        meta.intrinsic_metadata.mcast_grp = mc_index;
        meta.tunnel_metadata.tunnel_terminate = TRUE;
#ifdef FABRIC_ENABLE
        meta.fabric_metadata.dst_device = FABRIC_DEVICE_MULTICAST;
#endif /* FABRIC_ENABLE */
    }
    table outer_ipv6_multicast
    {
        key = {
            meta.multicast_metadata.ipv6_mcast_key_type: exact;
            meta.multicast_metadata.ipv6_mcast_key     : exact;
            headers.ipv6.srcAddr                       : exact;
            headers.ipv6.dstAddr                       : exact;
        }
        actions = {
            nop;
            on_miss;
            outer_multicast_route_s_g_hit;
            outer_multicast_bridge_s_g_hit;
        }
        size = OUTER_MULTICAST_S_G_TABLE_SIZE;
    }
    action outer_multicast_route_sm_star_g_hit(bit<16> mc_index, bit<16> mcast_rpf_group)
    {
        meta.multicast_metadata.outer_mcast_mode = MCAST_MODE_SM;
        meta.intrinsic_metadata.mcast_grp = mc_index;
        meta.multicast_metadata.outer_mcast_route_hit = TRUE;
        meta.multicast_metadata.mcast_rpf_group = mcast_rpf_group ^ (bit<16>)meta.multicast_metadata.bd_mrpf_group;
#ifdef FABRIC_ENABLE
        meta.fabric_metadata.dst_device = FABRIC_DEVICE_MULTICAST;
#endif /* FABRIC_ENABLE */
    }
    action outer_multicast_route_bidir_star_g_hit(bit<16> mc_index, bit<16> mcast_rpf_group)
    {
        meta.multicast_metadata.outer_mcast_mode = MCAST_MODE_BIDIR;
        meta.intrinsic_metadata.mcast_grp = mc_index;
        meta.multicast_metadata.outer_mcast_route_hit = TRUE;
#ifdef OUTER_PIM_BIDIR_OPTIMIZATION
        meta.multicast_metadata.mcast_rpf_group = mcast_rpf_group | (bit<16>)meta.multicast_metadata.bd_mrpf_group;
#else
        meta.multicast_metadata.mcast_rpf_group = mcast_rpf_group;
#endif
#ifdef FABRIC_ENABLE
        meta.fabric_metadata.dst_device = FABRIC_DEVICE_MULTICAST;
#endif /* FABRIC_ENABLE */
    }
    action outer_multicast_bridge_star_g_hit(bit<16> mc_index)
    {
        meta.intrinsic_metadata.mcast_grp = mc_index;
        meta.tunnel_metadata.tunnel_terminate = TRUE;
#ifdef FABRIC_ENABLE
        meta.fabric_metadata.dst_device = FABRIC_DEVICE_MULTICAST;
#endif /* FABRIC_ENABLE */
    }
    table outer_ipv6_multicast_star_g
    {
        key = {
            meta.multicast_metadata.ipv6_mcast_key_type: exact;
            meta.multicast_metadata.ipv6_mcast_key     : exact;
            headers.ipv6.dstAddr                       : ternary;
        }
        actions = {
            nop;
            outer_multicast_route_sm_star_g_hit;
            outer_multicast_route_bidir_star_g_hit;
            outer_multicast_bridge_star_g_hit;
        }
        size = OUTER_MULTICAST_STAR_G_TABLE_SIZE;
    }
#endif /* !TUNNEL_DISABLE && !MULTICAST_DISABLE && !IPV6_DISABLE */

    apply
    {
#if !defined(TUNNEL_DISABLE) && !defined(MULTICAST_DISABLE) && !defined(IPV6_DISABLE)
        /* check for ipv6 multicast tunnel termination  */
        switch (outer_ipv6_multicast.apply().action_run) {
            on_miss: {
                outer_ipv6_multicast_star_g.apply();
            }
        }
#endif /* !TUNNEL_DISABLE && !MULTICAST_DISABLE && !IPV6_DISABLE */
    }
}

/*****************************************************************************/
/* Process outer IP multicast                                                */
/*****************************************************************************/
control process_outer_multicast(inout headers_t headers, inout metadata meta)
{
    apply 
    {
#if !defined(TUNNEL_DISABLE) && !defined(MULTICAST_DISABLE)
        if (headers.ipv4.isValid()) {
            process_outer_ipv4_multicast.apply(headers, meta);
        } else {
            if (headers.ipv6.isValid()) {
                process_outer_ipv6_multicast.apply(headers, meta);
            }
        }
        process_outer_multicast_rpf.apply(meta);
#endif /* !TUNNEL_DISABLE && !MULTICAST_DISABLE */
    }
}


/*****************************************************************************/
/* IP multicast RPF check                                                    */
/*****************************************************************************/
control process_multicast_rpf(inout metadata meta)
{
#if !defined(L3_MULTICAST_DISABLE) && !defined(PIM_BIDIR_OPTIMIZATION)
    action multicast_rpf_check_pass()
    {
        meta.l3_metadata.routed = TRUE;
    }
    action multicast_rpf_check_fail()
    {
        meta.multicast_metadata.multicast_route_mc_index = 0;
        meta.multicast_metadata.mcast_route_hit = FALSE;
#ifdef FABRIC_ENABLE
        meta.fabric_metadata.dst_device = 0;
#endif /* FABRIC_ENABLE */
    }
    table multicast_rpf
    {
        key = {
            meta.multicast_metadata.mcast_rpf_group: exact;
            meta.multicast_metadata.bd_mrpf_group  : exact;
        }
        actions = {
            multicast_rpf_check_pass;
            multicast_rpf_check_fail;
        }
        size = MCAST_RPF_TABLE_SIZE;
    }
#endif /* !L3_MULTICAST_DISABLE && !PIM_BIDIR_OPTIMIZATION */

    apply
    {
#if !defined(L3_MULTICAST_DISABLE) && !defined(PIM_BIDIR_OPTIMIZATION)
    if (multicast_metadata.mcast_route_hit == TRUE) {
        multicast_rpf.apply();
    }
#endif /* !L3_MULTICAST_DISABLE && !PIM_BIDIR_OPTIMIZATION */
    }
}

/*****************************************************************************/
/* IPv4 multicast lookup                                                     */
/*****************************************************************************/
control process_ipv4_multicast(inout metadata meta)
{
#if !defined(L2_MULTICAST_DISABLE) && !defined(IPV4_DISABLE)
    action on_miss() {}
    action multicast_bridge_s_g_hit(bit<16> mc_index)
    {
        meta.multicast_metadata.multicast_bridge_mc_index = mc_index;
        meta.multicast_metadata.mcast_bridge_hit = TRUE;
    }
    table ipv4_multicast_bridge
    {
        key = {
            meta.ingress_metadata.bd      : exact;
            meta.ipv4_metadata.lkp_ipv4_sa: exact;
            meta.ipv4_metadata.lkp_ipv4_da: exact;
        }
        actions = {
            on_miss;
            multicast_bridge_s_g_hit;
        }
        size = IPV4_MULTICAST_S_G_TABLE_SIZE;
    }
    action nop() {}
    action multicast_bridge_star_g_hit(bit<16> mc_index)
    {
        meta.multicast_metadata.multicast_bridge_mc_index = mc_index;
        meta.multicast_metadata.mcast_bridge_hit = TRUE;
    }
    table ipv4_multicast_bridge_star_g
    {
        key = {
            meta.ingress_metadata.bd      : exact;
            meta.ipv4_metadata.lkp_ipv4_da: exact;
        }
        actions = {
            nop;
            multicast_bridge_star_g_hit;
        }
        size = IPV4_MULTICAST_STAR_G_TABLE_SIZE;
    }
#endif /* !L2_MULTICAST_DISABLE && !IPV4_DISABLE */
#if !defined(L3_MULTICAST_DISABLE) && !defined(IPV4_DISABLE)
    direct_counter(CounterType.packets) ipv4_multicast_route_s_g_stats;
    action on_miss_counter() {
        ipv4_multicast_route_s_g_stats.count();
    }
    action multicast_route_s_g_hit_counter(bit<16> mc_index, bit<16> mcast_rpf_group)
    {
        ipv4_multicast_route_s_g_stats.count();
        meta.multicast_metadata.multicast_route_mc_index = mc_index;
        meta.multicast_metadata.mcast_mode = MCAST_MODE_SM;
        meta.multicast_metadata.mcast_route_hit = TRUE;
        meta.multicast_metadata.mcast_rpf_group = mcast_rpf_group ^ (bit<16>)meta.multicast_metadata.bd_mrpf_group;
    }
    table ipv4_multicast_route
    {
        key = {
            meta.l3_metadata.vrf          : exact;
            meta.ipv4_metadata.lkp_ipv4_sa: exact;
            meta.ipv4_metadata.lkp_ipv4_da: exact;
        }
        actions = {
            on_miss_counter;
            multicast_route_s_g_hit_counter;
        }
        size = IPV4_MULTICAST_S_G_TABLE_SIZE;
        counters = ipv4_multicast_route_s_g_stats;
    }
    direct_counter(CounterType.packets) ipv4_multicast_route_star_g_stats;
    action multicast_route_star_g_miss_counter()
    {
        ipv4_multicast_route_star_g_stats.count();
        meta.l3_metadata.l3_copy = TRUE;
    }
    action multicast_route_sm_star_g_hit_counter(bit<16> mc_index, bit<16> mcast_rpf_group)
    {
        ipv4_multicast_route_star_g_stats.count();
        meta.multicast_metadata.mcast_mode = MCAST_MODE_SM;
        meta.multicast_metadata.multicast_route_mc_index = mc_index;
        meta.multicast_metadata.mcast_route_hit = TRUE;
        meta.multicast_metadata.mcast_rpf_group = mcast_rpf_group ^ (bit<16>)meta.multicast_metadata.bd_mrpf_group;
    }
    action multicast_route_bidir_star_g_hit_counter(bit<16> mc_index, bit<16> mcast_rpf_group)
    {
        ipv4_multicast_route_star_g_stats.count();
        meta.multicast_metadata.mcast_mode = MCAST_MODE_BIDIR;
        meta.multicast_metadata.multicast_route_mc_index = mc_index;
        meta.multicast_metadata.mcast_route_hit = TRUE;
        meta.multicast_metadata.mcast_rpf_group = mcast_rpf_group | (bit<16>)meta.multicast_metadata.bd_mrpf_group;
    }
    table ipv4_multicast_route_star_g
    {
        key = {
            meta.l3_metadata.vrf          : exact;
            meta.ipv4_metadata.lkp_ipv4_da: exact;
        }
        actions = {
            multicast_route_star_g_miss_counter;
            multicast_route_sm_star_g_hit_counter;
            multicast_route_bidir_star_g_hit_counter;
        }
        size = IPV4_MULTICAST_STAR_G_TABLE_SIZE;
        counters = ipv4_multicast_route_star_g_stats;
    }
#endif /* !L3_MULTICAST_DISABLE && !IPV4_DISABLE */

    apply 
    {
#if !defined(L2_MULTICAST_DISABLE) && !defined(IPV4_DISABLE)
    /* ipv4 multicast lookup */
        if (DO_LOOKUP(L2)) {
            switch (ipv4_multicast_bridge.apply().action_run) {
                on_miss: {
                    ipv4_multicast_bridge_star_g.apply();
                }
            }
        }
#endif /* !L2_MULTICAST_DISABLE && !IPV4_DISABLE */
#if !defined(L3_MULTICAST_DISABLE) && !defined(IPV4_DISABLE)
        if (DO_LOOKUP(L3) && meta.multicast_metadata.ipv4_multicast_enabled == TRUE) {
            switch (ipv4_multicast_route.apply().action_run) {
                on_miss_counter: {
                    ipv4_multicast_route_star_g.apply();
                }
            }
        }
#endif /* !L3_MULTICAST_DISABLE && !IPV4_DISABLE */
    }
}



























































/*****************************************************************************/
/* IPv6 multicast lookup                                                     */
/*****************************************************************************/
control process_ipv6_multicast(inout metadata meta)
{
#if !defined(L2_MULTICAST_DISABLE) && !defined(IPV6_DISABLE)
    action on_miss() {}
    action multicast_bridge_s_g_hit(bit<16> mc_index)
    {
        meta.multicast_metadata.multicast_bridge_mc_index = mc_index;
        meta.multicast_metadata.mcast_bridge_hit = TRUE;
    }
    table ipv6_multicast_bridge
    {
        key = {
            meta.ingress_metadata.bd      : exact;
            meta.ipv6_metadata.lkp_ipv6_sa: exact;
            meta.ipv6_metadata.lkp_ipv6_da: exact;
        }
        actions = {
            on_miss;
            multicast_bridge_s_g_hit;
        }
        size = IPV6_MULTICAST_STAR_G_TABLE_SIZE;
    }
    action nop() {}
    action multicast_bridge_star_g_hit(bit<16> mc_index)
    {
        meta.multicast_metadata.multicast_bridge_mc_index = mc_index;
        meta.multicast_metadata.mcast_bridge_hit = TRUE;
    }
    table ipv6_multicast_bridge_star_g
    {
        key = {
            meta.ingress_metadata.bd      : exact;
            meta.ipv6_metadata.lkp_ipv6_da: exact;
        }
        actions = {
            nop;
            multicast_bridge_star_g_hit;
        }
        size = IPV6_MULTICAST_S_G_TABLE_SIZE;
    }
#endif /* !L2_MULTICAST_DISABLE && !IPV6_DISABLE */
#if !defined(L3_MULTICAST_DISABLE) && !defined(IPV6_DISABLE)
    direct_counter(CounterType.packets) ipv6_multicast_route_s_g_stats;
    action on_miss_counter() {
        ipv6_multicast_route_s_g_stats.count();
    }
    action multicast_route_s_g_hit_counter(bit<16> mc_index, bit<16> mcast_rpf_group)
    {
        ipv6_multicast_route_s_g_stats.count();
        meta.multicast_metadata.multicast_route_mc_index = mc_index;
        meta.multicast_metadata.mcast_mode = MCAST_MODE_SM;
        meta.multicast_metadata.mcast_route_hit = TRUE;
        meta.multicast_metadata.mcast_rpf_group = mcast_rpf_group ^ (bit<16>)meta.multicast_metadata.bd_mrpf_group;
    }
    table ipv6_multicast_route
    {
        key = {
            meta.l3_metadata.vrf          : exact;
            meta.ipv6_metadata.lkp_ipv6_sa: exact;
            meta.ipv6_metadata.lkp_ipv6_da: exact;
        }
        actions = {
            on_miss_counter;
            multicast_route_s_g_hit_counter;
        }
        size = IPV6_MULTICAST_STAR_G_TABLE_SIZE;
        counters = ipv6_multicast_route_s_g_stats;
    }
    direct_counter(CounterType.packets) ipv6_multicast_route_star_g_stats;
    action multicast_route_star_g_miss_counter()
    {
        ipv6_multicast_route_star_g_stats.count();
        meta.l3_metadata.l3_copy = TRUE;
    }
    action multicast_route_sm_star_g_hit_counter(bit<16> mc_index, bit<16> mcast_rpf_group)
    {
        ipv6_multicast_route_star_g_stats.count();
        meta.multicast_metadata.mcast_mode = MCAST_MODE_SM;
        meta.multicast_metadata.multicast_route_mc_index = mc_index;
        meta.multicast_metadata.mcast_route_hit = TRUE;
        meta.multicast_metadata.mcast_rpf_group = mcast_rpf_group ^ (bit<16>)meta.multicast_metadata.bd_mrpf_group;
    }
    action multicast_route_bidir_star_g_hit_counter(bit<16> mc_index, bit<16> mcast_rpf_group)
    {
        ipv6_multicast_route_star_g_stats.count();
        meta.multicast_metadata.mcast_mode = MCAST_MODE_BIDIR;
        meta.multicast_metadata.multicast_route_mc_index = mc_index;
        meta.multicast_metadata.mcast_route_hit = TRUE;
        meta.multicast_metadata.mcast_rpf_group = mcast_rpf_group | (bit<16>)meta.multicast_metadata.bd_mrpf_group;
    }
    table ipv6_multicast_route_star_g
    {
        key = {
            meta.l3_metadata.vrf          : exact;
            meta.ipv6_metadata.lkp_ipv6_da: exact;
        }
        actions = {
            multicast_route_star_g_miss_counter;
            multicast_route_sm_star_g_hit_counter;
            multicast_route_bidir_star_g_hit_counter;
        }
        size = IPV6_MULTICAST_S_G_TABLE_SIZE;
        counters = ipv6_multicast_route_star_g_stats;
    }
#endif /* !L3_MULTICAST_DISABLE && !IPV6_DISABLE */

    apply
    {
#if !defined(L2_MULTICAST_DISABLE) && !defined(IPV6_DISABLE)
        if (DO_LOOKUP(L2)) {
            switch (ipv6_multicast_bridge.apply().action_run) {
                on_miss: {
                    ipv6_multicast_bridge_star_g.apply();
                }
            }
        }
#endif /* !L2_MULTICAST_DISABLE && !IPV6_DISABLE */
#if !defined(L3_MULTICAST_DISABLE) && !defined(IPV6_DISABLE)
        if (DO_LOOKUP(L3) && meta.multicast_metadata.ipv6_multicast_enabled == TRUE) {
            switch (ipv6_multicast_route.apply().action_run) {
                on_miss_counter: {
                    ipv6_multicast_route_star_g.apply();
                }
            }
        }
#endif /* !L3_MULTICAST_DISABLE && !IPV6_DISABLE */
    }
}

/*****************************************************************************/
/* IP multicast processing                                                   */
/*****************************************************************************/
control process_multicast(inout metadata meta)
{
    apply
    {
#ifndef MULTICAST_DISABLE
        if (meta.l3_metadata.lkp_ip_type == IPTYPE_IPV4) {
            process_ipv4_multicast.apply(meta);
        } else {
            if (meta.l3_metadata.lkp_ip_type == IPTYPE_IPV6) {
                process_ipv6_multicast.apply(meta);
            }
        }
        process_multicast_rpf.apply(meta);
#endif /* MULTICAST_DISABLE */
    }
}

/*****************************************************************************/
/* Multicast flooding                                                        */
/*****************************************************************************/
control process_multicast_flooding(inout metadata meta)
{
#ifndef MULTICAST_DISABLE
    action nop() {}
    action set_bd_flood_mc_index(bit<16> mc_index)
    {
        meta.intrinsic_metadata.mcast_grp = mc_index;
    }
    table bd_flood
    {
        key = {
            meta.ingress_metadata.bd     : exact;
            meta.l2_metadata.lkp_pkt_type: exact;
        }
        actions = {
            nop;
            set_bd_flood_mc_index;
        }
        size = BD_FLOOD_TABLE_SIZE;
    }
#endif /* MULTICAST_DISABLE */

    apply 
    {
#ifndef MULTICAST_DISABLE
        bd_flood.apply();
#endif /* MULTICAST_DISABLE */
    }
}

/*****************************************************************************/
/* Multicast replication processing                                          */
/*****************************************************************************/
control process_replication(inout metadata meta)
{
#ifndef MULTICAST_DISABLE
    action nop() {}
    action outer_replica_from_rid(bit<16> bd, bit<14> tunnel_index, bit<5> tunnel_type, bit<4> header_count)
    {
        meta.egress_metadata.bd = bd;
        meta.multicast_metadata.replica = TRUE;
        meta.multicast_metadata.inner_replica = FALSE;
        meta.egress_metadata.routed = (bit<1>)meta.l3_metadata.outer_routed;
        meta.egress_metadata.same_bd_check = (bit<16>)bd ^ (bit<16>)meta.ingress_metadata.outer_bd;
        meta.tunnel_metadata.tunnel_index = tunnel_index;
        meta.tunnel_metadata.egress_tunnel_type = tunnel_type;
        meta.tunnel_metadata.egress_header_count = header_count;
    }
    action inner_replica_from_rid(bit<16> bd, bit<14> tunnel_index, bit<5> tunnel_type, bit<4> header_count)
    {
        meta.egress_metadata.bd = bd;
        meta.multicast_metadata.replica = TRUE;
        meta.multicast_metadata.inner_replica = TRUE;
        meta.egress_metadata.routed = (bit<1>)meta.l3_metadata.routed;
        meta.egress_metadata.same_bd_check = (bit<16>)bd ^ (bit<16>)meta.ingress_metadata.bd;
        meta.tunnel_metadata.tunnel_index = tunnel_index;
        meta.tunnel_metadata.egress_tunnel_type = tunnel_type;
        meta.tunnel_metadata.egress_header_count = header_count;
    }
    table rid
    {
        actions = {
            nop;
            outer_replica_from_rid;
            inner_replica_from_rid;
        }
        key = {
            meta.intrinsic_metadata.egress_rid: exact;
        }
        size = RID_TABLE_SIZE;
    }
    action set_replica_copy_bridged()
    {
        meta.egress_metadata.routed = FALSE;
    }
    table replica_type
    {
        key = {
            meta.multicast_metadata.replica   : exact;
            meta.egress_metadata.same_bd_check: ternary;
        }
        actions = {
            nop;
            set_replica_copy_bridged;
        }
        size = REPLICA_TYPE_TABLE_SIZE;
    }
#endif /* MULTICAST_DISABLE */

    apply 
    {
#ifndef MULTICAST_DISABLE
        if (meta.intrinsic_metadata.egress_rid != 16w0) {
            /* set info from rid */
            rid.apply();
            /*  routed or bridge replica */
            replica_type.apply();
        }
#endif /* MULTICAST_DISABLE */
    }
}

/*
 * PIM BIDIR DF check optimization description
 Assumption : Number of RPs in the network is X
 PIM_DF_CHECK_BITS : X

 For each RP, there is list of interfaces for which the switch is
 the designated forwarder.

 For example:
 RP1 : BD1, BD2, BD5
 RP2 : BD3, BD5
 ...
 RP16 : BD1, BD5

 RP1  is allocated value 0x0001
 RP2  is allocated value 0x0002
 ...
 RP16 is allocated value 0x8000

 With each BD, we store a bitmap of size PIM_DF_CHECK_BITS with all
 RPx that it belongs to set.

 BD1 : 0x8001 (1000 0000 0000 0001)
 BD2 : 0x0001 (0000 0000 0000 0001)
 BD3 : 0x0002 (0000 0000 0000 0010)
 BD5 : 0x8003 (1000 0000 0000 0011)

 With each (*,G) entry, we store the RP value.

 DF check : <RP value from (*,G) entry> & <mrpf group value from bd>
 If 0, rpf check fails.

 Eg, If (*,G) entry uses RP2, and packet comes in BD3 or BD5, then RPF
 check passes. If packet comes in any other interface, logical and
 operation will yield 0.
 */
