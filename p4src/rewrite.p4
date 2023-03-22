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
 * Packet rewrite processing
 */

/*****************************************************************************/
/* Packet rewrite lookup and actions                                         */
/*****************************************************************************/
control process_rewrite(inout headers_t headers, inout metadata meta)
{
    action nop() {}
    action set_l2_rewrite()
    {
        meta.egress_metadata.routed = FALSE;
        meta.egress_metadata.bd = (bit<16>)meta.ingress_metadata.bd;
        meta.egress_metadata.outer_bd = (bit<16>)meta.ingress_metadata.bd;
    }
    action set_l2_rewrite_with_tunnel(bit<14> tunnel_index, bit<5> tunnel_type)
    {
        meta.egress_metadata.routed = FALSE;
        meta.egress_metadata.bd = (bit<16>)meta.ingress_metadata.bd;
        meta.egress_metadata.outer_bd = (bit<16>)meta.ingress_metadata.bd;
        meta.tunnel_metadata.tunnel_index = tunnel_index;
        meta.tunnel_metadata.egress_tunnel_type = tunnel_type;
    }
    action set_l3_rewrite(bit<16> bd, bit<8> mtu_index, bit<48> dmac)
    {
        meta.egress_metadata.routed = TRUE;
        meta.egress_metadata.mac_da = dmac;
        meta.egress_metadata.bd = bd;
        meta.egress_metadata.outer_bd = (bit<16>)bd;
        meta.l3_metadata.mtu_index = mtu_index;
    }
    action set_l3_rewrite_with_tunnel(bit<16> bd, bit<48> dmac, bit<14> tunnel_index, bit<5> tunnel_type)
    {
        meta.egress_metadata.routed = TRUE;
        meta.egress_metadata.mac_da = dmac;
        meta.egress_metadata.bd = bd;
        meta.egress_metadata.outer_bd = (bit<16>)bd;
        meta.tunnel_metadata.tunnel_index = tunnel_index;
        meta.tunnel_metadata.egress_tunnel_type = tunnel_type;
    }
#ifndef MPLS_DISABLE
    action set_mpls_swap_push_rewrite_l2(bit<20> label, bit<14> tunnel_index, bit<4> header_count)
    {
        meta.egress_metadata.routed = (bit<1>)meta.l3_metadata.routed;
        meta.egress_metadata.bd = (bit<16>)meta.ingress_metadata.bd;
        headers.mpls[0].label = label;
        meta.tunnel_metadata.tunnel_index = tunnel_index;
        meta.tunnel_metadata.egress_header_count = header_count;
        meta.tunnel_metadata.egress_tunnel_type = EGRESS_TUNNEL_TYPE_MPLS_L2VPN;
    }
    action set_mpls_push_rewrite_l2(bit<14> tunnel_index, bit<4> header_count)
    {
        meta.egress_metadata.routed = (bit<1>)meta.l3_metadata.routed;
        meta.egress_metadata.bd = (bit<16>)meta.ingress_metadata.bd;
        meta.tunnel_metadata.tunnel_index = tunnel_index;
        meta.tunnel_metadata.egress_header_count = header_count;
        meta.tunnel_metadata.egress_tunnel_type = EGRESS_TUNNEL_TYPE_MPLS_L2VPN;
    }
    action set_mpls_swap_push_rewrite_l3(bit<16> bd, bit<48> dmac, bit<20> label, bit<14> tunnel_index, bit<4> header_count)
    {
        meta.egress_metadata.routed = (bit<1>)meta.l3_metadata.routed;
        meta.egress_metadata.bd = bd;
        headers.mpls[0].label = label;
        meta.egress_metadata.mac_da = dmac;
        meta.tunnel_metadata.tunnel_index = tunnel_index;
        meta.tunnel_metadata.egress_header_count = header_count;
        meta.tunnel_metadata.egress_tunnel_type = EGRESS_TUNNEL_TYPE_MPLS_L3VPN;
    }
    action set_mpls_push_rewrite_l3(bit<16> bd, bit<48> dmac, bit<14> tunnel_index, bit<4> header_count)
    {
        meta.egress_metadata.routed = (bit<1>)meta.l3_metadata.routed;
        meta.egress_metadata.bd = bd;
        meta.egress_metadata.mac_da = dmac;
        meta.tunnel_metadata.tunnel_index = tunnel_index;
        meta.tunnel_metadata.egress_header_count = header_count;
        meta.tunnel_metadata.egress_tunnel_type = EGRESS_TUNNEL_TYPE_MPLS_L3VPN;
    }
#endif /* MPLS_DISABLE */
    table rewrite
    {
        key = {
            meta.l3_metadata.nexthop_index: exact;
        }
        actions = {
            nop;
            set_l2_rewrite;
            set_l2_rewrite_with_tunnel;
            set_l3_rewrite;
            set_l3_rewrite_with_tunnel;
#ifndef MPLS_DISABLE
            set_mpls_swap_push_rewrite_l2;
            set_mpls_push_rewrite_l2;
            set_mpls_swap_push_rewrite_l3;
            set_mpls_push_rewrite_l3;
#endif /* MPLS_DISABLE */
        }
        size = NEXTHOP_TABLE_SIZE;
    }
#ifndef MULTICAST_DISABLE
    action rewrite_ipv4_multicast()
    {
        headers.ethernet.dstAddr[22:0] = ((bit<48>)headers.ipv4.dstAddr)[22:0];
    }
#ifndef IPV6_DISABLE
    action rewrite_ipv6_multicast() {}
#endif /* IPV6_DISABLE */
    table rewrite_multicast
    {
        key = {
            headers.ipv4.isValid()       : exact;
            headers.ipv4.dstAddr[31:28]  : ternary;
#ifndef IPV6_DISABLE
            headers.ipv6.isValid()       : exact;
            headers.ipv6.dstAddr[127:120]: ternary;
#endif /* IPV6_DISABLE */
        }
        actions = {
            nop;
            rewrite_ipv4_multicast;
#ifndef IPV6_DISABLE
            rewrite_ipv6_multicast;
#endif /* IPV6_DISABLE */
        }
    }
#endif /* MULTICAST_DISABLE */

    apply 
    {
        if ((meta.egress_metadata.routed == FALSE) ||
            (meta.l3_metadata.nexthop_index != 16w0))
        {
            rewrite.apply();
        } else {
#ifndef MULTICAST_DISABLE
            rewrite_multicast.apply();
#endif /* MULTICAST_DISABLE */
        }
    }
}
