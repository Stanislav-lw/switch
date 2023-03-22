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
 * Layer-3 processing
 */
/*****************************************************************************/
/* uRPF BD check                                                             */
/*****************************************************************************/
control process_urpf_bd(inout metadata meta)
{
#if !defined(L3_DISABLE) && !defined(URPF_DISABLE)
    action nop() {}
    action urpf_miss() 
    {
        meta.l3_metadata.urpf_check_fail = TRUE;
    }
    action urpf_bd_miss() 
    {
        meta.l3_metadata.urpf_check_fail = TRUE;
    }
    table urpf_bd
    {
        key = {
            meta.l3_metadata.urpf_bd_group: exact;
            meta.ingress_metadata.bd      : exact;
        }
        actions = {
            nop;
            urpf_miss;
            urpf_bd_miss;
        }
        size = URPF_GROUP_TABLE_SIZE;
    }
#endif /* L3_DISABLE && URPF_DISABLE */

    apply 
    {
#if !defined(L3_DISABLE) && !defined(URPF_DISABLE)
        if ((meta.l3_metadata.urpf_mode == URPF_MODE_STRICT) &&
            (meta.l3_metadata.urpf_hit == TRUE)) {
            urpf_bd.apply();
        }
#endif /* L3_DISABLE && URPF_DISABLE */
    }
}

/*****************************************************************************/
/* Egress L3 rewrite                                                         */
/*****************************************************************************/
control process_mac_rewrite(inout headers_t headers, inout metadata meta)
{
#if !defined(L3_DISABLE)
    action nop() {}
    action ipv4_unicast_rewrite()
    {
        headers.ethernet.dstAddr = (bit<48>)meta.egress_metadata.mac_da;
        headers.ipv4.ttl = headers.ipv4.ttl - 8w1;
#ifndef QOS_DISABLE
        headers.ipv4.diffserv = (bit<8>)meta.l3_metadata.lkp_dscp;
#endif /* QOS_DISABLE */
    }
#ifndef L3_MULTICAST_DISABLE
    action ipv4_multicast_rewrite()
    {
        headers.ethernet.dstAddr = headers.ethernet.dstAddr | 48w0x1005e000000;
        headers.ipv4.ttl = headers.ipv4.ttl - 8w1;
#ifndef QOS_DISABLE
        headers.ipv4.diffserv = (bit<8>)meta.l3_metadata.lkp_dscp;
#endif /* QOS_DISABLE */
    }
#endif /* L3_MULTICAST_DISABLE */
#ifndef IPV6_DISABLE
    action ipv6_unicast_rewrite()
    {
        headers.ethernet.dstAddr = (bit<48>)meta.egress_metadata.mac_da;
        headers.ipv6.hopLimit = headers.ipv6.hopLimit - 8w1;
#ifndef QOS_DISABLE
        headers.ipv6.trafficClass = (bit<8>)meta.l3_metadata.lkp_dscp;
#endif /* QOS_DISABLE */
    }
#ifndef L3_MULTICAST_DISABLE
    action ipv6_multicast_rewrite()
    {
        headers.ethernet.dstAddr = headers.ethernet.dstAddr | 48w0x333300000000;
        headers.ipv6.hopLimit = headers.ipv6.hopLimit - 8w1;
#ifndef QOS_DISABLE
        headers.ipv6.trafficClass = (bit<8>)meta.l3_metadata.lkp_dscp;
#endif /* QOS_DISABLE */
    }
#endif /* L3_MULTICAST_DISABLE */
#endif /* IPV6_DISABLE */
#ifndef MPLS_DISABLE
    action mpls_rewrite()
    {
        headers.ethernet.dstAddr = (bit<48>)meta.egress_metadata.mac_da;
        headers.mpls[0].ttl = headers.mpls[0].ttl - 8w1;
    }
#endif /* MPLS_DISABLE */
    table l3_rewrite
    {
        key = {
            headers.ipv4.isValid()       : exact;
#ifndef IPV6_DISABLE
            headers.ipv6.isValid()       : exact;
#endif /* IPV6_DISABLE */
#ifndef MPLS_DISABLE
            headers.mpls[0].isValid()    : exact;
#endif /* MPLS_DISABLE */
            headers.ipv4.dstAddr[31:28]  : ternary;
#ifndef IPV6_DISABLE
            headers.ipv6.dstAddr[127:120]: ternary;
#endif /* IPV6_DISABLE */
        }
        actions = {
            nop;
            ipv4_unicast_rewrite;
#ifndef L3_MULTICAST_DISABLE
            ipv4_multicast_rewrite;
#ifndef IPV6_DISABLE
#endif /* L3_MULTICAST_DISABLE */
            ipv6_unicast_rewrite;
#ifndef L3_MULTICAST_DISABLE
            ipv6_multicast_rewrite;
#endif /* L3_MULTICAST_DISABLE */
#endif /* IPV6_DISABLE */
#ifndef MPLS_DISABLE
            mpls_rewrite;
#endif /* MPLS_DISABLE */
        }
    }
    action rewrite_smac(bit<48> smac)
    {
        headers.ethernet.srcAddr = smac;
    }
    table smac_rewrite
    {
        key = {
            meta.egress_metadata.smac_idx: exact;
        }
        actions = {
            rewrite_smac;
        }
        size = MAC_REWRITE_TABLE_SIZE;
    }
#endif /* L3_DISABLE */

    apply
    {
#if !defined(L3_DISABLE)
        if (meta.egress_metadata.routed == TRUE) {
            l3_rewrite.apply();
            smac_rewrite.apply();
        }
#endif /* L3_DISABLE */
    }
}


/*****************************************************************************/
/* Egress MTU check                                                          */
/*****************************************************************************/
control process_mtu(inout headers_t headers, inout metadata meta)
{
#if !defined(L3_DISABLE)
    action mtu_miss()
    {
        meta.l3_metadata.l3_mtu_check = 16w0xffff;
    }
    action ipv4_mtu_check(bit<16> l3_mtu)
    {
        meta.l3_metadata.l3_mtu_check = l3_mtu |-| (bit<16>)headers.ipv4.totalLen;
    }
#ifndef IPV6_DISABLE
    action ipv6_mtu_check(bit<16> l3_mtu)
    {
        meta.l3_metadata.l3_mtu_check = l3_mtu |-| (bit<16>)headers.ipv6.payloadLen;
    }
#endif /* IPV6_DISABLE */
    table mtu
    {
        key = {
            meta.l3_metadata.mtu_index: exact;
            headers.ipv4.isValid()    : exact;
#ifndef IPV6_DISABLE
            headers.ipv6.isValid()    : exact;
#endif /* IPV6_DISABLE */
        }
        actions = {
            mtu_miss;
            ipv4_mtu_check;
#ifndef IPV6_DISABLE
            ipv6_mtu_check;
#endif /* IPV6_DISABLE */
        }
        size = L3_MTU_TABLE_SIZE;
    }
#endif /* L3_DISABLE */

    apply
    {
#if !defined(L3_DISABLE)
        mtu.apply();
#endif /* L3_DISABLE */
    }
}