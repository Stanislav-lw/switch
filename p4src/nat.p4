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
 * NAT processing
 */
/*****************************************************************************/
/* Ingress NAT lookup - src, dst, twice                                      */
/*****************************************************************************/
control process_ingress_nat(inout metadata meta)
{    
#ifndef NAT_DISABLE
    action nop() {}
    action on_miss() {}
    /*
     * packet has matched source nat binding, provide rewrite index for source
     * ip/port rewrite
     */
    action set_src_nat_rewrite_index(bit<14> nat_rewrite_index)
    {
        meta.nat_metadata.nat_rewrite_index = nat_rewrite_index;
    }
    /*
     * packet has matched destination nat binding, provide nexthop index for
     * forwarding and rewrite index for destination ip/port rewrite
     */
    action set_dst_nat_nexthop_index(bit<16> nexthop_index, bit<2> nexthop_type, bit<14> nat_rewrite_index)
    {
        meta.nat_metadata.nat_nexthop = nexthop_index;
        meta.nat_metadata.nat_nexthop_type = nexthop_type;
        meta.nat_metadata.nat_rewrite_index = nat_rewrite_index;
        meta.nat_metadata.nat_hit = TRUE;
    }
    /*
     * packet has matched twice nat binding, provide nexthop index for forwarding,
     * and rewrite index for source and destination ip/port rewrite
     */
    action set_twice_nat_nexthop_index(bit<16> nexthop_index, bit<2> nexthop_type, bit<14> nat_rewrite_index)
    {
        meta.nat_metadata.nat_nexthop = nexthop_index;
        meta.nat_metadata.nat_nexthop_type = nexthop_type;
        meta.nat_metadata.nat_rewrite_index = nat_rewrite_index;
        meta.nat_metadata.nat_hit = TRUE;
    }
    table nat_src
    {
        key = {
            meta.l3_metadata.vrf          : exact;
            meta.ipv4_metadata.lkp_ipv4_sa: exact;
            meta.l3_metadata.lkp_ip_proto : exact;
            meta.l3_metadata.lkp_l4_sport : exact;
        }
        actions = {
            on_miss;
            set_src_nat_rewrite_index;
        }
        size = IP_NAT_TABLE_SIZE;
    }
    table nat_dst
    {
        key = {
            meta.l3_metadata.vrf          : exact;
            meta.ipv4_metadata.lkp_ipv4_da: exact;
            meta.l3_metadata.lkp_ip_proto : exact;
            meta.l3_metadata.lkp_l4_dport : exact;
        }
        actions = {
            on_miss;
            set_dst_nat_nexthop_index;
        }
        size = IP_NAT_TABLE_SIZE;
    }
    table nat_flow
    {
        key = {
            meta.l3_metadata.vrf          : ternary;
            meta.ipv4_metadata.lkp_ipv4_sa: ternary;
            meta.ipv4_metadata.lkp_ipv4_da: ternary;
            meta.l3_metadata.lkp_ip_proto : ternary;
            meta.l3_metadata.lkp_l4_sport : ternary;
            meta.l3_metadata.lkp_l4_dport : ternary;
        }
        actions = {
            nop;
            set_src_nat_rewrite_index;
            set_dst_nat_nexthop_index;
            set_twice_nat_nexthop_index;
        }
        size = IP_NAT_FLOW_TABLE_SIZE;
    }
    table nat_twice
    {
        key = {
            meta.l3_metadata.vrf          : exact;
            meta.ipv4_metadata.lkp_ipv4_sa: exact;
            meta.ipv4_metadata.lkp_ipv4_da: exact;
            meta.l3_metadata.lkp_ip_proto : exact;
            meta.l3_metadata.lkp_l4_sport : exact;
            meta.l3_metadata.lkp_l4_dport : exact;
        }
        actions = {
            on_miss;
            set_twice_nat_nexthop_index;
        }
        size = IP_NAT_TABLE_SIZE;
    }
#endif /* NAT DISABLE */

    apply
    {
#ifndef NAT_DISABLE
        switch (nat_twice.apply().action_run) {
            on_miss: {
                switch (nat_dst.apply().action_run) {
                    on_miss: {
                        switch (nat_src.apply().action_run) {
                            on_miss: {
                                nat_flow.apply();
                            }
                        }
                    }
                }
            }
        }
#endif /* NAT DISABLE */
    }
}


/*****************************************************************************/
/* Egress NAT rewrite                                                        */
/*****************************************************************************/
control process_egress_nat(inout headers_t headers, inout metadata meta)
{
#ifndef NAT_DISABLE
    action nop(){}
    action nat_update_l4_checksum()
    {
        meta.nat_metadata.update_checksum = TRUE;
        meta.nat_metadata.l4_len = (bit<16>)headers.ipv4.totalLen + 16w65516;
    }
    action set_nat_src_rewrite(bit<32> src_ip)
    {
        headers.ipv4.srcAddr = src_ip;
        nat_update_l4_checksum();
    }
    action set_nat_dst_rewrite(bit<32> dst_ip)
    {
        headers.ipv4.dstAddr = dst_ip;
        nat_update_l4_checksum();
    }
    action set_nat_src_dst_rewrite(bit<32> src_ip, bit<32> dst_ip)
    {
        headers.ipv4.srcAddr = src_ip;
        headers.ipv4.dstAddr = dst_ip;
        nat_update_l4_checksum();
    }
    action set_nat_src_udp_rewrite(bit<32> src_ip, bit<16> src_port)
    {
        headers.ipv4.srcAddr = src_ip;
        headers.udp.srcPort = src_port;
        nat_update_l4_checksum();
    }
    action set_nat_dst_udp_rewrite(bit<32> dst_ip, bit<16> dst_port)
    {
        headers.ipv4.dstAddr = dst_ip;
        headers.udp.dstPort = dst_port;
        nat_update_l4_checksum();
    }
    action set_nat_src_dst_udp_rewrite(bit<32> src_ip, bit<32> dst_ip, bit<16> src_port, bit<16> dst_port)
    {
        headers.ipv4.srcAddr = src_ip;
        headers.ipv4.dstAddr = dst_ip;
        headers.udp.srcPort = src_port;
        headers.udp.dstPort = dst_port;
        nat_update_l4_checksum();
    }
    action set_nat_src_tcp_rewrite(bit<32> src_ip, bit<16> src_port)
    {
        headers.ipv4.srcAddr = src_ip;
        headers.tcp.srcPort = src_port;
        nat_update_l4_checksum();
    }
    action set_nat_dst_tcp_rewrite(bit<32> dst_ip, bit<16> dst_port)
    {
        headers.ipv4.dstAddr = dst_ip;
        headers.tcp.dstPort = dst_port;
        nat_update_l4_checksum();
    }
    action set_nat_src_dst_tcp_rewrite(bit<32> src_ip, bit<32> dst_ip, bit<16> src_port, bit<16> dst_port)
    {
        headers.ipv4.srcAddr = src_ip;
        headers.ipv4.dstAddr = dst_ip;
        headers.tcp.srcPort = src_port;
        headers.tcp.dstPort = dst_port;
        nat_update_l4_checksum();
    }
    table egress_nat
    {
        key = {
            meta.nat_metadata.nat_rewrite_index: exact;
        }
        actions = {
            nop;
            set_nat_src_rewrite;
            set_nat_dst_rewrite;
            set_nat_src_dst_rewrite;
            set_nat_src_udp_rewrite;
            set_nat_dst_udp_rewrite;
            set_nat_src_dst_udp_rewrite;
            set_nat_src_tcp_rewrite;
            set_nat_dst_tcp_rewrite;
            set_nat_src_dst_tcp_rewrite;
        }
        size = EGRESS_NAT_TABLE_SIZE;
    }
#endif /* NAT_DISABLE */

    apply
    {
#ifndef NAT_DISABLE
        if (meta.nat_metadata.ingress_nat_mode != NAT_MODE_NONE && 
            (bit<2>)meta.nat_metadata.ingress_nat_mode != meta.nat_metadata.egress_nat_mode) {
            egress_nat.apply();
        }
#endif /* NAT_DISABLE */
    }
}