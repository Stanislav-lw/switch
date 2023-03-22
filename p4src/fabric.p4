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

/*****************************************************************************/
/* Ingress fabric header processing                                          */
/*****************************************************************************/
control process_ingress_fabric(inout headers_t headers,
                               inout metadata meta,
                               inout standard_metadata_t standard_metadata)
{
    action nop() {}
    action terminate_cpu_packet()
    {
        standard_metadata.egress_spec = (bit<9>)headers.fabric_header.dstPortOrGroup;
        meta.egress_metadata.bypass = (bit<1>)headers.fabric_header_cpu.txBypass;
        meta.intrinsic_metadata.mcast_grp = (bit<16>)headers.fabric_header_cpu.mcast_grp;

        headers.ethernet.etherType = (bit<16>)headers.fabric_payload_header.etherType;
        headers.fabric_header.setInvalid();
        headers.fabric_header_cpu.setInvalid();
        headers.fabric_payload_header.setInvalid();
    }
#ifdef FABRIC_ENABLE
    action switch_fabric_unicast_packet()
    {
        meta.fabric_metadata.fabric_header_present = TRUE;
        meta.fabric_metadata.dst_device = (bit<8>)headers.fabric_header.dstDevice;
        meta.fabric_metadata.dst_port = (bit<16>)headers.fabric_header.dstPortOrGroup;
    }
    action terminate_fabric_unicast_packet()
    {
        standard_metadata.egress_spec = (bit<9>)headers.fabric_header.dstPortOrGroup;

        meta.tunnel_metadata.tunnel_terminate = (bit<1>)headers.fabric_header_unicast.tunnelTerminate;
        meta.tunnel_metadata.ingress_tunnel_type = (bit<5>)headers.fabric_header_unicast.ingressTunnelType;
        meta.l3_metadata.nexthop_index = (bit<16>)headers.fabric_header_unicast.nexthopIndex;
        meta.l3_metadata.routed = (bit<1>)headers.fabric_header_unicast.routed;
        meta.l3_metadata.outer_routed = (bit<1>)headers.fabric_header_unicast.outerRouted;
        headers.ethernet.etherType = (bit<16>)headers.fabric_payload_header.etherType;

        headers.fabric_header.setInvalid();
        headers.fabric_header_unicast.setInvalid();
        headers.fabric_payload_header.setInvalid();
    }
#ifndef MULTICAST_DISABLE
    action switch_fabric_multicast_packet()
    {
        meta.fabric_metadata.fabric_header_present = TRUE;
        meta.intrinsic_metadata.mcast_grp = (bit<16>)headers.fabric_header.dstPortOrGroup;
    }
    action terminate_fabric_multicast_packet()
    {
        meta.tunnel_metadata.tunnel_terminate = (bit<1>)headers.fabric_header_multicast.tunnelTerminate;
        meta.tunnel_metadata.ingress_tunnel_type = (bit<5>)headers.fabric_header_multicast.ingressTunnelType;
        meta.l3_metadata.nexthop_index = 16w0;
        meta.l3_metadata.routed = (bit<1>)headers.fabric_header_multicast.routed;
        meta.l3_metadata.outer_routed = (bit<1>)headers.fabric_header_multicast.outerRouted;

        meta.intrinsic_metadata.mcast_grp = (bit<16>)headers.fabric_header_multicast.mcastGrp;

        headers.ethernet.etherType = (bit<16>)headers.fabric_payload_header.etherType;
        headers.fabric_header.setInvalid();
        headers.fabric_header_multicast.setInvalid();
        headers.fabric_payload_header.setInvalid();
    }
#endif /* MULTICAST_DISABLE */
#endif /* FABRIC_ENABLE */
    table fabric_ingress_dst_lkp
    {
        key = {
            headers.fabric_header.dstDevice: exact;
        }
        actions = {
            nop;
            terminate_cpu_packet;
#ifdef FABRIC_ENABLE
            switch_fabric_unicast_packet;
            terminate_fabric_unicast_packet;
#ifndef MULTICAST_DISABLE
            switch_fabric_multicast_packet;
            terminate_fabric_multicast_packet;
#endif /* MULTICAST_DISABLE */
#endif /* FABRIC_ENABLE */
        }
    }
#ifdef FABRIC_ENABLE
    action set_ingress_ifindex_properties() {}
    table fabric_ingress_src_lkp
    {
        key = {
            headers.fabric_header_multicast.ingressIfindex: exact;
        }
        actions = {
            nop;
            set_ingress_ifindex_properties;
        }
        size = 1024;
    }
#endif /* FABRIC_ENABLE */
    action non_ip_over_fabric()
    {
        meta.l2_metadata.lkp_mac_sa = (bit<48>)headers.ethernet.srcAddr;
        meta.l2_metadata.lkp_mac_da = (bit<48>)headers.ethernet.dstAddr;
        meta.l2_metadata.lkp_mac_type = (bit<16>)headers.ethernet.etherType;
    }
    action ipv4_over_fabric()
    {
        meta.l2_metadata.lkp_mac_sa = (bit<48>)headers.ethernet.srcAddr;
        meta.l2_metadata.lkp_mac_da = (bit<48>)headers.ethernet.dstAddr;
        meta.ipv4_metadata.lkp_ipv4_sa = (bit<32>)headers.ipv4.srcAddr;
        meta.ipv4_metadata.lkp_ipv4_da = (bit<32>)headers.ipv4.dstAddr;
        meta.l3_metadata.lkp_ip_proto = (bit<8>)headers.ipv4.protocol;
        meta.l3_metadata.lkp_l4_sport = (bit<16>)meta.l3_metadata.lkp_outer_l4_sport;
        meta.l3_metadata.lkp_l4_dport = (bit<16>)meta.l3_metadata.lkp_outer_l4_dport;
    }
    action ipv6_over_fabric()
    {
        meta.l2_metadata.lkp_mac_sa = (bit<48>)headers.ethernet.srcAddr;
        meta.l2_metadata.lkp_mac_da = (bit<48>)headers.ethernet.dstAddr;
        meta.ipv6_metadata.lkp_ipv6_sa = (bit<128>)headers.ipv6.srcAddr;
        meta.ipv6_metadata.lkp_ipv6_da = (bit<128>)headers.ipv6.dstAddr;
        meta.l3_metadata.lkp_ip_proto = (bit<8>)headers.ipv6.nextHdr;
        meta.l3_metadata.lkp_l4_sport = (bit<16>)meta.l3_metadata.lkp_outer_l4_sport;
        meta.l3_metadata.lkp_l4_dport = (bit<16>)meta.l3_metadata.lkp_outer_l4_dport;
    }
    table native_packet_over_fabric
    {
        key = {
            headers.ipv4.isValid(): exact;
#ifndef IPV6_DISABLE
            headers.ipv6.isValid(): exact;
#endif /* IPV6_DISABLE */
        }
        actions = {
            non_ip_over_fabric;
            ipv4_over_fabric;
#ifndef IPV6_DISABLE
            ipv6_over_fabric;
#endif /* IPV6_DISABLE */
        }
        size = 1024;
    }

    apply
    {
        if (meta.ingress_metadata.port_type != PORT_TYPE_NORMAL) {
            fabric_ingress_dst_lkp.apply();
#ifdef FABRIC_ENABLE
            if (meta.ingress_metadata.port_type == PORT_TYPE_FABRIC) {
                if (headers.fabric_header_multicast.isValid()) {
                    fabric_ingress_src_lkp.apply();
                }
                if (meta.tunnel_metadata.tunnel_terminate == FALSE) {
                    native_packet_over_fabric.apply();
                }
            }
#endif /* FABRIC_ENABLE */
        }
    }
}

/*****************************************************************************/
/* Fabric LAG resolution                                                     */
/*****************************************************************************/
control process_fabric_lag(inout headers_t headers,
                           inout metadata meta,
                           inout standard_metadata_t standard_metadata)
{
#ifdef FABRIC_ENABLE
    @mode("fair") action_selector(HashAlgorithm.identity, LAG_GROUP_TABLE_SIZE, LAG_BIT_WIDTH) fabric_lag_action_profile;
    action nop() {}
    action set_fabric_lag_port(bit<9> port)
    {
        standard_metadata.egress_spec = port;
    }
#ifndef MULTICAST_DISABLE
#ifndef FABRIC_NO_LOCAL_SWITCHING
    action set_fabric_multicast()
    {
        meta.multicast_metadata.mcast_grp = (bit<16>)meta.intrinsic_metadata.mcast_grp;
    }
#else // dodge warning
    action set_fabric_multicast(bit<8> fabric_mgid)
    {
        meta.multicast_metadata.mcast_grp = (bit<16>)meta.intrinsic_metadata.mcast_grp;
        // no local switching, reset fields to send packet on fabric mgid
        meta.intrinsic_metadata.mcast_grp = fabric_mgid;
    }
#endif /* FABRIC_NO_LOCAL_SWITCHING */
#endif /* MULTICAST_DISABLE */
    table fabric_lag
    {
        key = {
            meta.fabric_metadata.dst_device: exact;
            meta.hash_metadata.hash2       : selector;
        }
        actions = {
            nop;
            set_fabric_lag_port;
            set_fabric_multicast;
        }
        implementation = fabric_lag_action_profile;
    }
#endif /* FABRIC_ENABLE */

    apply
    {
#ifdef FABRIC_ENABLE
        fabric_lag.apply();
#endif /* FABRIC_ENABLE */
    }
}

// /*****************************************************************************/
// /* Fabric rewrite actions                                                    */
// /*****************************************************************************/
// action cpu_rx_rewrite()
// {
//     headers.fabric_header.setValid();
//     headers.fabric_header.headerVersion = 2w0;
//     headers.fabric_header.packetVersion = 2w0;
//     headers.fabric_header.pad1 = 1w0;
//     headers.fabric_header.packetType = FABRIC_HEADER_TYPE_CPU;
//     headers.fabric_header_cpu.setValid();
//     headers.fabric_header_cpu.ingressPort = (bit<16>)meta.ingress_metadata.ingress_port;
//     headers.fabric_header_cpu.ingressIfindex = (bit<16>)meta.ingress_metadata.ifindex;
//     headers.fabric_header_cpu.ingressBd = (bit<16>)meta.ingress_metadata.bd;
//     headers.fabric_header_cpu.reasonCode = (bit<16>)meta.fabric_metadata.reason_code;
//     headers.fabric_payload_header.setValid();
//     headers.fabric_payload_header.etherType = (bit<16>)headers.ethernet.etherType;
//     headers.ethernet.etherType = ETHERTYPE_BF_FABRIC;
// }

// action fabric_rewrite(bit<14> tunnel_index)
// {
//     meta.tunnel_metadata.tunnel_index = tunnel_index;
// }

// #ifdef FABRIC_ENABLE
// action fabric_unicast_rewrite()
// {
//     headers.fabric_header.setValid();
//     headers.fabric_header.headerVersion = 2w0;
//     headers.fabric_header.packetVersion = 2w0;
//     headers.fabric_header.pad1 = 1w0;
//     headers.fabric_header.packetType = FABRIC_HEADER_TYPE_UNICAST;
//     headers.fabric_header.dstDevice = (bit<8>)meta.fabric_metadata.dst_device;
//     headers.fabric_header.dstPortOrGroup = (bit<16>)meta.fabric_metadata.dst_port;

//     headers.fabric_header_unicast.setValid();
//     headers.fabric_header_unicast.tunnelTerminate = (bit<1>)meta.tunnel_metadata.tunnel_terminate;
//     headers.fabric_header_unicast.routed = (bit<1>)meta.l3_metadata.routed;
//     headers.fabric_header_unicast.outerRouted = (bit<1>)meta.l3_metadata.outer_routed;
//     headers.fabric_header_unicast.ingressTunnelType = (bit<5>)meta.tunnel_metadata.ingress_tunnel_type;
//     headers.fabric_header_unicast.nexthopIndex = (bit<16>)meta.l3_metadata.nexthop_index;
//     headers.fabric_payload_header.setValid();
//     headers.fabric_payload_header.etherType = (bit<16>)headers.ethernet.etherType;
//     headers.ethernet.etherType = ETHERTYPE_BF_FABRIC;
// }

// #ifndef MULTICAST_DISABLE
// action fabric_multicast_rewrite(bit<16> fabric_mgid)
// {
//     headers.fabric_header.setValid();
//     headers.fabric_header.headerVersion = 2w0;
//     headers.fabric_header.packetVersion = 2w0;
//     headers.fabric_header.pad1 = 1w0;
//     headers.fabric_header.packetType = FABRIC_HEADER_TYPE_MULTICAST;
//     headers.fabric_header.dstDevice = FABRIC_DEVICE_MULTICAST;
//     headers.fabric_header.dstPortOrGroup = fabric_mgid;
//     headers.fabric_header_multicast.ingressIfindex = (bit<16>)meta.ingress_metadata.ifindex;
//     headers.fabric_header_multicast.ingressBd = (bit<16>)meta.ingress_metadata.bd;

//     headers.fabric_header_multicast.setValid();
//     headers.fabric_header_multicast.tunnelTerminate = (bit<1>)meta.tunnel_metadata.tunnel_terminate;
//     headers.fabric_header_multicast.routed = (bit<1>)meta.l3_metadata.routed;
//     headers.fabric_header_multicast.outerRouted = (bit<1>)meta.l3_metadata.outer_routed;
//     headers.fabric_header_multicast.ingressTunnelType = (bit<5>)meta.tunnel_metadata.ingress_tunnel_type;
//     headers.fabric_header_multicast.mcastGrp = (bit<16>)meta.multicast_metadata.mcast_grp;
    
//     headers.fabric_payload_header.setValid();
//     headers.fabric_payload_header.etherType = (bit<16>)headers.ethernet.etherType;
//     headers.ethernet.etherType = ETHERTYPE_BF_FABRIC;
// }
// #endif /* MULTICAST_DISABLE */
// #endif /* FABRIC_ENABLE */
