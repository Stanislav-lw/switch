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

/* enable all advanced features */
//#define ADV_FEATURES

#define ETHERTYPE_BF_FABRIC    16w0x9000
#define ETHERTYPE_VLAN         16w0x8100
#define ETHERTYPE_QINQ         16w0x9100
#define ETHERTYPE_MPLS         16w0x8847
#define ETHERTYPE_IPV4         16w0x0800
#define ETHERTYPE_IPV6         16w0x86dd
#define ETHERTYPE_ARP          16w0x0806
#define ETHERTYPE_RARP         16w0x8035
#define ETHERTYPE_NSH          16w0x894f
#define ETHERTYPE_ETHERNET     16w0x6558
#define ETHERTYPE_ROCE         16w0x8915
#define ETHERTYPE_FCOE         16w0x8906
#define ETHERTYPE_TRILL        16w0x22f3
#define ETHERTYPE_VNTAG        16w0x8926
#define ETHERTYPE_LLDP         16w0x88cc
#define ETHERTYPE_LACP         16w0x8809

/* Tunnel types */
#define INGRESS_TUNNEL_TYPE_NONE               5w0
#define INGRESS_TUNNEL_TYPE_VXLAN              5w1
#define INGRESS_TUNNEL_TYPE_GRE                5w2
#define INGRESS_TUNNEL_TYPE_IP_IN_IP           5w3
#define INGRESS_TUNNEL_TYPE_GENEVE             5w4
#define INGRESS_TUNNEL_TYPE_NVGRE              5w5
#define INGRESS_TUNNEL_TYPE_MPLS_L2VPN         5w6
#define INGRESS_TUNNEL_TYPE_MPLS_L3VPN         5w9
#define INGRESS_TUNNEL_TYPE_VXLAN_GPE          5w12

#ifndef ADV_FEATURES
#define PARSE_ETHERTYPE                                  \
        ETHERTYPE_VLAN: parse_vlan;                      \
        ETHERTYPE_QINQ: parse_qinq;                      \
        ETHERTYPE_MPLS: parse_mpls;                      \
        ETHERTYPE_IPV4: parse_ipv4;                      \
        ETHERTYPE_IPV6: parse_ipv6;                      \
        ETHERTYPE_ARP: parse_arp_rarp;                   \
        ETHERTYPE_LLDP: parse_set_prio_high;             \
        ETHERTYPE_LACP: parse_set_prio_high;             \
        default: accept

#define PARSE_ETHERTYPE_MINUS_VLAN                       \
        ETHERTYPE_MPLS: parse_mpls;                      \
        ETHERTYPE_IPV4: parse_ipv4;                      \
        ETHERTYPE_IPV6: parse_ipv6;                      \
        ETHERTYPE_ARP: parse_arp_rarp;                   \
        ETHERTYPE_LLDP: parse_set_prio_high;             \
        ETHERTYPE_LACP: parse_set_prio_high;             \
        default: accept
#else
#define PARSE_ETHERTYPE                                  \
        ETHERTYPE_VLAN: parse_vlan;                      \
        ETHERTYPE_QINQ: parse_qinq;                      \
        ETHERTYPE_MPLS: parse_mpls;                      \
        ETHERTYPE_IPV4: parse_ipv4;                      \
        ETHERTYPE_IPV6: parse_ipv6;                      \
        ETHERTYPE_ARP: parse_arp_rarp;                   \
        ETHERTYPE_RARP: parse_arp_rarp;                  \
        ETHERTYPE_NSH: parse_nsh;                        \
        ETHERTYPE_ROCE: parse_roce;                      \
        ETHERTYPE_FCOE: parse_fcoe;                      \
        ETHERTYPE_TRILL: parse_trill;                    \
        ETHERTYPE_VNTAG: parse_vntag;                    \
        ETHERTYPE_LLDP: parse_set_prio_high;             \
        ETHERTYPE_LACP: parse_set_prio_high;             \
        default: accept

#define PARSE_ETHERTYPE_MINUS_VLAN                       \
        ETHERTYPE_MPLS: parse_mpls;                      \
        ETHERTYPE_IPV4: parse_ipv4;                      \
        ETHERTYPE_IPV6: parse_ipv6;                      \
        ETHERTYPE_ARP: parse_arp_rarp;                   \
        ETHERTYPE_RARP: parse_arp_rarp;                  \
        ETHERTYPE_NSH: parse_nsh;                        \
        ETHERTYPE_ROCE: parse_roce;                      \
        ETHERTYPE_FCOE: parse_fcoe;                      \
        ETHERTYPE_TRILL: parse_trill;                    \
        ETHERTYPE_VNTAG: parse_vntag;                    \
        ETHERTYPE_LLDP: parse_set_prio_high;             \
        ETHERTYPE_LACP: parse_set_prio_high;             \
        default: accept
#endif

#define IP_PROTOCOLS_IGMP              8w2
#define IP_PROTOCOLS_EIGRP             8w88
#define IP_PROTOCOLS_OSPF              8w89
#define IP_PROTOCOLS_PIM               8w103
#define IP_PROTOCOLS_VRRP              8w112

#define IP_PROTOCOLS_IPV4              8w4
#define IP_PROTOCOLS_TCP               8w6
#define IP_PROTOCOLS_UDP               8w17
#define IP_PROTOCOLS_IPV6              8w41
#define IP_PROTOCOLS_GRE               8w47
#define IP_PROTOCOLS_ICMPV6            8w58

#define IP_PROTOCOLS_IPHL_ICMP         (13w0x0, 4w0x5, 8w0x1)   // 0x501
#define IP_PROTOCOLS_IPHL_IPV4         (13w0x0, 4w0x5, 8w0x4)   // 0x504
#define IP_PROTOCOLS_IPHL_TCP          (13w0x0, 4w0x5, 8w0x6)   // 0x506
#define IP_PROTOCOLS_IPHL_UDP          (13w0x0, 4w0x5, 8w0x11)  // 0x511
#define IP_PROTOCOLS_IPHL_IPV6         (13w0x0, 4w0x5, 8w0x29)  // 0x529
#define IP_PROTOCOLS_IPHL_GRE          (13w0x0, 4w0x5, 8w0x2f)  // 0x52f

// Vxlan header decoding for INT
// flags.p == 1 && next_proto == 5
#ifndef __TARGET_BMV2__
#define VXLAN_GPE_NEXT_PROTO_INT 16w0x0805 &&& 16w0x08ff
#else
#define VXLAN_GPE_NEXT_PROTO_INT 8w0x05 &&& 8w0xff
#endif

#define UDP_PORT_BOOTPS                16w67
#define UDP_PORT_BOOTPC                16w68
#define UDP_PORT_RIP                   16w520
#define UDP_PORT_RIPNG                 16w521
#define UDP_PORT_DHCPV6_CLIENT         16w546
#define UDP_PORT_DHCPV6_SERVER         16w547
#define UDP_PORT_HSRP                  16w1985
#define UDP_PORT_BFD                   16w3785
#define UDP_PORT_LISP                  16w4341
#define UDP_PORT_VXLAN                 16w4789
#define UDP_PORT_VXLAN_GPE             16w4790
#define UDP_PORT_ROCE_V2               16w4791
#define UDP_PORT_GENV                  16w6081
#define UDP_PORT_SFLOW                 16w6343

#define TCP_PORT_BGP                   16w179
#define TCP_PORT_MSDP                  16w639

#define GRE_PROTOCOLS_NVGRE            30w0x20006558
#define GRE_PROTOCOLS_ERSPAN_T3        16w0x22EB   /* Type III version 2 */

#define CONTROL_TRAFFIC_PRIO_0         3w0
#define CONTROL_TRAFFIC_PRIO_1         3w1
#define CONTROL_TRAFFIC_PRIO_2         3w2
#define CONTROL_TRAFFIC_PRIO_3         3w3
#define CONTROL_TRAFFIC_PRIO_4         3w4
#define CONTROL_TRAFFIC_PRIO_5         3w5
#define CONTROL_TRAFFIC_PRIO_6         3w6
#define CONTROL_TRAFFIC_PRIO_7         3w7


parser parserImpl(packet_in packet,
                  out headers_t headers,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) 
{
    state start 
    {
        transition parse_ethernet;
    }



    state parse_ethernet 
    {
        packet.extract(headers.ethernet);
        transition select(headers.ethernet.etherType)
        {
            16w0 &&& 16w0xFE00: parse_llc_header; 
            16w0 &&& 16w0xFA00: parse_llc_header;
            ETHERTYPE_BF_FABRIC: parse_fabric_header;
            PARSE_ETHERTYPE;
        }
    }


    state parse_llc_header 
    {
        packet.extract(headers.llc_header);
        transition select(headers.llc_header.dsap, headers.llc_header.ssap) 
        {
            (8w0xAA, 8w0xAA): parse_snap_header;
            (8w0xFE, 8w0xFE): parse_set_prio_med;
            default: accept;
        }
    }

    state parse_snap_header 
    {
        packet.extract(headers.snap_header);
        transition select(headers.snap_header.type_) 
        {
            PARSE_ETHERTYPE;
        }
    }

    state parse_set_prio_med 
    {
        meta.intrinsic_metadata.priority = CONTROL_TRAFFIC_PRIO_3;
        transition accept;
    }


    state parse_fabric_header 
    {
        packet.extract(headers.fabric_header);
        transition select(headers.fabric_header.packetType)
        {
#ifdef FABRIC_ENABLE
            FABRIC_HEADER_TYPE_UNICAST:   parse_fabric_header_unicast;
            FABRIC_HEADER_TYPE_MULTICAST: parse_fabric_header_multicast;
            FABRIC_HEADER_TYPE_MIRROR:    parse_fabric_header_mirror;
#endif /* FABRIC_ENABLE */
            FABRIC_HEADER_TYPE_CPU:       parse_fabric_header_cpu;
            default: accept;
        }
    }

    state parse_fabric_header_unicast
    {
        packet.extract(headers.fabric_header_unicast);
        transition parse_fabric_payload_header;
    }

    state parse_fabric_header_multicast
    {
        packet.extract(headers.fabric_header_multicast);
        transition parse_fabric_payload_header;
    }

    state parse_fabric_header_mirror
    {
        packet.extract(headers.fabric_header_mirror);
        transition parse_fabric_payload_header;
    }

    state parse_fabric_header_cpu 
    {
        packet.extract(headers.fabric_header_cpu);
        meta.ingress_metadata.bypass_lookups = headers.fabric_header_cpu.reasonCode;
#ifdef SFLOW_ENABLE
        transition select(headers.fabric_header_cpu.reasonCode) 
        {
            CPU_REASON_CODE_SFLOW: parse_fabric_sflow_header;
            default: parse_fabric_payload_header;
        }
#else
        transition parse_fabric_payload_header;
#endif
    }

#ifdef SFLOW_ENABLE
    state parse_fabric_sflow_header 
    {
        packet.extract(headers.fabric_header_sflow);
        transition parse_fabric_payload_header;
    }
#endif

    state parse_fabric_payload_header 
    {
        packet.extract(headers.fabric_payload_header);
        transition select(headers.fabric_payload_header.etherType) 
        {
            16w0 &&& 16w0xfe00: parse_llc_header;
            16w0 &&& 16w0xfa00: parse_llc_header;
            PARSE_ETHERTYPE;
        }
    }



    state parse_vlan 
    {
        packet.extract(headers.vlan_tag[0]);
        transition select(headers.vlan_tag[0].etherType) 
        {
            PARSE_ETHERTYPE_MINUS_VLAN;
        }
    }



    state parse_qinq 
    {
        packet.extract(headers.vlan_tag[0]);
        transition select(headers.vlan_tag[0].etherType) 
        {
            ETHERTYPE_VLAN: parse_qinq_vlan;
            default: accept;
        }
    }

    state parse_qinq_vlan 
    {
        packet.extract(headers.vlan_tag[1]);
        transition select(headers.vlan_tag[1].etherType) 
        {
            PARSE_ETHERTYPE_MINUS_VLAN;
        }
    }



    state parse_mpls 
    {
#ifndef MPLS_DISABLE
        packet.extract(headers.mpls.next);
        transition select(headers.mpls.last.bos) 
        {
            1w0: parse_mpls;
            1w1: parse_mpls_bos;
            default: accept;
        }
#else
       transition accept;
#endif
    }

    state parse_mpls_bos 
    {
        transition select((packet.lookahead<bit<4>>())[3:0]) 
        {
#ifndef MPLS_DISABLE
            4w0x4: parse_mpls_inner_ipv4;
            4w0x6: parse_mpls_inner_ipv6;
#endif
            default: parse_eompls;
        }
    }

    state parse_mpls_inner_ipv4 
    {
        meta.tunnel_metadata.ingress_tunnel_type = INGRESS_TUNNEL_TYPE_MPLS_L3VPN;
        transition parse_inner_ipv4;
    }

    state parse_inner_ipv4 
    {
        packet.extract(headers.inner_ipv4);
        meta.ipv4_metadata.lkp_ipv4_sa = headers.inner_ipv4.srcAddr;
        meta.ipv4_metadata.lkp_ipv4_da = headers.inner_ipv4.dstAddr;
        meta.l3_metadata.lkp_ip_proto = headers.inner_ipv4.protocol;
        meta.l3_metadata.lkp_ip_ttl = headers.inner_ipv4.ttl;
        transition select(headers.inner_ipv4.fragOffset, headers.inner_ipv4.ihl, headers.inner_ipv4.protocol) 
        {
            IP_PROTOCOLS_IPHL_ICMP: parse_inner_icmp;
            IP_PROTOCOLS_IPHL_TCP: parse_inner_tcp;
            IP_PROTOCOLS_IPHL_UDP: parse_inner_udp;
            default: accept;
        }
    }

    state parse_mpls_inner_ipv6 
    {
        meta.tunnel_metadata.ingress_tunnel_type = INGRESS_TUNNEL_TYPE_MPLS_L3VPN;
        transition parse_inner_ipv6;
    }

    state parse_inner_ipv6 
    {
        packet.extract(headers.inner_ipv6);
#if !defined(IPV6_DISABLE)
        meta.ipv6_metadata.lkp_ipv6_sa = headers.inner_ipv6.srcAddr;
        meta.ipv6_metadata.lkp_ipv6_da = headers.inner_ipv6.dstAddr;
        meta.l3_metadata.lkp_ip_proto = headers.inner_ipv6.nextHdr;
        meta.l3_metadata.lkp_ip_ttl = headers.inner_ipv6.hopLimit;
#endif /* !defined(IPV6_DISABLE) */
        transition select(headers.inner_ipv6.nextHdr) 
        {
            IP_PROTOCOLS_ICMPV6: parse_inner_icmp;
            IP_PROTOCOLS_TCP: parse_inner_tcp;
            IP_PROTOCOLS_UDP: parse_inner_udp;
            default: accept;
        }
    }

    state parse_inner_icmp 
    {
        packet.extract(headers.inner_icmp);
        meta.l3_metadata.lkp_l4_sport = headers.inner_icmp.typeCode;
        transition accept;
    }

    state parse_inner_tcp 
    {
        packet.extract(headers.inner_tcp);
        meta.l3_metadata.lkp_l4_sport = headers.inner_tcp.srcPort;
        meta.l3_metadata.lkp_l4_dport = headers.inner_tcp.dstPort;
        transition accept;
    }

    state parse_inner_udp 
    {
        packet.extract(headers.inner_udp);
        meta.l3_metadata.lkp_l4_sport = headers.inner_udp.srcPort;
        meta.l3_metadata.lkp_l4_dport = headers.inner_udp.dstPort;
        transition accept;
    }


    state parse_eompls 
    {
        packet.extract(headers.eompls);
        meta.tunnel_metadata.ingress_tunnel_type = INGRESS_TUNNEL_TYPE_MPLS_L2VPN;
        transition parse_inner_ethernet;
    }

    state parse_inner_ethernet 
    {
        packet.extract(headers.inner_ethernet);
        meta.l2_metadata.lkp_mac_sa = headers.inner_ethernet.srcAddr;
        meta.l2_metadata.lkp_mac_da = headers.inner_ethernet.dstAddr;
        transition select(headers.inner_ethernet.etherType) 
        {
            ETHERTYPE_IPV4: parse_inner_ipv4;
#ifndef TUNNEL_OVER_IPV6_DISABLE
            ETHERTYPE_IPV6: parse_inner_ipv6;
#endif
            default: accept;
        }
    }



    state parse_ipv4 
    {
        packet.extract(headers.ipv4);
        transition select(headers.ipv4.fragOffset, headers.ipv4.ihl, headers.ipv4.protocol) 
        {
            IP_PROTOCOLS_IPHL_ICMP: parse_icmp;
            IP_PROTOCOLS_IPHL_TCP: parse_tcp;
            IP_PROTOCOLS_IPHL_UDP: parse_udp;
#ifndef TUNNEL_DISABLE
            IP_PROTOCOLS_IPHL_GRE: parse_gre;
            IP_PROTOCOLS_IPHL_IPV4: parse_ipv4_in_ip;
            IP_PROTOCOLS_IPHL_IPV6: parse_ipv6_in_ip;
#endif /* TUNNEL_DISABLE */
            (13w0, 4w0, IP_PROTOCOLS_IGMP): parse_set_prio_med;
            (13w0, 4w0, IP_PROTOCOLS_EIGRP): parse_set_prio_med;
            (13w0, 4w0, IP_PROTOCOLS_OSPF): parse_set_prio_med;
            (13w0, 4w0, IP_PROTOCOLS_PIM): parse_set_prio_med;
            (13w0, 4w0, IP_PROTOCOLS_VRRP): parse_set_prio_med;
            default: accept;
        }
    }

    state parse_ipv6 
    {
        packet.extract(headers.ipv6);
        transition select(headers.ipv6.nextHdr) 
        {
            IP_PROTOCOLS_ICMPV6: parse_icmp;
            IP_PROTOCOLS_TCP: parse_tcp;
            IP_PROTOCOLS_IPV4: parse_ipv4_in_ip;
#ifndef TUNNEL_DISABLE
#ifndef TUNNEL_OVER_IPV6_DISABLE
            IP_PROTOCOLS_UDP: parse_udp;
            IP_PROTOCOLS_GRE: parse_gre;
            IP_PROTOCOLS_IPV6: parse_ipv6_in_ip;
#else
            IP_PROTOCOLS_UDP: parse_udp_v6;
            IP_PROTOCOLS_GRE: parse_gre_v6;
#endif /* TUNNEL_OVER_IPV6_DISABLE */
#endif /* TUNNEL_DISABLE */
            IP_PROTOCOLS_EIGRP: parse_set_prio_med;
            IP_PROTOCOLS_OSPF: parse_set_prio_med;
            IP_PROTOCOLS_PIM: parse_set_prio_med;
            IP_PROTOCOLS_VRRP: parse_set_prio_med;

            default: accept;
        }
    }

    state parse_icmp 
    {
        packet.extract(headers.icmp);
        meta.l3_metadata.lkp_outer_l4_sport = headers.icmp.typeCode;
        transition select(headers.icmp.typeCode) {
            /* MLD and ND, 130-136 */
            16w0x8200 &&& 16w0xfe00: parse_set_prio_med;
            16w0x8400 &&& 16w0xfc00: parse_set_prio_med;
            16w0x8800 &&& 16w0xff00: parse_set_prio_med;
            default: accept;
        }
    }

    state parse_tcp 
    {
        packet.extract(headers.tcp);
        meta.l3_metadata.lkp_outer_l4_sport = headers.tcp.srcPort;
        meta.l3_metadata.lkp_outer_l4_dport = headers.tcp.dstPort;
        transition select(headers.tcp.dstPort) {
            TCP_PORT_BGP: parse_set_prio_med;
            TCP_PORT_MSDP: parse_set_prio_med;
            default: accept;
        }
    }


    state parse_udp 
    {
        packet.extract(headers.udp);
        meta.l3_metadata.lkp_outer_l4_sport = headers.udp.srcPort;
        meta.l3_metadata.lkp_outer_l4_dport = headers.udp.dstPort;
        transition select(headers.udp.dstPort) {
#ifndef TUNNEL_DISABLE
            UDP_PORT_VXLAN: parse_vxlan;
            UDP_PORT_GENV: parse_geneve;
#endif /* TUNNEL_DISABLE */
#ifdef INT_ENABLE
            // vxlan-gpe is only supported in the context of INT at this time
            UDP_PORT_VXLAN_GPE: parse_vxlan_gpe;
#endif
#ifdef ADV_FEATURES
            UDP_PORT_ROCE_V2: parse_roce_v2;
            UDP_PORT_LISP: parse_lisp;
            UDP_PORT_BFD: parse_bfd;
#endif
            UDP_PORT_BOOTPS: parse_set_prio_med;
            UDP_PORT_BOOTPC: parse_set_prio_med;
            UDP_PORT_DHCPV6_CLIENT: parse_set_prio_med;
            UDP_PORT_DHCPV6_SERVER: parse_set_prio_med;
            UDP_PORT_RIP: parse_set_prio_med;
            UDP_PORT_RIPNG: parse_set_prio_med;
            UDP_PORT_HSRP: parse_set_prio_med;
            UDP_PORT_SFLOW: parse_sflow;
            default: accept;
        }
    }

    state parse_vxlan 
    {
        packet.extract(headers.vxlan);
        meta.tunnel_metadata.ingress_tunnel_type = INGRESS_TUNNEL_TYPE_VXLAN;
        meta.tunnel_metadata.tunnel_vni = headers.vxlan.vni;
        transition parse_inner_ethernet;
    }

    state parse_geneve 
    {
        packet.extract(headers.genv);
        meta.tunnel_metadata.tunnel_vni = headers.genv.vni;
        meta.tunnel_metadata.ingress_tunnel_type = INGRESS_TUNNEL_TYPE_GENEVE;
        transition select(headers.genv.ver, headers.genv.optLen, headers.genv.protoType) {
            (2w0x0, 6w0x0, ETHERTYPE_ETHERNET): parse_inner_ethernet;
        }
    }

#ifdef INT_ENABLE
    state parse_vxlan_gpe 
    {
        packet.extract(headers.vxlan_gpe);
        meta.tunnel_metadata.ingress_tunnel_type = INGRESS_TUNNEL_TYPE_VXLAN_GPE;
        meta.tunnel_metadata.tunnel_vni = headers.vxlan_gpe.vni;
#ifndef __TARGET_BMV2__
        transition select(headers.vxlan_gpe.flags, headers.vxlan_gpe.next_proto)
        {
            (8w0x8 &&& 8w0x8, 8w0x5 &&& 8w0xff): parse_gpe_int_header;
#else
        transition select(headers.vxlan_gpe.next_proto)
        {
            VXLAN_GPE_NEXT_PROTO_INT: parse_gpe_int_header;
#endif
            default: parse_inner_ethernet;
        }
    }
#endif

#ifdef INT_ENABLE
    state parse_gpe_int_header 
    {
        // GPE uses a shim header to preserve the next_protocol field
        packet.extract(headers.vxlan_gpe_int_header);
        meta.int_metadata.gpe_int_hdr_len = (bit<16>)headers.vxlan_gpe_int_header.len;
        transition parse_int_header;
    }

    state parse_int_header 
    {
        packet.extract(headers.int_header);
        meta.int_metadata.instruction_cnt = (bit<16>)headers.int_header.ins_cnt;
        transition select(headers.int_header.rsvd1, headers.int_header.total_hop_cnt) 
        {
            // reserved bits = 0 and total_hop_cnt == 0
            // no int_values are added by upstream
            (5w0x0, 8w0x0): accept;
#ifdef INT_EP_ENABLE
            // parse INT val headers added by upstream devices (total_hop_cnt != 0)
            // reserved bits must be 0
            (5w0x0 &&& 5w0xf, 8w0x0 &&& 8w0x0): parse_int_val;
#endif /* INT_EP_ENABLE */
            default: accept;
            // never transition to the following state
            default: parse_all_int_meta_value_heders;
        }
    }

#ifdef INT_EP_ENABLE
    state parse_int_val 
    {
        packet.extract(headers.int_value.next);
        transition select(headers.int_value.last.bos) 
        {
            1w0: parse_int_val;
            1w1: parse_inner_ethernet;
        }
    }
#endif /* INT_EP_ENABLE */

    state parse_all_int_meta_value_heders 
    {
        // bogus state.. just extract all possible int headers in the
        // correct order to build
        // the correct parse graph for deparser (while adding headers)
        packet.extract(headers.int_switch_id_header);
        packet.extract(headers.int_ingress_port_id_header);
        packet.extract(headers.int_hop_latency_header);
        packet.extract(headers.int_q_occupancy_header);
        packet.extract(headers.int_ingress_tstamp_header);
        packet.extract(headers.int_egress_port_id_header);
        packet.extract(headers.int_q_congestion_header);
        packet.extract(headers.int_egress_port_tx_utilization_header);
#ifdef INT_EP_ENABLE
        transition parse_int_val;
#else
        transition accept;
#endif /* INT_EP_ENABLE */
    }
#endif /* INT_ENABLE */

#ifdef ADV_FEATURES
    state parse_roce_v2 
    {
        packet.extract(headers.roce_v2);
        transition accept;
    }

    state parse_lisp 
    {
        packet.extract(headers.lisp);
        transition select((packet.lookahead<bit<4>>())[3:0]) 
        { 
            4w0x4: parse_inner_ipv4;
            4w0x6: parse_inner_ipv6;
            default: accept;
        }
    }

    state parse_bfd 
    {
        packet.extract(headers.bfd);
        transition parse_set_prio_max;
    }

    state parse_set_prio_max 
    {
        meta.intrinsic_metadata.priority = CONTROL_TRAFFIC_PRIO_7;
        transition accept;
    }
#endif /* ADV_FEATURES */

    state parse_sflow 
    {
#ifdef SFLOW_ENABLE
        packet.extract(headers.sflow_hdr);
#endif
        transition accept;
    }


    state parse_gre 
    {
        packet.extract(headers.gre);
        transition select(headers.gre.C, headers.gre.R, headers.gre.K, headers.gre.S, headers.gre.s,
                          headers.gre.recurse, headers.gre.flags, headers.gre.ver, headers.gre.proto) 
        {
            (1w0x0, 1w0x0, 1w0x1, 1w0x0, 1w0x0, 3w0x0, 5w0x0, 3w0x0, 16w0x6558): parse_nvgre;        // GRE_PROTOCOLS_NVGRE
            (1w0x0, 1w0x0, 1w0x0, 1w0x0, 1w0x0, 3w0x0, 5w0x0, 3w0x0, 16w0x800): parse_gre_ipv4;      // ETHERTYPE_IPV4
            (1w0x0, 1w0x0, 1w0x0, 1w0x0, 1w0x0, 3w0x0, 5w0x0, 3w0x0, 16w0x86dd): parse_gre_ipv6;     // ETHERTYPE_IPV6
            (1w0x0, 1w0x0, 1w0x0, 1w0x0, 1w0x0, 3w0x0, 5w0x0, 3w0x0, 16w0x22eb): parse_erspan_t3;    // GRE_PROTOCOLS_ERSPAN_T3
#ifdef ADV_FEATURES
            (1w0x0, 1w0x0, 1w0x0, 1w0x0, 1w0x0, 3w0x0, 5w0x0, 3w0x0, 16w0x894f): parse_nsh; // ETHERTYPE_NSH
#endif
            default: accept;
        }
    }

    state parse_nvgre 
    {
        packet.extract(headers.nvgre);
        meta.tunnel_metadata.ingress_tunnel_type = INGRESS_TUNNEL_TYPE_NVGRE;
        meta.tunnel_metadata.tunnel_vni = headers.nvgre.tni;
        transition parse_inner_ethernet;
    }

    state parse_gre_ipv4 
    {
        meta.tunnel_metadata.ingress_tunnel_type = INGRESS_TUNNEL_TYPE_GRE;
        transition parse_inner_ipv4;
    }

    state parse_gre_ipv6 
    {
        meta.tunnel_metadata.ingress_tunnel_type = INGRESS_TUNNEL_TYPE_GRE;
        transition parse_inner_ipv6;
    }

    state parse_erspan_t3 
    {
        packet.extract(headers.erspan_header_t3);
        transition parse_inner_ethernet;
    }


    state parse_ipv4_in_ip 
    {
        meta.tunnel_metadata.ingress_tunnel_type = INGRESS_TUNNEL_TYPE_IP_IN_IP;
        transition parse_inner_ipv4;
    }

    state parse_ipv6_in_ip 
    {
        meta.tunnel_metadata.ingress_tunnel_type = INGRESS_TUNNEL_TYPE_IP_IN_IP;
        transition parse_inner_ipv6;
    }


    state parse_udp_v6 
    {
        packet.extract(headers.udp);
        meta.l3_metadata.lkp_outer_l4_sport = headers.udp.srcPort;
        meta.l3_metadata.lkp_outer_l4_dport = headers.udp.dstPort;
        transition select(headers.udp.dstPort) 
        {
            UDP_PORT_BOOTPS: parse_set_prio_med;
            UDP_PORT_BOOTPC: parse_set_prio_med;
            UDP_PORT_DHCPV6_CLIENT: parse_set_prio_med;
            UDP_PORT_DHCPV6_SERVER: parse_set_prio_med;
            UDP_PORT_RIP: parse_set_prio_med;
            UDP_PORT_RIPNG: parse_set_prio_med;
            UDP_PORT_HSRP: parse_set_prio_med;
            default: accept;
        }
    }

    state parse_gre_v6 
    {
        packet.extract(headers.gre);
        transition select(headers.gre.C, headers.gre.R, headers.gre.K, headers.gre.S, headers.gre.s,
                          headers.gre.recurse, headers.gre.flags, headers.gre.ver, headers.gre.proto) 
        {
            (1w0x0, 1w0x0, 1w0x0, 1w0x0, 1w0x0, 3w0x0, 5w0x0, 3w0x0, 16w0x800): parse_gre_ipv4; // ETHERTYPE_IPV4
            default: accept;
        }
    }



    state parse_arp_rarp 
    {
        transition parse_set_prio_med;
    }



    state parse_nsh 
    {
        packet.extract(headers.nsh);
        packet.extract(headers.nsh_context);
        transition select(headers.nsh.protoType) 
        {
            ETHERTYPE_IPV4: parse_inner_ipv4;
            ETHERTYPE_IPV6: parse_inner_ipv6;
            ETHERTYPE_ETHERNET: parse_inner_ethernet;
            default: accept;
        }
    }



    state parse_roce 
    {
        packet.extract(headers.roce_header);
        transition accept;
    }



    state parse_fcoe 
    {
        packet.extract(headers.fcoe_header);
        transition accept;
    }



    state parse_trill 
    {
        packet.extract(headers.trill);
        transition parse_inner_ethernet;
    }



    state parse_vntag 
    {
        packet.extract(headers.vntag);
        transition parse_inner_ethernet;
    }


    state parse_set_prio_high 
    {
        meta.intrinsic_metadata.priority = CONTROL_TRAFFIC_PRIO_5;
        transition accept;
    }
}