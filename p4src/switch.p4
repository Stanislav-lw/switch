#include <core.p4>
#define V1MODEL_VERSION 20200408
#include <v1model.p4>

#include "includes/p4features.h"
#include "includes/drop_reason_codes.h"
#include "includes/cpu_reason_codes.h"
#include "includes/p4_table_sizes.h"

#include "includes/defines.p4"
#include "includes/headers.p4"
#include "includes/intrinsic.p4"
#include "includes/parser.p4"

#include "switch_config.p4"
#include "port.p4"
#include "l2.p4"
#include "l3.p4"
#include "ipv4.p4"
#include "ipv6.p4"
#include "multicast.p4"
#include "fabric.p4"
#include "tunnel.p4"
#include "acl.p4"
#include "nat.p4"
#include "nexthop.p4"
#include "rewrite.p4"
#include "security.p4"
#include "egress_filter.p4"
#include "mirror.p4"
#include "int_transit.p4"
#include "hashes.p4"
#include "meter.p4"
#include "sflow.p4"
#include "qos.p4"



control verifyChecksum(inout headers_t headers,
                       inout metadata meta) 
{
  apply 
  {
    verify_checksum(headers.inner_ipv4.isValid() && headers.inner_ipv4.ihl == 4w5,
                    { headers.inner_ipv4.version,
                      headers.inner_ipv4.ihl,
                      headers.inner_ipv4.diffserv,
                      headers.inner_ipv4.totalLen,
                      headers.inner_ipv4.identification,
                      headers.inner_ipv4.flags,
                      headers.inner_ipv4.fragOffset,
                      headers.inner_ipv4.ttl,
                      headers.inner_ipv4.protocol,
                      headers.inner_ipv4.srcAddr,
                      headers.inner_ipv4.dstAddr },
                    headers.inner_ipv4.headersChecksum,
                    HashAlgorithm.csum16);
    verify_checksum(headers.ipv4.isValid() && headers.ipv4.ihl == 4w5,
                    { headers.ipv4.version,
                      headers.ipv4.ihl,
                      headers.ipv4.diffserv,
                      headers.ipv4.totalLen,
                      headers.ipv4.identification,
                      headers.ipv4.flags,
                      headers.ipv4.fragOffset,
                      headers.ipv4.ttl,
                      headers.ipv4.protocol,
                      headers.ipv4.srcAddr,
                      headers.ipv4.dstAddr },
                    headers.ipv4.headersChecksum,
                    HashAlgorithm.csum16);
  }
}

control ingress(inout headers_t headers,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) 
{
  action rmac_hit()
  {
      meta.l3_metadata.rmac_hit = TRUE;
  }
  action rmac_miss()
  {
      meta.l3_metadata.rmac_hit = FALSE;
  }
  table rmac
  {
    key = {
        meta.l3_metadata.rmac_group: exact;
        meta.l2_metadata.lkp_mac_da: exact;
    }
    actions = {
        rmac_hit;
        rmac_miss;
    }
    size = ROUTER_MAC_TABLE_SIZE;
  }
  apply 
  {
    process_ingress_port_mapping.apply(meta, standard_metadata);
    process_validate_outer_header.apply(headers, meta, standard_metadata);
    process_global_params.apply(meta, standard_metadata);
    process_port_vlan_mapping.apply(headers, meta);
    process_spanning_tree.apply(meta);
    process_ingress_qos_map.apply(meta);
    process_ip_sourceguard.apply(meta);
    process_int_endpoint.apply(headers, meta, standard_metadata);
    process_ingress_sflow.apply(headers, meta);
    process_tunnel.apply(headers, meta, standard_metadata);
    process_storm_control.apply(meta, standard_metadata);
    if (meta.ingress_metadata.port_type != PORT_TYPE_FABRIC) {
      if (!headers.mpls[0].isValid() && meta.l3_metadata.fib_hit == TRUE)
      {
          process_validate_packet.apply(meta);
          process_ingress_l4port.apply(meta);
          process_mac.apply(meta, standard_metadata);
          process_mac_acl.apply(meta);
          if (meta.l3_metadata.lkp_ip_type == IPTYPE_IPV4 ||
              meta.l3_metadata.lkp_ip_type == IPTYPE_IPV6)
          {
              process_ip_acl.apply(headers, meta);
          }
          switch (rmac.apply().action_run) {
            rmac_miss: {
                process_multicast.apply(meta);
            }
            default: {
              if (DO_LOOKUP(L3)) {
                if (meta.l3_metadata.lkp_ip_type == IPTYPE_IPV4 && 
                    meta.ipv4_metadata.ipv4_unicast_enabled == TRUE) 
                {
                    process_ipv4_racl.apply(meta);
                    process_ipv4_urpf.apply(meta);
                    process_ipv4_fib.apply(meta);
                } else {
                    if (meta.l3_metadata.lkp_ip_type == IPTYPE_IPV6 &&
                        meta.ipv6_metadata.ipv6_unicast_enabled == TRUE)
                    {
                        process_ipv6_racl.apply(meta);
                        process_ipv6_urpf.apply(meta);
                        process_ipv6_fib.apply(meta);
                    }
                }
                process_urpf_bd.apply(meta);
              }
            }
          }
          process_ingress_nat.apply(meta);
      }
    }
    process_meter_index.apply(meta);
    process_hashes.apply(headers, meta);
    process_meter_action.apply(meta, standard_metadata);
    if (meta.ingress_metadata.port_type != PORT_TYPE_FABRIC) {
      process_ingress_bd_stats.apply(meta);
      process_ingress_acl_stats.apply(meta);
      process_storm_control_stats.apply(meta, standard_metadata);
      process_fwd_results.apply(meta, standard_metadata);
      process_nexthop.apply(meta);
      if (meta.ingress_metadata.egress_ifindex == IFINDEX_FLOOD) {
          process_multicast_flooding.apply(meta);
      } else {
          process_lag.apply(meta, standard_metadata);
      }
      process_mac_learning.apply(meta);
    }
    process_fabric_lag.apply(headers, meta, standard_metadata);
    process_traffic_class.apply(meta);
    if (meta.ingress_metadata.port_type != PORT_TYPE_FABRIC) {
        process_system_acl.apply(meta, standard_metadata);
    }
  }
}

control egress(inout headers_t headers,
               inout metadata meta,
               inout standard_metadata_t standard_metadata) 
{
  action egress_port_type_normal(bit<16> ifindex, bit<5> qos_group, bit<16> if_label)
  {
    meta.egress_metadata.port_type = PORT_TYPE_NORMAL;
    meta.egress_metadata.ifindex = ifindex;
    meta.qos_metadata.egress_qos_group = qos_group;
    meta.acl_metadata.egress_if_label = if_label;
  }
  action egress_port_type_fabric(bit<16> ifindex)
  {
    meta.egress_metadata.port_type = PORT_TYPE_FABRIC;
    meta.egress_metadata.ifindex = ifindex;
    meta.tunnel_metadata.egress_tunnel_type = EGRESS_TUNNEL_TYPE_FABRIC;
  }
  action egress_port_type_cpu(bit<16> ifindex)
  {
    meta.egress_metadata.port_type = PORT_TYPE_CPU;
    meta.egress_metadata.ifindex = ifindex;
    meta.tunnel_metadata.egress_tunnel_type = EGRESS_TUNNEL_TYPE_CPU;
  }
  table egress_port_mapping
  {
    actions = {
        egress_port_type_normal;
        egress_port_type_fabric;
        egress_port_type_cpu;
    }
    key = {
        standard_metadata.egress_port: exact;
    }
    size = PORTMAP_TABLE_SIZE;
  }
  apply 
  {
    if ((meta.intrinsic_metadata.deflection_flag == FALSE) && 
        (meta.egress_metadata.bypass == FALSE)) 
    {
      if (pkt_is_mirrored) {
          process_mirroring.apply(headers, meta);
      } else {
          process_replication.apply(meta);
      }
      switch (egress_port_mapping.apply().action_run) {
        egress_port_type_normal: {
          if (pkt_is_not_mirrored) {
              process_vlan_decap.apply(headers);
          }
          process_tunnel_decap.apply(headers, meta);
          process_rewrite.apply(headers, meta);
          process_egress_bd.apply(meta);
          process_egress_qos_map.apply(meta);
          process_mac_rewrite.apply(headers, meta);
          process_mtu.apply(headers, meta);
          process_int_insertion.apply(headers, meta, standard_metadata);
          process_egress_nat.apply(headers, meta);
          process_egress_bd_stats.apply(meta);
        }
      }
      process_egress_l4port.apply(headers, meta);
      process_tunnel_encap.apply(headers, meta, standard_metadata);
      if (meta.egress_metadata.port_type == PORT_TYPE_NORMAL) {
          process_egress_acl.apply(headers, meta, standard_metadata);
      }
      process_int_outer_encap.apply(headers, meta, standard_metadata);
      if (meta.egress_metadata.port_type == PORT_TYPE_NORMAL) {
          process_vlan_xlate.apply(headers, meta);
      }
      process_egress_filter.apply(meta, standard_metadata);
    }
    if (meta.egress_metadata.port_type == PORT_TYPE_NORMAL) {
      process_egress_system_acl.apply(meta, standard_metadata);
    }
  }
}

control computeChecksum(inout headers_t  headers, 
                          inout metadata meta) 
{
  apply 
  {
    update_checksum(headers.inner_ipv4.isValid() && headers.inner_ipv4.ihl == 4w5,
                    { headers.inner_ipv4.version,
                      headers.inner_ipv4.ihl,
                      headers.inner_ipv4.diffserv,
                      headers.inner_ipv4.totalLen,
                      headers.inner_ipv4.identification,
                      headers.inner_ipv4.flags,
                      headers.inner_ipv4.fragOffset,
                      headers.inner_ipv4.ttl,
                      headers.inner_ipv4.protocol,
                      headers.inner_ipv4.srcAddr,
                      headers.inner_ipv4.dstAddr },
                    headers.inner_ipv4.headersChecksum,
                    HashAlgorithm.csum16);
    update_checksum(headers.ipv4.isValid() && headers.ipv4.ihl == 4w5,
                    { headers.ipv4.version,
                      headers.ipv4.ihl,
                      headers.ipv4.diffserv,
                      headers.ipv4.totalLen,
                      headers.ipv4.identification,
                      headers.ipv4.flags,
                      headers.ipv4.fragOffset,
                      headers.ipv4.ttl,
                      headers.ipv4.protocol,
                      headers.ipv4.srcAddr,
                      headers.ipv4.dstAddr },
                    headers.ipv4.headersChecksum,
                    HashAlgorithm.csum16);
  }
}

control deparser(packet_out packet, 
                 in headers_t headers) 
{
  apply 
  {
    packet.emit(headers.ethernet);
    packet.emit(headers.llc_header);
    packet.emit(headers.snap_header);
    packet.emit(headers.roce_header);
    packet.emit(headers.roce_v2_header);
    packet.emit(headers.fcoe_header);
    packet.emit(headers.vlan_tag[0]);
    packet.emit(headers.vlan_tag[1]);
    packet.emit(headers.ieee802_1ah);
    packet.emit(headers.mpls[0]);
    packet.emit(headers.mpls[1]);
    packet.emit(headers.mpls[2]);
    packet.emit(headers.icmp);
    packet.emit(headers.ipv4);
    packet.emit(headers.ipv6);
    packet.emit(headers.sctp);
    packet.emit(headers.tcp);
    packet.emit(headers.udp);
    packet.emit(headers.inner_ethernet);
    packet.emit(headers.inner_icmp);
    packet.emit(headers.inner_ipv4);
    packet.emit(headers.inner_ipv6);
    packet.emit(headers.inner_sctp);
    packet.emit(headers.inner_udp);
    packet.emit(headers.inner_tcp);
    packet.emit(headers.gre);
    packet.emit(headers.nvgre);
    packet.emit(headers.erspan_header_t3);
    packet.emit(headers.ipsec_esp);
    packet.emit(headers.ipsec_ah);
    packet.emit(headers.arp_rarp);
    packet.emit(headers.arp_rarp_ipv4);
    packet.emit(headers.eompls);
    packet.emit(headers.vxlan);
    packet.emit(headers.nsh);
    packet.emit(headers.nsh_context);
    packet.emit(headers.genv);
    packet.emit(headers.genv_opt_A);
    packet.emit(headers.genv_opt_B);
    packet.emit(headers.genv_opt_C);
    packet.emit(headers.trill);
    packet.emit(headers.lisp);
    packet.emit(headers.vntag);
    packet.emit(headers.bfd);
#ifdef SFLOW_ENABLE
    packet.emit(headers.sflow_hdr);
    packet.emit(headers.sflow_sample);
    packet.emit(headers.sflow_raw_hdr_record);
#endif
    packet.emit(headers.fabric_header);
    packet.emit(headers.fabric_header_cpu);
    packet.emit(headers.fabric_header_sflow);
    packet.emit(headers.fabric_header_mirror);
    packet.emit(headers.fabric_header_multicast);
    packet.emit(headers.fabric_header_unicast);
    packet.emit(headers.fabric_payload_header);
    packet.emit(headers.snap_header);
#ifdef INT_ENABLE
    packet.emit(headers.int_header);
    packet.emit(headers.int_switch_id_header);
    packet.emit(headers.int_ingress_port_id_header);
    packet.emit(headers.int_hop_latency_header);
    packet.emit(headers.int_q_occupancy_header);
    packet.emit(headers.int_ingress_tstamp_header);
    packet.emit(headers.int_egress_port_id_header);
    packet.emit(headers.int_q_congestion_header);
    packet.emit(headers.int_egress_port_tx_utilization_header);
    packet.emit(headers.vxlan_gpe_int_header);
    packet.emit(headers.vxlan_gpe);
#endif
    packet.emit(headers.int_value);
  }
}


V1Switch(parserImpl(),
         verifyChecksum(),
         ingress(),
         egress(),
         computeChecksum(),
         deparser()) main;