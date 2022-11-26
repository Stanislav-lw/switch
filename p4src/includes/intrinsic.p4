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
enum bit<8> FieldLists {
    none = 0,
    i2e_mirror_info = 1,
    cpu_info = 2,
    e2e_mirror_info = 3,
    int_i2e_mirror_info = 4,
    mirror_info = 5,
    sflow_cpu_info = 6
}

struct acl_metadata_t 
{
    bit<1>  acl_deny;                       // Ifacl/vacl deny action.
    bit<1>  racl_deny;                      // Racl deny action.
    bit<16> acl_nexthop;                    // Next hop from ifacl/vacl.
    bit<16> racl_nexthop;                   // Next hop from racl.
    bit<2>  acl_nexthop_type;               // Ecmp or nexthop.
    bit<2>  racl_nexthop_type;              // Ecmp or nexthop.
    bit<1>  acl_redirect;                   // Ifacl/vacl redirect action.
    bit<1>  racl_redirect;                  // Racl redirect action.
    bit<16> if_label;                       // If label for acls.
    bit<16> bd_label;                       // Bd label for acls.
    bit<14> acl_stats_index;                // Acl stats index.
    bit<16> egress_if_label;                // If label for egress acls.
    bit<16> egress_bd_label;                // Bd label for egress acls.
    bit<8>  ingress_src_port_range_id;      // Ingress src port range id.
    bit<8>  ingress_dst_port_range_id;      // Ingress dst port range id.
    bit<8>  egress_src_port_range_id;       // Egress src port range id.
    bit<8>  egress_dst_port_range_id;       // Egress dst port range id.
}

struct egress_filter_metadata_t
{
    bit<16> ifindex_check;  // Src port filter.
    bit<16> bd;             // Bd for src port filter.
    bit<16> inner_bd;       // Split horizon filter.
}

struct egress_metadata_t
{
    bit<1>  bypass;             // Bypass egress pipeline.
    bit<2>  port_type;          // Egress port type.
    bit<16> payload_length;     // Payload length for tunnels.
    bit<9>  smac_idx;           // Index into source mac table.
    bit<16> bd;                 // Egress inner bd.
    bit<16> outer_bd;           // Egress inner bd. // NOTE: CHECK IT
    bit<48> mac_da;             // Final mac da.
    bit<1>  routed;             // Is this replica routed.
    bit<16> same_bd_check;      // Ingress bd xor egress bd.
    bit<8>  drop_reason;        // Drop reason.
    bit<16> ifindex;            // Egress interface index.
}

struct fabric_metadata_t
{
    bit<3>  packetType;
    bit<1>  fabric_header_present;
    @field_list(FieldLists.cpu_info, FieldLists.sflow_cpu_info) 
    bit<16> reason_code;    // Cpu reason code.
    bit<8>  dst_device;     // Destination device id.
    bit<16> dst_port;       // Destination port id.
}

struct global_config_metadata_t
{
    bit<1> enable_dod;  // Enable Deflection-on-Drop.
}

struct hash_metadata_t
{
    bit<16> hash1;
    bit<16> hash2;
    bit<16> entropy_hash;
}

struct i2e_metadata_t
{
    @field_list(FieldLists.i2e_mirror_info, FieldLists.e2e_mirror_info)
    bit<32> ingress_tstamp;
    @field_list(FieldLists.i2e_mirror_info, FieldLists.e2e_mirror_info, FieldLists.int_i2e_mirror_info) 
    bit<16> mirror_session_id;
}

struct ingress_metadata_t
{
    @field_list(FieldLists.cpu_info, FieldLists.sflow_cpu_info) 
    bit<9>  ingress_port;       // Input physical port.
    @field_list(FieldLists.cpu_info, FieldLists.mirror_info, FieldLists.sflow_cpu_info) 
    bit<16> ifindex;            // Input interface index.
    bit<16> egress_ifindex;     // Egress interface index.
    bit<2>  port_type;          // Ingress port type.
    bit<16> outer_bd;           // Outer BD.
    @field_list(FieldLists.cpu_info, FieldLists.sflow_cpu_info) 
    bit<16> bd;                 // BD.
    bit<1>  drop_flag;          // If set, drop the packet.
    @field_list(FieldLists.mirror_info) 
    bit<8>  drop_reason;        // Drop reason.
    bit<1>  control_frame;      // Control frame.
    bit<16> bypass_lookups;     // List of lookups to skip.
    @saturating 
    bit<32> sflow_take_sample;
}

struct int_metadata_t
{
    bit<32> switch_id;
    bit<8>  insert_cnt;
    bit<16> insert_byte_cnt;
    bit<16> gpe_int_hdr_len;
    bit<8>  gpe_int_hdr_len8;
    bit<16> instruction_cnt;
}

struct int_metadata_i2e_t
{
    @field_list(FieldLists.int_i2e_mirror_info) 
    bit<1> sink;
    bit<1> source;
}

struct ingress_intrinsic_metadata_t
{
    bit<1>  resubmit_flag;              // Flag distinguishing original packets from resubmitted packets.
    bit<48> ingress_global_timestamp;   // Global timestamp (ns) taken upon arrival at ingress. 
    bit<16> mcast_grp;                  // Multicast group id (key for the mcast replication table).
    bit<1>  deflection_flag;            // Flag indicating whether a packet is deflected due to deflect_on_drop.
    bit<1>  deflect_on_drop;            // Flag indicating whether a packet can be deflected by TM on congestion drop.
    bit<2>  enq_congest_stat;           // Queue congestion status at the packet enqueue time.
    bit<2>  deq_congest_stat;           // Queue congestion status at the packet enqueue time.
    bit<13> mcast_hash;                 // Multicast hashing.
    bit<16> egress_rid;                 // Replication ID for multicast.
    bit<32> lf_field_list;              // Learn filter field list.
    bit<3>  priority;                   // Set packet priority.
    bit<3>  ingress_cos;                // Ingress cos.
    bit<2>  packet_color;               // Packet color.
    bit<5>  qid;                        // Queue id.
}

struct ipv4_metadata_t
{
    bit<32> lkp_ipv4_sa;            // Ipv4 source address.
    bit<32> lkp_ipv4_da;            // Ipv4 destination address.
    bit<1>  ipv4_unicast_enabled;   // Is ipv4 unicast routing enabled.
    bit<2>  ipv4_urpf_mode;         // 0: none, 1: strict, 3: loose.
}

struct ipv6_metadata_t
{
    bit<128> lkp_ipv6_sa;               // Ipv6 source address.
    bit<128> lkp_ipv6_da;               // Ipv6 destination address.
    bit<1>   ipv6_unicast_enabled;      // Is ipv6 unicast routing enabled on BD.
    bit<1>   ipv6_src_is_link_local;    // Source is link local address.
    bit<2>   ipv6_urpf_mode;            // 0: none, 1: strict, 3: loose.
}

struct l2_metadata_t
{
    bit<48> lkp_mac_sa;
    bit<48> lkp_mac_da;
    bit<3>  lkp_pkt_type;
    bit<16> lkp_mac_type;
    bit<3>  lkp_pcp;
    bit<16> l2_nexthop;                 // Next hop from l2.
    bit<2>  l2_nexthop_type;            // Ecmp or nexthop.
    bit<1>  l2_redirect;                // L2 redirect action.
    bit<1>  l2_src_miss;                // L2 source miss.
    bit<16> l2_src_move;                // L2 source interface mis-match.
    bit<10> stp_group;                  // Spanning tree group id.
    bit<3>  stp_state;                  // Spanning tree port state.
    bit<16> bd_stats_idx;               // Ingress BD stats index.
    bit<1>  learning_enabled;           // Is learning enabled.
    bit<1>  port_vlan_mapping_miss;     // Port vlan mapping miss.
    bit<16> same_if_check;              // Same interface check.
}

struct l3_metadata_t
{
    bit<2>  lkp_ip_type;
    bit<4>  lkp_ip_version;
    bit<8>  lkp_ip_proto;
    bit<8>  lkp_dscp;
    bit<8>  lkp_ip_ttl;
    bit<16> lkp_l4_sport;
    bit<16> lkp_l4_dport;
    bit<16> lkp_outer_l4_sport;
    bit<16> lkp_outer_l4_dport;
    bit<16> vrf;                // VRF.
    bit<10> rmac_group;         // Rmac group, for rmac indirection.
    bit<1>  rmac_hit;           // Dst mac is the router's mac.
    bit<2>  urpf_mode;          // Urpf mode for current lookup.
    bit<1>  urpf_hit;           // Hit in urpf table.
    bit<1>  urpf_check_fail;    // Urpf check failed.
    bit<16> urpf_bd_group;      // Urpf bd group.
    bit<1>  fib_hit;            // Fib hit.
    bit<16> fib_nexthop;        // Next hop from fib.
    bit<2>  fib_nexthop_type;   // Ecmp or nexthop.
    bit<16> same_bd_check;      // Ingress bd xor egress bd.
    bit<16> nexthop_index;      // Nexthop/rewrite index.
    bit<1>  routed;             // Is packet routed?.
    bit<1>  outer_routed;       // Is outer packet routed?.
    bit<8>  mtu_index;          // Index into mtu table.
    bit<1>  l3_copy;            // Copy packet to CPU.
    bit<16> l3_mtu_check;       // Result of mtu check.
    bit<16> egress_l4_sport;
    bit<16> egress_l4_dport;
}

struct meter_metadata_t
{
    bit<2>  packet_color;   // Packet color.
    bit<16> meter_index;    // Meter index.
}

struct multicast_metadata_t
{
    bit<1>  ipv4_mcast_key_type;        // 0 bd, 1 vrf.
    bit<16> ipv4_mcast_key;             // Bd or vrf value.
    bit<1>  ipv6_mcast_key_type;        // 0 bd, 1 vrf.
    bit<16> ipv6_mcast_key;             // Bd or vrf value.
    bit<1>  outer_mcast_route_hit;      // Hit in the outer multicast table.
    bit<2>  outer_mcast_mode;           // Multicast mode from route.
    bit<1>  mcast_route_hit;            // Hit in the multicast route table.
    bit<1>  mcast_bridge_hit;           // Hit in the multicast bridge table.
    bit<1>  ipv4_multicast_enabled;     // Is ipv4 multicast enabled on BD.
    bit<1>  ipv6_multicast_enabled;     // Is ipv6 multicast enabled on BD.
    bit<1>  igmp_snooping_enabled;      // Is IGMP snooping enabled on BD.
    bit<1>  mld_snooping_enabled;       // Is MLD snooping enabled on BD.
    bit<16> bd_mrpf_group;              // Rpf group from bd lookup.
    bit<16> mcast_rpf_group;            // Rpf group from mcast lookup.
    bit<2>  mcast_mode;                 // Multicast mode from route.
    bit<16> multicast_route_mc_index;   // Multicast index from mfib.
    bit<16> multicast_bridge_mc_index;  // Multicast index from igmp/mld snoop.
    bit<1>  inner_replica;              // Is copy is due to inner replication.
    bit<1>  replica;                    // Is this a replica.
    bit<16> mcast_grp;
}

struct nat_metadata_t
{
    bit<2>  ingress_nat_mode;       // 0: none, 1: inside, 2: outside.
    bit<2>  egress_nat_mode;        // Nat mode of egress_bd.
    bit<16> nat_nexthop;            // Next hop from nat.
    bit<2>  nat_nexthop_type;       // Ecmp or nexthop.
    bit<1>  nat_hit;                // Fwd and rewrite info from nat.
    bit<14> nat_rewrite_index;      // NAT rewrite index.
    bit<1>  update_checksum;        // Update tcp/udp checksum.
    bit<1>  update_inner_checksum;  // Update inner tcp/udp checksum.
    bit<16> l4_len;                 // L4 length.
}

struct nexthop_metadata_t
{
    bit<2> nexthop_type;    // Final next hop index type.
}

struct qos_metadata_t
{
    bit<5> ingress_qos_group;
    bit<5> tc_qos_group;
    bit<5> egress_qos_group;
    bit<8> lkp_tc;
    bit<1> trust_dscp;
    bit<1> trust_pcp;
}

struct queueing_metadata_t
{
    bit<48> enq_timestamp;
    bit<16> enq_qdepth; // Queue depth at the packet enqueue time.
    bit<32> deq_timedelta;
    bit<16> deq_qdepth;
}

struct security_metadata_t
{
    bit<1> ipsg_enabled;        // Is ip source guard feature enabled.
    bit<1> ipsg_check_fail;     // Psg check failed.
}

struct sflow_meta_t
{
    bit<16> sflow_session_id;
}

struct tunnel_metadata_t
{
    bit<5>  ingress_tunnel_type;    // Tunnel type from parser.
    bit<24> tunnel_vni;             // Tunnel id.
    bit<1>  mpls_enabled;           // Is mpls enabled on BD.
    bit<20> mpls_label;             // Mpls label.
    bit<3>  mpls_exp;               // Mpls Traffic Class.
    bit<8>  mpls_ttl;               // Mpls Ttl.
    bit<5>  egress_tunnel_type;     // Type of tunnel.
    bit<14> tunnel_index;           // Tunnel index.
    bit<9>  tunnel_src_index;       // Index to tunnel src ip.
    bit<9>  tunnel_smac_index;      // Index to tunnel src mac.
    bit<14> tunnel_dst_index;       // Index to tunnel dst ip.
    bit<14> tunnel_dmac_index;      // Index to tunnel dst mac.
    bit<24> vnid;                   // Tunnel vnid.
    bit<1>  tunnel_terminate;       // Is tunnel being terminated?.
    bit<1>  tunnel_if_check;        // Tun terminate xor originate.
    bit<4>  egress_header_count;    // Number of mpls header stack.
    bit<8>  inner_ip_proto;         // Inner IP protocol.
    bit<1>  skip_encap_inner;       // Skip encap_process_inner.
}

struct metadata
{
    acl_metadata_t               acl_metadata;
    egress_filter_metadata_t     egress_filter_metadata;
    egress_metadata_t            egress_metadata;
    fabric_metadata_t            fabric_metadata;
    global_config_metadata_t     global_config_metadata;
    hash_metadata_t              hash_metadata;
    i2e_metadata_t               i2e_metadata;
    ingress_metadata_t           ingress_metadata;
    int_metadata_t               int_metadata;
    int_metadata_i2e_t           int_metadata_i2e;
    ingress_intrinsic_metadata_t intrinsic_metadata;
    ipv4_metadata_t              ipv4_metadata;
    ipv6_metadata_t              ipv6_metadata;
    l2_metadata_t                l2_metadata;
    l3_metadata_t                l3_metadata;
    meter_metadata_t             meter_metadata;
    multicast_metadata_t         multicast_metadata;
    nat_metadata_t               nat_metadata;
    nexthop_metadata_t           nexthop_metadata;
    qos_metadata_t               qos_metadata;
    queueing_metadata_t          queueing_metadata;
    security_metadata_t          security_metadata;
    sflow_meta_t                 sflow_metadata;
    tunnel_metadata_t            tunnel_metadata;
}

#define PKT_INSTANCE_TYPE_NORMAL 0
#define PKT_INSTANCE_TYPE_INGRESS_CLONE 1
#define PKT_INSTANCE_TYPE_EGRESS_CLONE 2
#define PKT_INSTANCE_TYPE_COALESCED 3
#define PKT_INSTANCE_TYPE_INGRESS_RECIRC 4
#define PKT_INSTANCE_TYPE_REPLICATION 5
#define PKT_INSTANCE_TYPE_RESUBMIT 6

#define pkt_is_mirrored \
    ((standard_metadata.instance_type != PKT_INSTANCE_TYPE_NORMAL) && \
     (standard_metadata.instance_type != PKT_INSTANCE_TYPE_REPLICATION))

#define pkt_is_not_mirrored \
    ((standard_metadata.instance_type == PKT_INSTANCE_TYPE_NORMAL) || \
     (standard_metadata.instance_type == PKT_INSTANCE_TYPE_REPLICATION))
