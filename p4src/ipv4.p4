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
 * IPv4 processing
 */
/*****************************************************************************/
/* Validate outer IPv4 header                                                */
/*****************************************************************************/
control validate_outer_ipv4_header(inout headers_t headers, inout metadata meta)
{
#if !defined(L3_DISABLE) && !defined(IPV4_DISABLE)
    action set_valid_outer_ipv4_packet()
    {
        meta.l3_metadata.lkp_ip_type = IPTYPE_IPV4;
        meta.l3_metadata.lkp_dscp = (bit<8>)headers.ipv4.diffserv;
        meta.l3_metadata.lkp_ip_version = (bit<4>)headers.ipv4.version;
    }
    action set_malformed_outer_ipv4_packet(bit<8> drop_reason)
    {
        meta.ingress_metadata.drop_flag = TRUE;
        meta.ingress_metadata.drop_reason = drop_reason;
    }
    table validate_outer_ipv4_packet
    {
        key = {
            headers.ipv4.version       : ternary;
            headers.ipv4.ttl           : ternary;
            headers.ipv4.srcAddr[31:24]: ternary;
        }
        actions = {
            set_valid_outer_ipv4_packet;
            set_malformed_outer_ipv4_packet;
        }
        size = VALIDATE_PACKET_TABLE_SIZE;
    }
#endif /* L3_DISABLE && IPV4_DISABLE */

    apply
    {
#if !defined(L3_DISABLE) && !defined(IPV4_DISABLE)
        validate_outer_ipv4_packet.apply();
#endif /* L3_DISABLE && IPV4_DISABLE */
    }
}

/*****************************************************************************/
/* IPv4 FIB lookup                                                           */
/*****************************************************************************/
control process_ipv4_fib(inout metadata meta)
{
#if !defined(L3_DISABLE) && !defined(IPV4_DISABLE)
    action on_miss() {}
    action fib_hit_nexthop(bit<16> nexthop_index)
    {
        meta.l3_metadata.fib_hit = TRUE;
        meta.l3_metadata.fib_nexthop = nexthop_index;
        meta.l3_metadata.fib_nexthop_type = NEXTHOP_TYPE_SIMPLE;
    }
    action fib_hit_ecmp(bit<16> ecmp_index)
    {
        meta.l3_metadata.fib_hit = TRUE;
        meta.l3_metadata.fib_nexthop = ecmp_index;
        meta.l3_metadata.fib_nexthop_type = NEXTHOP_TYPE_ECMP;
    }
    table ipv4_fib
    {
        key = {
            meta.l3_metadata.vrf          : exact;
            meta.ipv4_metadata.lkp_ipv4_da: exact;
        }
        actions = {
            on_miss;
            fib_hit_nexthop;
            fib_hit_ecmp;
        }
        size = IPV4_HOST_TABLE_SIZE;
    }
    table ipv4_fib_lpm
    {
        key = {
            meta.l3_metadata.vrf          : exact;
            meta.ipv4_metadata.lkp_ipv4_da: lpm;
        }
        actions = {
            on_miss;
            fib_hit_nexthop;
            fib_hit_ecmp;
        }
        size = IPV4_LPM_TABLE_SIZE;
    }
#endif /* L3_DISABLE && IPV4_DISABLE */  
    
    apply
    {
#if !defined(L3_DISABLE) && !defined(IPV4_DISABLE)
        /* fib lookup */
        switch (ipv4_fib.apply().action_run) {
            on_miss: {
                ipv4_fib_lpm.apply();
            }
        }
#endif /* L3_DISABLE && IPV4_DISABLE */
    }
}

/*****************************************************************************/
/* IPv4 uRPF lookup                                                          */
/*****************************************************************************/
control process_ipv4_urpf(inout metadata meta)
{
#if !defined(L3_DISABLE) && !defined(IPV4_DISABLE) && !defined(URPF_DISABLE)
    action on_miss() {}
    action ipv4_urpf_hit(bit<16> urpf_bd_group)
    {
        meta.l3_metadata.urpf_hit = TRUE;
        meta.l3_metadata.urpf_bd_group = urpf_bd_group;
        meta.l3_metadata.urpf_mode = (bit<2>)meta.ipv4_metadata.ipv4_urpf_mode;
    }
    action urpf_miss()
    {
        meta.l3_metadata.urpf_check_fail = TRUE;
    }
    table ipv4_urpf
    {
        key = {
            meta.l3_metadata.vrf          : exact;
            meta.ipv4_metadata.lkp_ipv4_sa: exact;
        }
        actions = {
            on_miss;
            ipv4_urpf_hit;
        }
        size = IPV4_HOST_TABLE_SIZE;
    }
    table ipv4_urpf_lpm
    {
        key = {
            meta.l3_metadata.vrf          : exact;
            meta.ipv4_metadata.lkp_ipv4_sa: lpm;
        }
        actions = {
            ipv4_urpf_hit;
            urpf_miss;
        }
        size = IPV4_LPM_TABLE_SIZE;
    }
#endif /* L3_DISABLE && IPV4_DISABLE && URPF_DISABLE */

    apply
    {
#if !defined(L3_DISABLE) && !defined(IPV4_DISABLE) && !defined(URPF_DISABLE)        
        if (meta.ipv4_metadata.ipv4_urpf_mode != URPF_MODE_NONE) {
            switch (ipv4_urpf.apply().action_run) {
                on_miss: {
                    ipv4_urpf_lpm.apply();
                }
            }
        }
#endif /* L3_DISABLE && IPV4_DISABLE && URPF_DISABLE */
    }
}
