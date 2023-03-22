/*****************************************************************************/
/* HASH calculation                                                          */
/*****************************************************************************/
control process_hashes(inout headers_t headers, inout metadata meta)
{
    action compute_lkp_ipv4_hash()
    {
        hash(meta.hash_metadata.hash1, HashAlgorithm.crc16, (bit<16>)0, { meta.ipv4_metadata.lkp_ipv4_sa,
                                                                          meta.ipv4_metadata.lkp_ipv4_da,
                                                                          meta.l3_metadata.lkp_ip_proto,
                                                                          meta.l3_metadata.lkp_l4_sport,
                                                                          meta.l3_metadata.lkp_l4_dport }, (bit<32>)65536);
        hash(meta.hash_metadata.hash2, HashAlgorithm.crc16, (bit<16>)0, { meta.l2_metadata.lkp_mac_sa,
                                                                          meta.l2_metadata.lkp_mac_da,
                                                                          meta.ipv4_metadata.lkp_ipv4_sa,
                                                                          meta.ipv4_metadata.lkp_ipv4_da,
                                                                          meta.l3_metadata.lkp_ip_proto,
                                                                          meta.l3_metadata.lkp_l4_sport,
                                                                          meta.l3_metadata.lkp_l4_dport }, (bit<32>)65536);
    }
    table compute_ipv4_hashes
    {
        key = {
            meta.ingress_metadata.drop_flag: exact;
        }
        actions = {
            compute_lkp_ipv4_hash;
        }
    }
    action compute_lkp_ipv6_hash()
    {
        hash(meta.hash_metadata.hash1, HashAlgorithm.crc16, (bit<16>)0, { meta.ipv6_metadata.lkp_ipv6_sa,
                                                                          meta.ipv6_metadata.lkp_ipv6_da,
                                                                          meta.l3_metadata.lkp_ip_proto,
                                                                          meta.l3_metadata.lkp_l4_sport,
                                                                          meta.l3_metadata.lkp_l4_dport }, (bit<32>)65536);
        hash(meta.hash_metadata.hash2, HashAlgorithm.crc16, (bit<16>)0, { meta.l2_metadata.lkp_mac_sa,
                                                                          meta.l2_metadata.lkp_mac_da,
                                                                          meta.ipv6_metadata.lkp_ipv6_sa,
                                                                          meta.ipv6_metadata.lkp_ipv6_da,
                                                                          meta.l3_metadata.lkp_ip_proto,
                                                                          meta.l3_metadata.lkp_l4_sport,
                                                                          meta.l3_metadata.lkp_l4_dport }, (bit<32>)65536);
    }
    table compute_ipv6_hashes
    {
        key = {
            meta.ingress_metadata.drop_flag: exact;
        }
        actions = {
            compute_lkp_ipv6_hash;
        }
    }
    action compute_lkp_non_ip_hash()
    {
        hash(meta.hash_metadata.hash2, HashAlgorithm.crc16, (bit<16>)0, { meta.ingress_metadata.ifindex,
                                                                          meta.l2_metadata.lkp_mac_sa,
                                                                          meta.l2_metadata.lkp_mac_da,
                                                                          meta.l2_metadata.lkp_mac_type }, (bit<32>)65536);
    }
    table compute_non_ip_hashes
    {
        key = {
            meta.ingress_metadata.drop_flag: exact;
        }
        actions = {
            compute_lkp_non_ip_hash;
        }
    }
    action computed_two_hashes()
    {
        meta.intrinsic_metadata.mcast_hash = (bit<13>)meta.hash_metadata.hash1;
        meta.hash_metadata.entropy_hash = (bit<16>)meta.hash_metadata.hash2;
    }
    action computed_one_hash()
    {
        meta.hash_metadata.hash1 = (bit<16>)meta.hash_metadata.hash2;
        meta.intrinsic_metadata.mcast_hash = (bit<13>)meta.hash_metadata.hash2;
        meta.hash_metadata.entropy_hash = (bit<16>)meta.hash_metadata.hash2;
    }
    table compute_other_hashes
    {
        key = {
            meta.hash_metadata.hash1: exact;
        }
        actions = {
            computed_two_hashes;
            computed_one_hash;
        }
    }

    apply
    {
        if ((meta.tunnel_metadata.tunnel_terminate == FALSE && headers.ipv4.isValid()) ||
            (meta.tunnel_metadata.tunnel_terminate == TRUE && headers.inner_ipv4.isValid())) {
#ifndef IPV4_DISABLE
            compute_ipv4_hashes.apply();
#endif /* IPV4_DISABLE */
        }
#ifndef IPV6_DISABLE
        else {
            if ((meta.tunnel_metadata.tunnel_terminate == FALSE && headers.ipv6.isValid()) ||
                (meta.tunnel_metadata.tunnel_terminate == TRUE && headers.inner_ipv6.isValid())) {
                compute_ipv6_hashes.apply();
            }
#endif /* IPV6_DISABLE */
            else {
#ifndef L2_DISABLE
                compute_non_ip_hashes.apply();
#endif /* L2_DISABLE */
            }
#ifndef IPV6_DISABLE
        }
#endif /* IPV6_DISABLE */
        compute_other_hashes.apply();
    }
}