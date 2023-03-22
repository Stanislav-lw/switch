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
/* Egress filtering logic                                                    */
/*****************************************************************************/
control process_egress_filter(inout metadata meta, inout standard_metadata_t standard_metadata)
{
#ifdef EGRESS_FILTER
    action egress_filter_check()
    {
        meta.egress_filter_metadata.ifindex_check = (bit<16>)meta.ingress_metadata.ifindex ^ (bit<16>)meta.egress_metadata.ifindex;
        meta.egress_filter_metadata.bd = (bit<16>)meta.ingress_metadata.outer_bd ^ (bit<16>)meta.egress_metadata.outer_bd;
        meta.egress_filter_metadata.inner_bd = (bit<16>)meta.ingress_metadata.bd ^ (bit<16>)meta.egress_metadata.bd;
    }
    action set_egress_filter_drop()
    {
        mark_to_drop(standard_metadata);
    }
    table egress_filter
    {
        actions = {
            egress_filter_check;
        }
    }
    table egress_filter_drop
    {
        actions = {
            set_egress_filter_drop;
        }
    }
#endif /* EGRESS_FILTER */

    apply
    {
#ifdef EGRESS_FILTER
        egress_filter.apply();
        if (meta.multicast_metadata.inner_replica == TRUE) {
            if (((meta.tunnel_metadata.ingress_tunnel_type == INGRESS_TUNNEL_TYPE_NONE) &&
                 (meta.tunnel_metadata.egress_tunnel_type == EGRESS_TUNNEL_TYPE_NONE) &&
                 (meta.egress_filter_metadata.bd == 16w0) &&
                 (meta.egress_filter_metadata.ifindex_check == 16w0)) ||
                ((meta.tunnel_metadata.ingress_tunnel_type != INGRESS_TUNNEL_TYPE_NONE) &&
                 (meta.tunnel_metadata.egress_tunnel_type != EGRESS_TUNNEL_TYPE_NONE)) &&
                 (meta.egress_filter_metadata.inner_bd == 16w0)) {
                egress_filter_drop.apply();
            }
        }
#endif /* EGRESS_FILTER */
    }
}