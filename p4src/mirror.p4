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
 * Mirror processing
 */
control process_mirroring(inout headers_t headers, inout metadata meta)
{
#ifndef MIRROR_DISABLE
    action nop() {}
    action set_mirror_nhop(bit<16> nhop_idx)
    {
        meta.l3_metadata.nexthop_index = nhop_idx;
    }
    action set_mirror_bd(bit<16> bd)
    {
        meta.egress_metadata.bd = bd;
    }
    action sflow_pkt_to_cpu(bit<16> reason_code)
    {
        headers.fabric_header_sflow.setValid();
        headers.fabric_header_sflow.sflow_session_id = (bit<16>)meta.sflow_metadata.sflow_session_id;
        headers.fabric_header_sflow.sflow_egress_ifindex = (bit<16>)meta.ingress_metadata.egress_ifindex;
        meta.fabric_metadata.reason_code = reason_code;
    }
    table mirror
    {
        key = {
            meta.i2e_metadata.mirror_session_id: exact;
        }
        actions = {
            nop;
            set_mirror_nhop;
            set_mirror_bd;
            sflow_pkt_to_cpu;
        }
        size = MIRROR_SESSIONS_TABLE_SIZE;
    }
#endif /* MIRROR_DISABLE */

    apply
    {
#ifndef MIRROR_DISABLE
        mirror.apply();
#endif /* MIRROR_DISABLE */
    }
}
