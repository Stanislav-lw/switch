/*
Copyright 2016-present Barefoot Networks, Inc. 

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


/* ---------------------- sflow ingress processing ------------------------ */
control process_ingress_sflow(inout headers_t headers, inout metadata meta)
{
#ifdef SFLOW_ENABLE
    direct_counter(CounterType.packets) sflow_ingress_session_pkt_counter;
    action nop() {}
    action sflow_ing_pkt_to_cpu(bit<32> sflow_i2e_mirror_id)
    {
        meta.i2e_metadata.mirror_session_id = (bit<16>)sflow_i2e_mirror_id;
        clone_preserving_field_list(CloneType.I2E, (bit<32>)sflow_i2e_mirror_id, (bit<8>)FieldLists.sflow_cpu_info);
    }
    table sflow_ing_take_sample
    {
        /* take_sample > MAX_VAL_31 and valid sflow_session_id => take the sample */
        key = {
            meta.ingress_metadata.sflow_take_sample : ternary;
            meta.sflow_metadata.sflow_session_id    : exact;
        }
        actions = {
            nop;
            sflow_ing_pkt_to_cpu;
        }
        size = MAX_SFLOW_SESSIONS;
    }
    action act_counter()
    {
        sflow_ingress_session_pkt_counter.count();
    }
    action sflow_ing_session_enable(bit<32> rate_thr, bit<16> session_id)
    {
        /* take_sample(sat) = rate_thr + take_sample(initialized from RNG) */
        /* if take_sample == max_val, sample will be take in the subsequent table-action */
        sflow_ingress_session_pkt_counter.count();
        meta.ingress_metadata.sflow_take_sample = rate_thr |+| meta.ingress_metadata.sflow_take_sample;
        meta.sflow_metadata.sflow_session_id = session_id;
    }
    table sflow_ingress
    {
        /* Table to determine ingress port based enablement */
        /* This is separate from ACLs so that this table can be applied */
        /* independent of ACLs */
        key = {
            meta.ingress_metadata.ifindex  : ternary;
            meta.ipv4_metadata.lkp_ipv4_sa : ternary;
            meta.ipv4_metadata.lkp_ipv4_da : ternary;
            headers.sflow_hdr.isValid()        : exact; /* do not sflow an sflow frame */
        }
        actions = {
            act_counter; /* default action */
            sflow_ing_session_enable;
        }
        size = SFLOW_INGRESS_TABLE_SIZE;
        counters = sflow_ingress_session_pkt_counter;
    }
#endif /* SFLOW_ENABLE */

    apply
    {
#ifdef SFLOW_ENABLE
        sflow_ingress.apply();
        sflow_ing_take_sample.apply();
#endif /* SFLOW_ENABLE */
    }
}