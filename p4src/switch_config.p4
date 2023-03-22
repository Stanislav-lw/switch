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
 * System global parameters
 */
control process_global_params(inout metadata meta,
                              inout standard_metadata_t standard_metadata)
{
    action deflect_on_drop(bit<1> enable_dod) 
    {
        meta.intrinsic_metadata.deflect_on_drop = enable_dod;
    }
    action set_config_parameters()
    {
        /* read system config parameters and store them in metadata
         * or take appropriate action
         */
        deflect_on_drop(1w0);
        /* initialization */
        meta.i2e_metadata.ingress_tstamp = (bit<32>)meta.intrinsic_metadata.ingress_global_timestamp;
        meta.ingress_metadata.ingress_port = (bit<9>)standard_metadata.ingress_port;
        meta.l2_metadata.same_if_check = (bit<16>)meta.ingress_metadata.ifindex;
        standard_metadata.egress_spec = INVALID_PORT_ID;
#ifdef SFLOW_ENABLE
        /* use 31 bit random number generator and detect overflow into upper half
         * to decide to take a sample
         */
        random(meta.ingress_metadata.sflow_take_sample, 32w0, 32w0x7fffffff);
#endif
    }

    /* set up global controls/parameters */
    apply
    {
        set_config_parameters();
    }
}
