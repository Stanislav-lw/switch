/*
 * Meter processing
 */
/*****************************************************************************/
/* Meters                                                                    */
/*****************************************************************************/
control process_meter_index(inout metadata meta)
{
#ifndef METER_DISABLE
    direct_meter<bit<2>>(MeterType.bytes) direct_meter_index;
    action nop()
    {
        direct_meter_index.read(meta.meter_metadata.packet_color);
    }
    table meter_index 
    {
        key = {
            meta.meter_metadata.meter_index: exact;
        }
        actions = {
            nop;
        }
        size = METER_INDEX_TABLE_SIZE;
        meters = direct_meter_index;
    }
#endif /* METER_DISABLE */

    apply 
    {
#ifndef METER_DISABLE
        if (DO_LOOKUP(METER)) {
            meter_index.apply();
        }
#endif /* METER_DISABLE */
    }
}

control process_meter_action(inout metadata meta, inout standard_metadata_t standard_metadata)
{
#ifndef METER_DISABLE
#ifndef STATS_DISABLE
    direct_counter(CounterType.packets) meter_stats;
#endif /* STATS_DISABLE */
    action meter_permit()
    {
#ifndef STATS_DISABLE
        meter_stats.count();
#endif /* STATS_DISABLE */
    }
    action meter_deny()
    {
#ifndef STATS_DISABLE
        meter_stats.count();
#endif /* STATS_DISABLE */
        mark_to_drop(standard_metadata);
    }
    table meter_action
    {
        key = {
            meta.meter_metadata.packet_color: exact;
            meta.meter_metadata.meter_index : exact;
        }
        actions = {
            meter_permit;
            meter_deny;
        }
        size = METER_ACTION_TABLE_SIZE;
#ifndef STATS_DISABLE
        counters = meter_stats;
#endif /* STATS_DISABLE */
    }
#endif /* METER_DISABLE */
    
    apply
    {
#ifndef METER_DISABLE
        if (DO_LOOKUP(METER)) {
            meter_action.apply();
        }
#endif /* METER_DISABLE */
    }
}