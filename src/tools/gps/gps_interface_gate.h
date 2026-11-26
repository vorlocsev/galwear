#ifndef R800_GPS_INTERFACE_GATE_H
#define R800_GPS_INTERFACE_GATE_H

/* Include after gps_abi.h. These checks assume a readable, live donor table.
 * Size and non-null slots do not prove proprietary function signatures. */
static inline int gps_interface_valid(const GpsInterface *table)
{
    if (!table || (__UINTPTR_TYPE__)table % __alignof__(GpsInterface))
        return 0;
    if (table->size != sizeof(*table))
        return 0;
    return table->init && table->start && table->stop && table->cleanup &&
           table->inject_time && table->inject_location && table->set_position_mode;
}

static inline int gps_xtra_interface_valid(const GpsXtraInterface *table)
{
    if (!table || (__UINTPTR_TYPE__)table % __alignof__(GpsXtraInterface))
        return 0;
    if (table->size != sizeof(*table))
        return 0;
    return table->init && table->inject_xtra_data;
}

#endif
