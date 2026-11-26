/* Explicitly selected local XTRA ABI. No proprietary ABI inference. */
#ifndef R800_GPS_XTRA_H
#define R800_GPS_XTRA_H
enum gps_xtra_result { XTRA_DISABLED, XTRA_INVALID_DATA, XTRA_UNAVAILABLE,
                       XTRA_INIT_FAILED, XTRA_INJECT_FAILED, XTRA_OK };
static enum gps_xtra_result gps_xtra_submit(const GpsInterface *gps,
        const GpsXtraInterface **cached, GpsXtraCallbacks *callbacks,
        char *data, int size, int *hal_result)
{
    const GpsXtraInterface *candidate;
    *hal_result = 0;
    if (R800_XTRA_ABI == 0)
        return XTRA_DISABLED;
    if (!data || size <= 0 || size > 256 * 1024)
        return XTRA_INVALID_DATA;
    if (!*cached) {
        if (!gps || !gps->get_extension || !callbacks ||
            !callbacks->download_request_cb || !callbacks->create_thread_cb)
            return XTRA_UNAVAILABLE;
#if R800_XTRA_ABI == 2
        if (callbacks->size != sizeof(*callbacks))
            return XTRA_UNAVAILABLE;
#endif
        candidate = gps->get_extension("gps-xtra");
        if (!candidate || candidate->size < sizeof(*candidate) ||
            !candidate->init || !candidate->inject_xtra_data)
            return XTRA_UNAVAILABLE;
        *hal_result = candidate->init(callbacks);
        if (*hal_result != 0)
            return XTRA_INIT_FAILED;
        *cached = candidate;
    }
    *hal_result = (*cached)->inject_xtra_data(data, size);
    return *hal_result == 0 ? XTRA_OK : XTRA_INJECT_FAILED;
}
#endif
