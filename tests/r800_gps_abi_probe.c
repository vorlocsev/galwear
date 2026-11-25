/* Compile-only ARM32 ABI test. No guest code is executed. */
typedef unsigned int size_t;
typedef unsigned short uint16_t;
typedef unsigned int uint32_t;
typedef long long int64_t;
typedef unsigned long pthread_t;
#include "../src/tools/gps/gps_abi.h"
const unsigned int r800_gps_abi_sizes[] = {
    sizeof(GpsLocation), sizeof(GpsStatus), sizeof(GpsCallbacks),
    sizeof(GpsInterface), sizeof(GpsXtraCallbacks), sizeof(GpsXtraInterface)
};
