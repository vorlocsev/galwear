/* Known synthetic dlopen payload. */
__attribute__((visibility("default"))) int probe_add(int value)
{
    return value + 21;
}
