// SPDX-License-Identifier: Apache-2.0
// Host-only AOSP property_info fixture generator for disposable QEMU virt.
#include <fstream>
#include <iostream>
#include <string>
#include <vector>
#include <property_info_serializer/property_info_serializer.h>
#include <property_info_parser/property_info_parser.h>

int main(int argc, char** argv) {
    if (argc != 2 && (argc != 3 || std::string(argv[2]) != "--virt-fixture")) {
        std::cerr << "usage: galwear_property_info <new property_info file> [--virt-fixture]\n";
        return 2;
    }
    using android::properties::PropertyInfoEntry;
    const std::string context = argc == 3 ? "user_u:base_r:base_t" : "u:object_r:default_prop:s0";
    const std::vector<PropertyInfoEntry> entries = {
        {"debug.galwear.probe", context, "string", true},
    };
    std::string data, error;
    if (!android::properties::BuildTrie(entries, context, "string", &data, &error)) {
        std::cerr << error << '\n';
        return 1;
    }
    if (data.empty() || data.size() > 65536) return 1;
    const auto* area = reinterpret_cast<const android::properties::PropertyInfoArea*>(data.data());
    const char* found_context = nullptr;
    const char* found_type = nullptr;
    area->GetPropertyInfo("debug.galwear.probe", &found_context, &found_type);
    if (!found_context || !found_type || context != found_context ||
        std::string(found_type) != "string") return 1;
    std::ofstream out(argv[1], std::ios::binary | std::ios::out);
    out.write(data.data(), data.size());
    out.close();
    if (!out) return 1;
    std::cout << "r800-property-info: serialized lookup=PASS\n";
    return 0;
}
