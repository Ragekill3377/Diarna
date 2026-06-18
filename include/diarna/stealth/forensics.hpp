#pragma once
#include <diarna/compiler_port.hpp>
#include <cstdint>
#include <string>
#include <vector>
#include <memory>

namespace diarna::stealth {

class ForensicEvasion {
public:
    static ForensicEvasion& instance();

    bool wipe_mft_entry(const std::wstring& path);
    bool wipe_mft_entries(const std::vector<std::wstring>& paths);
    bool clear_usn_journal(wchar_t drive_letter = L'C');
    bool wipe_logfile(wchar_t drive_letter = L'C');
    bool overwrite_clusters(const std::wstring& path, uint32_t passes = 3);
    bool zero_timestamps(const std::wstring& path);
    bool remove_directory_index(const std::wstring& path);
    bool wipe_ads(const std::wstring& path);
    bool full_wipe(const std::wstring& path);
    bool nuke_freespace(wchar_t drive_letter = L'C', uint32_t passes = 1);

    struct NtfsVolumeInfo {
        uint64_t bytes_per_sector;
        uint8_t sectors_per_cluster;
        uint64_t mft_start_lcn;
        uint64_t mftmirr_start_lcn;
        uint32_t mft_record_size;
        uint32_t cluster_size;
    };
    bool parse_ntfs_boot(wchar_t drive_letter, NtfsVolumeInfo& info);

private:
    ForensicEvasion();
    ForensicEvasion(const ForensicEvasion&) = delete;
    ForensicEvasion& operator=(const ForensicEvasion&) = delete;

    HANDLE open_volume_direct(wchar_t drive_letter);
    uint64_t lcn_to_offset(const NtfsVolumeInfo& info, uint64_t lcn);
    bool read_sector(HANDLE h, uint64_t offset, void* buf, uint32_t size);
    bool write_sector(HANDLE h, uint64_t offset, const void* buf, uint32_t size);
    uint64_t get_file_frn(const std::wstring& path);
    bool collect_file_clusters(HANDLE h, const NtfsVolumeInfo& info,
                               const std::wstring& path, std::vector<uint64_t>& clusters);
    bool find_mft_record(HANDLE h, const NtfsVolumeInfo& info,
                         uint64_t frn, uint64_t& record_offset);
    bool overwrite_cluster_range(HANDLE h, uint64_t start_lcn, uint64_t count,
                                  uint32_t passes);
};

} // namespace diarna::stealth
