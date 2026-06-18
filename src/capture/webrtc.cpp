#include <diarna/compiler_port.hpp>
#include <diarna/capture/capture.hpp>

#include <d3d11.h>
#include <dxgi1_2.h>
#include <gdiplus.h>
#include <mutex>
#include <cstring>

#include <obfuscation/obfusheader.h>
DIARNA_LINK_LIB("d3d11.lib")
DIARNA_LINK_LIB("dxgi.lib")
DIARNA_LINK_LIB("gdiplus.lib")
DIARNA_LINK_LIB("ole32.lib")
DIARNA_LINK_LIB("ws2_32.lib")

namespace diarna::capture {

DesktopDuplicator::DesktopDuplicator(int output_index)
    : output_index_(output_index) {
    INDIRECT_BRANCH;

    D3D_FEATURE_LEVEL feature_levels[] = {
        D3D_FEATURE_LEVEL_11_1,
        D3D_FEATURE_LEVEL_11_0,
        D3D_FEATURE_LEVEL_10_1,
        D3D_FEATURE_LEVEL_10_0,
    };

    ID3D11Device* dev = nullptr;
    ID3D11DeviceContext* ctx = nullptr;
    D3D_FEATURE_LEVEL chosen_level;

    HRESULT hr = D3D11CreateDevice(
        nullptr,
        D3D_DRIVER_TYPE_HARDWARE,
        nullptr,
        0,
        feature_levels,
        ARRAYSIZE(feature_levels),
        D3D11_SDK_VERSION,
        &dev,
        &chosen_level,
        &ctx);

    if (FAILED(hr)) {
        hr = D3D11CreateDevice(
            nullptr,
            D3D_DRIVER_TYPE_WARP,
            nullptr,
            0,
            feature_levels,
            ARRAYSIZE(feature_levels),
            D3D11_SDK_VERSION,
            &dev,
            &chosen_level,
            &ctx);
    }

    if (SUCCEEDED(hr) && dev && ctx) {
        device_ = dev;
        context_ = ctx;
    }
}

DesktopDuplicator::~DesktopDuplicator() {
    INDIRECT_BRANCH;
    stop();
    cleanup();
}

DIARNA_INLINE void DesktopDuplicator::cleanup() {
    if (staging_texture_) {
        staging_texture_->Release();
        staging_texture_ = nullptr;
    }
    if (duplication_) {
        duplication_->Release();
        duplication_ = nullptr;
    }
    if (context_) {
        context_->Release();
        context_ = nullptr;
    }
    if (device_) {
        device_->Release();
        device_ = nullptr;
    }
    last_width_ = 0;
    last_height_ = 0;
}

bool DesktopDuplicator::start(int fps, FrameCallback callback) {
    INDIRECT_BRANCH;

    if (!device_ || !context_)
        return false;
    if (running_.load())
        return false;
    if (fps <= 0)
        fps = 15;

    IDXGIDevice* dxgi_device = nullptr;
    HRESULT hr = device_->QueryInterface(__uuidof(IDXGIDevice),
                                          reinterpret_cast<void**>(&dxgi_device));
    if (FAILED(hr) || !dxgi_device)
        return false;

    IDXGIAdapter* adapter = nullptr;
    hr = dxgi_device->GetAdapter(&adapter);
    dxgi_device->Release();
    if (FAILED(hr) || !adapter)
        return false;

    IDXGIOutput* output = nullptr;
    hr = adapter->EnumOutputs(static_cast<UINT>(output_index_), &output);
    adapter->Release();
    if (FAILED(hr) || !output)
        return false;

    IDXGIOutput1* output1 = nullptr;
    hr = output->QueryInterface(__uuidof(IDXGIOutput1),
                                 reinterpret_cast<void**>(&output1));
    output->Release();
    if (FAILED(hr) || !output1)
        return false;

    hr = output1->DuplicateOutput(device_, &duplication_);
    output1->Release();
    if (FAILED(hr) || !duplication_)
        return false;

    DXGI_OUTDUPL_DESC dup_desc;
    duplication_->GetDesc(&dup_desc);

    D3D11_TEXTURE2D_DESC tex_desc = {};
    tex_desc.Width = dup_desc.ModeDesc.Width;
    tex_desc.Height = dup_desc.ModeDesc.Height;
    tex_desc.MipLevels = 1;
    tex_desc.ArraySize = 1;
    tex_desc.Format = dup_desc.ModeDesc.Format;
    tex_desc.SampleDesc.Count = 1;
    tex_desc.SampleDesc.Quality = 0;
    tex_desc.Usage = D3D11_USAGE_STAGING;
    tex_desc.BindFlags = 0;
    tex_desc.CPUAccessFlags = D3D11_CPU_ACCESS_READ;
    tex_desc.MiscFlags = 0;

    hr = device_->CreateTexture2D(&tex_desc, nullptr, &staging_texture_);
    if (FAILED(hr) || !staging_texture_) {
        duplication_->Release();
        duplication_ = nullptr;
        return false;
    }

    last_width_ = static_cast<int>(dup_desc.ModeDesc.Width);
    last_height_ = static_cast<int>(dup_desc.ModeDesc.Height);

    running_.store(true);
    capture_thread_ = std::thread(&DesktopDuplicator::capture_loop, this, fps,
                                   std::move(callback));
    return true;
}

void DesktopDuplicator::stop() {
    INDIRECT_BRANCH;
    running_.store(false);
    if (capture_thread_.joinable()) {
        capture_thread_.join();
    }
}

DIARNA_INLINE void DesktopDuplicator::capture_loop(int fps,
                                                    FrameCallback callback) {
    auto frame_duration = std::chrono::microseconds(1000000 / fps);
    auto next_frame = std::chrono::steady_clock::now();

    while (running_.load()) {
        auto now = std::chrono::steady_clock::now();
        if (now >= next_frame) {
            acquire_frame(callback);
            next_frame = std::chrono::steady_clock::now() + frame_duration;

            if (next_frame <= std::chrono::steady_clock::now()) {
                next_frame = std::chrono::steady_clock::now() + frame_duration;
            }
        } else {
            auto wait_time = std::chrono::duration_cast<std::chrono::milliseconds>(
                next_frame - now);
            if (wait_time > std::chrono::milliseconds(1)) {
                std::this_thread::sleep_for(wait_time);
            }
        }
    }
}

bool DesktopDuplicator::acquire_frame(const FrameCallback& callback) {
    INDIRECT_BRANCH;

    if (!duplication_ || !staging_texture_)
        return false;

    IDXGIResource* desktop_resource = nullptr;
    DXGI_OUTDUPL_FRAME_INFO frame_info = {};

    HRESULT hr = duplication_->AcquireNextFrame(0, &frame_info,
                                                  &desktop_resource);
    if (hr == DXGI_ERROR_ACCESS_LOST) {
        return false;
    }
    if (hr == DXGI_ERROR_WAIT_TIMEOUT) {
        return false;
    }
    if (FAILED(hr)) {
        return false;
    }
    if (!desktop_resource) {
        duplication_->ReleaseFrame();
        return false;
    }

    ID3D11Texture2D* desktop_texture = nullptr;
    hr = desktop_resource->QueryInterface(__uuidof(ID3D11Texture2D),
                                           reinterpret_cast<void**>(&desktop_texture));
    desktop_resource->Release();

    if (FAILED(hr) || !desktop_texture) {
        duplication_->ReleaseFrame();
        return false;
    }

    D3D11_TEXTURE2D_DESC tex_desc;
    desktop_texture->GetDesc(&tex_desc);

    if (static_cast<int>(tex_desc.Width) != last_width_ ||
        static_cast<int>(tex_desc.Height) != last_height_) {

        if (staging_texture_) {
            staging_texture_->Release();
            staging_texture_ = nullptr;
        }

        D3D11_TEXTURE2D_DESC new_staging = {};
        new_staging.Width = tex_desc.Width;
        new_staging.Height = tex_desc.Height;
        new_staging.MipLevels = 1;
        new_staging.ArraySize = 1;
        new_staging.Format = tex_desc.Format;
        new_staging.SampleDesc.Count = 1;
        new_staging.SampleDesc.Quality = 0;
        new_staging.Usage = D3D11_USAGE_STAGING;
        new_staging.BindFlags = 0;
        new_staging.CPUAccessFlags = D3D11_CPU_ACCESS_READ;
        new_staging.MiscFlags = 0;

        HRESULT create_hr = device_->CreateTexture2D(&new_staging, nullptr,
                                                       &staging_texture_);
        if (FAILED(create_hr) || !staging_texture_) {
            desktop_texture->Release();
            duplication_->ReleaseFrame();
            return false;
        }

        last_width_ = static_cast<int>(tex_desc.Width);
        last_height_ = static_cast<int>(tex_desc.Height);
    }

    context_->CopyResource(staging_texture_, desktop_texture);

    D3D11_MAPPED_SUBRESOURCE mapped = {};
    hr = context_->Map(staging_texture_, 0, D3D11_MAP_READ, 0, &mapped);

    if (SUCCEEDED(hr) && mapped.pData && callback) {
        callback(static_cast<const uint8_t*>(mapped.pData),
                 static_cast<int>(tex_desc.Width),
                 static_cast<int>(tex_desc.Height),
                 static_cast<int>(mapped.RowPitch));
        context_->Unmap(staging_texture_, 0);
    }

    desktop_texture->Release();
    duplication_->ReleaseFrame();
    return true;
}

bool DesktopDuplicator::acquire_frame_raw(std::vector<uint8_t>& out_bgra,
                                           int& width, int& height) {
    INDIRECT_BRANCH;

    if (!duplication_ || !staging_texture_)
        return false;

    IDXGIResource* desktop_resource = nullptr;
    DXGI_OUTDUPL_FRAME_INFO frame_info = {};

    HRESULT hr = duplication_->AcquireNextFrame(500, &frame_info,
                                                  &desktop_resource);
    if (hr == DXGI_ERROR_WAIT_TIMEOUT)
        return false;
    if (FAILED(hr))
        return false;
    if (!desktop_resource) {
        duplication_->ReleaseFrame();
        return false;
    }

    ID3D11Texture2D* desktop_texture = nullptr;
    hr = desktop_resource->QueryInterface(__uuidof(ID3D11Texture2D),
                                           reinterpret_cast<void**>(&desktop_texture));
    desktop_resource->Release();

    if (FAILED(hr) || !desktop_texture) {
        duplication_->ReleaseFrame();
        return false;
    }

    D3D11_TEXTURE2D_DESC tex_desc;
    desktop_texture->GetDesc(&tex_desc);

    if (static_cast<int>(tex_desc.Width) != last_width_ ||
        static_cast<int>(tex_desc.Height) != last_height_) {

        if (staging_texture_) {
            staging_texture_->Release();
            staging_texture_ = nullptr;
        }

        D3D11_TEXTURE2D_DESC new_staging = {};
        new_staging.Width = tex_desc.Width;
        new_staging.Height = tex_desc.Height;
        new_staging.MipLevels = 1;
        new_staging.ArraySize = 1;
        new_staging.Format = tex_desc.Format;
        new_staging.SampleDesc.Count = 1;
        new_staging.SampleDesc.Quality = 0;
        new_staging.Usage = D3D11_USAGE_STAGING;
        new_staging.BindFlags = 0;
        new_staging.CPUAccessFlags = D3D11_CPU_ACCESS_READ;
        new_staging.MiscFlags = 0;

        HRESULT create_hr = device_->CreateTexture2D(&new_staging, nullptr,
                                                       &staging_texture_);
        if (FAILED(create_hr) || !staging_texture_) {
            desktop_texture->Release();
            duplication_->ReleaseFrame();
            return false;
        }

        last_width_ = static_cast<int>(tex_desc.Width);
        last_height_ = static_cast<int>(tex_desc.Height);
    }

    context_->CopyResource(staging_texture_, desktop_texture);
    desktop_texture->Release();

    D3D11_MAPPED_SUBRESOURCE mapped = {};
    hr = context_->Map(staging_texture_, 0, D3D11_MAP_READ, 0, &mapped);

    if (SUCCEEDED(hr) && mapped.pData) {
        int row_pitch = static_cast<int>(mapped.RowPitch);
        int data_height = static_cast<int>(tex_desc.Height);
        size_t total_bytes = static_cast<size_t>(row_pitch) * data_height;

        out_bgra.resize(total_bytes);
        std::memcpy(out_bgra.data(), mapped.pData, total_bytes);

        width = static_cast<int>(tex_desc.Width);
        height = data_height;

        context_->Unmap(staging_texture_, 0);
        duplication_->ReleaseFrame();
        return true;
    }

    duplication_->ReleaseFrame();
    return false;
}

bool DesktopDuplicator::capture_single_frame(std::vector<uint8_t>& out_bgra,
                                              int& width, int& height) {
    INDIRECT_BRANCH;
    return acquire_frame_raw(out_bgra, width, height);
}

WebRTCStreamer::WebRTCStreamer() {
    INDIRECT_BRANCH;
}

WebRTCStreamer::~WebRTCStreamer() {
    INDIRECT_BRANCH;
    stop();
    if (gdiplus_token_ != 0) {
        Gdiplus::GdiplusShutdown(gdiplus_token_);
        gdiplus_token_ = 0;
    }
    if (winsock_initialized_) {
        if (socket_ != INVALID_SOCKET) {
            closesocket(socket_);
            socket_ = INVALID_SOCKET;
        }
        WSACleanup();
        winsock_initialized_ = false;
    }
}

bool WebRTCStreamer::initialize(const WebRTCConfig& config) {
    INDIRECT_BRANCH;

    config_ = config;

    WSADATA wsa_data = {};
    int wsa_ret = WSAStartup(MAKEWORD(2, 2), &wsa_data);
    if (wsa_ret != 0)
        return false;
    winsock_initialized_ = true;

    Gdiplus::GdiplusStartupInput si;
    si.GdiplusVersion = 1;
    si.DebugEventCallback = nullptr;
    si.SuppressBackgroundThread = FALSE;
    si.SuppressExternalCodecs = FALSE;
    Gdiplus::Status st = Gdiplus::GdiplusStartup(&gdiplus_token_, &si, nullptr);
    if (st != Gdiplus::Ok) {
        gdiplus_token_ = 0;
    }

    return true;
}

bool WebRTCStreamer::start() {
    INDIRECT_BRANCH;

    if (running_.load())
        return false;

    duplicator_ = std::make_unique<DesktopDuplicator>(0);
    if (!duplicator_)
        return false;

    running_.store(true);
    stream_thread_ = std::thread(&WebRTCStreamer::stream_loop, this);
    return true;
}

void WebRTCStreamer::stop() {
    INDIRECT_BRANCH;

    running_.store(false);

    if (duplicator_) {
        duplicator_->stop();
    }

    if (stream_thread_.joinable()) {
        stream_thread_.join();
    }

    duplicator_.reset();

    if (socket_ != INVALID_SOCKET) {
        closesocket(socket_);
        socket_ = INVALID_SOCKET;
    }
}

void WebRTCStreamer::send_frame(const uint8_t* data, size_t size) {
    INDIRECT_BRANCH;

    std::lock_guard<std::mutex> lock(frame_mutex_);
    if (frame_callback_ && data && size > 0) {
        frame_callback_(std::vector<uint8_t>(data, data + size));
    }
}

void WebRTCStreamer::set_frame_callback(FrameCallback callback) {
    INDIRECT_BRANCH;

    std::lock_guard<std::mutex> lock(frame_mutex_);
    frame_callback_ = std::move(callback);
}

DIARNA_INLINE std::vector<uint8_t> WebRTCStreamer::encode_bgra_to_jpeg(
    const uint8_t* bgra, int width, int height, int stride, int quality) {

    if (!bgra || width <= 0 || height <= 0)
        return {};

    Gdiplus::Bitmap bitmap(width, height, stride,
                             PixelFormat32bppARGB,
                             const_cast<BYTE*>(bgra));
    if (bitmap.GetLastStatus() != Gdiplus::Ok)
        return {};

    CLSID jpeg_clsid = {};
    {
        UINT num = 0, size = 0;
        Gdiplus::GetImageEncodersSize(&num, &size);
        if (size == 0) return {};

        std::vector<uint8_t> buf(size);
        auto* codecs = reinterpret_cast<Gdiplus::ImageCodecInfo*>(buf.data());
        Gdiplus::GetImageEncoders(num, size, codecs);

        for (UINT i = 0; i < num; ++i) {
            if (wcscmp(codecs[i].MimeType, L"image/jpeg") == 0) {
                jpeg_clsid = codecs[i].Clsid;
                break;
            }
        }
    }

    if (jpeg_clsid.Data1 == 0)
        return {};

    HGLOBAL hglobal = GlobalAlloc(GMEM_MOVEABLE, 0);
    if (!hglobal)
        return {};

    IStream* stream = nullptr;
    HRESULT hr = CreateStreamOnHGlobal(hglobal, TRUE, &stream);
    if (FAILED(hr) || !stream) {
        GlobalFree(hglobal);
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
        ULONG read = 0;
        stream->Read(result.data(), static_cast<ULONG>(result.size()), &read);
    }

    stream->Release();
    return result;
}

DIARNA_INLINE std::vector<uint8_t> WebRTCStreamer::resize_nearest(
    const uint8_t* bgra, int src_width, int src_height, int stride,
    int target_w, int target_h) {

    if (!bgra || src_width <= 0 || src_height <= 0 ||
        target_w <= 0 || target_h <= 0)
        return {};

    int out_stride = target_w * 4;
    std::vector<uint8_t> output(static_cast<size_t>(out_stride) * target_h);

    for (int y = 0; y < target_h; ++y) {
        int src_y = (y * src_height) / target_h;
        if (src_y >= src_height)
            src_y = src_height - 1;

        const uint8_t* src_row = bgra + static_cast<size_t>(src_y) * stride;
        uint8_t* dst_row = output.data() + static_cast<size_t>(y) * out_stride;

        for (int x = 0; x < target_w; ++x) {
            int src_x = (x * src_width) / target_w;
            if (src_x >= src_width)
                src_x = src_width - 1;

            const uint8_t* src_pixel = src_row + static_cast<size_t>(src_x) * 4;
            uint8_t* dst_pixel = dst_row + static_cast<size_t>(x) * 4;

            dst_pixel[0] = src_pixel[0];
            dst_pixel[1] = src_pixel[1];
            dst_pixel[2] = src_pixel[2];
            dst_pixel[3] = src_pixel[3];
        }
    }

    return output;
}

DIARNA_INLINE void WebRTCStreamer::stream_loop() {
    bool ok = duplicator_->start(config_.fps,
        [this](const uint8_t* bgra, int width, int height, int pitch) {
            if (!running_.load())
                return;

            int target_w = width;
            int target_h = height;
            const uint8_t* source_data = bgra;
            int source_pitch = pitch;

            std::vector<uint8_t> resized_buf;

            if (config_.resize_to_720p && height > 720) {
                target_h = 720;
                target_w = (width * 720) / height;
                if (target_w < 1) target_w = 1;

                resized_buf = resize_nearest(bgra, width, height, pitch,
                                              target_w, target_h);
                source_data = resized_buf.data();
                source_pitch = target_w * 4;
            }

            std::vector<uint8_t> jpeg_data = encode_bgra_to_jpeg(
                source_data, target_w, target_h, source_pitch,
                config_.quality);

            if (!jpeg_data.empty()) {
                std::lock_guard<std::mutex> lock(frame_mutex_);
                if (frame_callback_) {
                    frame_callback_(jpeg_data);
                }
            }
        });

    while (running_.load()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    duplicator_->stop();
}

} // namespace diarna::capture
