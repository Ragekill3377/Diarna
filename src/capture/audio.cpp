#include <diarna/compiler_port.hpp>
#include <diarna/capture/capture.hpp>

#ifndef _WIN32
#error "Diarna Audio capture requires Windows"
#endif

#include <mmdeviceapi.h>
#include <audioclient.h>
#include <functiondiscoverykeys_devpkey.h>
#include <propvarutil.h>
#include <mmreg.h>

#include <mutex>
#include <chrono>

#include <obfuscation/obfusheader.h>
DIARNA_LINK_LIB("ole32.lib")

#ifndef SPEAKER_FRONT_LEFT
#   define SPEAKER_FRONT_LEFT  0x1
#   define SPEAKER_FRONT_RIGHT 0x2
#   define SPEAKER_FRONT_CENTER 0x4
#endif

namespace diarna::capture {

struct Audio::Impl {
    IMMDeviceEnumerator* enumerator = nullptr;
    IMMDevice* device = nullptr;
    IAudioClient* audio_client = nullptr;
    IAudioCaptureClient* capture_client = nullptr;
    WAVEFORMATEX* mix_format = nullptr;

    std::thread capture_thread;
    std::atomic<bool> running{false};
    std::atomic<bool> stop_flag{false};

    AudioCallback callback;

    std::vector<uint8_t> wav_data;
    std::mutex data_mutex;

    uint32_t sample_rate = 44100;
    uint8_t  channels = 2;
    uint16_t bits_per_sample = 16;
    uint16_t block_align = 4;

    Impl() = default;

    void release_com() noexcept {
        if (capture_client) { capture_client->Release(); capture_client = nullptr; }
        if (audio_client)   { audio_client->Release();   audio_client   = nullptr; }
        if (device)         { device->Release();          device         = nullptr; }
        if (enumerator)     { enumerator->Release();      enumerator     = nullptr; }
        if (mix_format)     { CoTaskMemFree(mix_format);  mix_format     = nullptr; }
    }
};

Audio::Audio() : impl_(std::make_unique<Impl>()) {
    INDIRECT_BRANCH;
    CoInitializeEx(nullptr, COINIT_MULTITHREADED);
}

Audio::~Audio() {
    INDIRECT_BRANCH;
    stop_capture();
    CoUninitialize();
}

Audio::Audio(Audio&& other) noexcept : impl_(std::move(other.impl_)) {
    INDIRECT_BRANCH;
}

Audio& Audio::operator=(Audio&& other) noexcept {
    INDIRECT_BRANCH;
    if (this != &other) {
        stop_capture();
        impl_ = std::move(other.impl_);
    }
    return *this;
}

bool Audio::start_capture(uint32_t sample_rate,
                          uint8_t  channels,
                          AudioCallback callback) {
    INDIRECT_BRANCH;
    if (impl_->running.load()) return false;

    stop_capture();

    impl_->sample_rate = sample_rate;
    impl_->channels    = channels;
    impl_->callback    = std::move(callback);

    {
        std::lock_guard<std::mutex> lock(impl_->data_mutex);
        impl_->wav_data.clear();
    }

    HRESULT hr = CoCreateInstance(
        CLSID_MMDeviceEnumerator, nullptr, CLSCTX_ALL,
        IID_PPV_ARGS(&impl_->enumerator));
    if (FAILED(hr)) goto fail;

    hr = impl_->enumerator->GetDefaultAudioEndpoint(
        eCapture, eConsole, &impl_->device);
    if (FAILED(hr)) goto fail;

    hr = impl_->device->Activate(
        IID_IAudioClient, CLSCTX_ALL, nullptr,
        (void**)&impl_->audio_client);
    if (FAILED(hr)) goto fail;

    hr = impl_->audio_client->GetMixFormat(&impl_->mix_format);
    if (FAILED(hr)) goto fail;

    {
        WAVEFORMATEX* pwfx = impl_->mix_format;
        if (pwfx->wFormatTag == WAVE_FORMAT_EXTENSIBLE) {
            WAVEFORMATEXTENSIBLE* pwfxe = (WAVEFORMATEXTENSIBLE*)pwfx;
            pwfxe->Format.nSamplesPerSec = sample_rate;
            pwfxe->Format.nChannels      = channels;
            pwfxe->Format.nBlockAlign    =
                channels * pwfxe->Format.wBitsPerSample / 8;
            pwfxe->Format.nAvgBytesPerSec =
                pwfxe->Format.nSamplesPerSec * pwfxe->Format.nBlockAlign;
            pwfxe->Samples.wValidBitsPerSample =
                pwfxe->Format.wBitsPerSample;
            pwfxe->dwChannelMask =
                (channels == 1) ? SPEAKER_FRONT_CENTER :
                (channels == 2) ? (SPEAKER_FRONT_LEFT | SPEAKER_FRONT_RIGHT) :
                KSAUDIO_SPEAKER_STEREO;
            pwfxe->SubFormat = KSDATAFORMAT_SUBTYPE_PCM;
        } else {
            pwfx->nSamplesPerSec = sample_rate;
            pwfx->nChannels      = channels;
            pwfx->nBlockAlign    = channels * pwfx->wBitsPerSample / 8;
            pwfx->nAvgBytesPerSec = pwfx->nSamplesPerSec * pwfx->nBlockAlign;
        }
        impl_->bits_per_sample = impl_->mix_format->wBitsPerSample;
        impl_->block_align     = impl_->mix_format->nBlockAlign;
    }

    hr = impl_->audio_client->Initialize(
        AUDCLNT_SHAREMODE_SHARED,
        0,
        10000000,
        0,
        impl_->mix_format,
        nullptr);
    if (FAILED(hr)) goto fail;

    hr = impl_->audio_client->GetService(
        IID_PPV_ARGS(&impl_->capture_client));
    if (FAILED(hr)) goto fail;

    hr = impl_->audio_client->Start();
    if (FAILED(hr)) goto fail;

    impl_->stop_flag = false;
    impl_->running   = true;

    impl_->capture_thread = std::thread([this]() {
        INDIRECT_BRANCH;
        std::vector<uint8_t> local_buf;

        while (!impl_->stop_flag.load()) {
            UINT32 packet_size = 0;
            HRESULT hr2 = impl_->capture_client->GetNextPacketSize(
                &packet_size);
            if (FAILED(hr2)) break;

            if (packet_size == 0) {
                Sleep(5);
                continue;
            }

            while (packet_size > 0 && !impl_->stop_flag.load()) {
                BYTE*  data = nullptr;
                UINT32 frames = 0;
                DWORD  flags = 0;

                hr2 = impl_->capture_client->GetBuffer(
                    &data, &frames, &flags, nullptr, nullptr);
                if (FAILED(hr2)) break;

                if (data != nullptr && frames > 0 &&
                    !(flags & AUDCLNT_BUFFERFLAGS_SILENT)) {
                    UINT32 bytes = frames * impl_->block_align;
                    local_buf.insert(local_buf.end(), data, data + bytes);
                }

                impl_->capture_client->ReleaseBuffer(frames);

                hr2 = impl_->capture_client->GetNextPacketSize(
                    &packet_size);
                if (FAILED(hr2)) break;
            }

            if (!local_buf.empty()) {
                if (impl_->callback) {
                    impl_->callback(local_buf);
                }
                {
                    std::lock_guard<std::mutex> lock(impl_->data_mutex);
                    impl_->wav_data.insert(impl_->wav_data.end(),
                                           local_buf.begin(), local_buf.end());
                }
                local_buf.clear();
            }

            Sleep(5);
        }
    });

    return true;

fail:
    impl_->release_com();
    return false;
}

void Audio::stop_capture() {
    INDIRECT_BRANCH;
    if (!impl_->running.load()) return;

    impl_->stop_flag = true;

    if (impl_->capture_thread.joinable()) {
        impl_->capture_thread.join();
    }

    if (impl_->audio_client) {
        impl_->audio_client->Stop();
    }

    impl_->release_com();
    impl_->running = false;
}

bool Audio::is_capturing() const {
    INDIRECT_BRANCH;
    return impl_->running.load();
}

std::vector<uint8_t> Audio::capture_seconds(uint32_t seconds,
                                            uint32_t sample_rate,
                                            uint8_t  channels) {
    INDIRECT_BRANCH;
    if (!start_capture(sample_rate, channels, nullptr))
        return {};

    std::this_thread::sleep_for(std::chrono::seconds(seconds));
    stop_capture();

    std::vector<uint8_t> pcm;
    {
        std::lock_guard<std::mutex> lock(impl_->data_mutex);
        pcm = std::move(impl_->wav_data);
    }

    uint16_t bits_per_samp = impl_->bits_per_sample;
    uint16_t num_chans     = impl_->channels;
    uint32_t srate         = impl_->sample_rate;

    uint32_t data_size = static_cast<uint32_t>(pcm.size());
    uint32_t byte_rate = srate * num_chans * (bits_per_samp / 8);
    uint16_t blk_align = num_chans * (bits_per_samp / 8);

    std::vector<uint8_t> wav;
    wav.reserve(44 + data_size);

    auto wr8  = [&](uint8_t v) { wav.push_back(v); };
    auto wr16 = [&](uint16_t v) {
        wr8(static_cast<uint8_t>(v & 0xFF));
        wr8(static_cast<uint8_t>((v >> 8) & 0xFF));
    };
    auto wr32 = [&](uint32_t v) {
        wr16(static_cast<uint16_t>(v & 0xFFFF));
        wr16(static_cast<uint16_t>((v >> 16) & 0xFFFF));
    };

    wr8('R'); wr8('I'); wr8('F'); wr8('F');
    wr32(36 + data_size);
    wr8('W'); wr8('A'); wr8('V'); wr8('E');

    wr8('f'); wr8('m'); wr8('t'); wr8(' ');
    wr32(16);
    wr16(1);
    wr16(num_chans);
    wr32(srate);
    wr32(byte_rate);
    wr16(blk_align);
    wr16(bits_per_samp);

    wr8('d'); wr8('a'); wr8('t'); wr8('a');
    wr32(data_size);

    wav.insert(wav.end(), pcm.begin(), pcm.end());
    return wav;
}

std::vector<std::string> Audio::enumerate_devices() {
    INDIRECT_BRANCH;
    std::vector<std::string> result;

    HRESULT co_hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);

    IMMDeviceEnumerator* enumerator = nullptr;
    HRESULT hr = CoCreateInstance(
        CLSID_MMDeviceEnumerator, nullptr, CLSCTX_ALL,
        IID_PPV_ARGS(&enumerator));
    if (FAILED(hr) || !enumerator) {
        if (SUCCEEDED(co_hr)) CoUninitialize();
        return result;
    }

    IMMDeviceCollection* collection = nullptr;
    hr = enumerator->EnumAudioEndpoints(
        eCapture, DEVICE_STATE_ACTIVE, &collection);
    if (FAILED(hr) || !collection) {
        enumerator->Release();
        if (SUCCEEDED(co_hr)) CoUninitialize();
        return result;
    }

    UINT count = 0;
    hr = collection->GetCount(&count);
    if (SUCCEEDED(hr)) {
        for (UINT i = 0; i < count; ++i) {
            IMMDevice* dev = nullptr;
            hr = collection->Item(i, &dev);
            if (FAILED(hr) || !dev) continue;

            IPropertyStore* store = nullptr;
            hr = dev->OpenPropertyStore(STGM_READ, &store);
            if (SUCCEEDED(hr)) {
                PROPVARIANT var;
                PropVariantInit(&var);
                hr = store->GetValue(PKEY_Device_FriendlyName, &var);
                if (SUCCEEDED(hr) && var.vt == VT_LPWSTR && var.pwszVal) {
                    int len = WideCharToMultiByte(
                        CP_UTF8, 0, var.pwszVal, -1,
                        nullptr, 0, nullptr, nullptr);
                    if (len > 0) {
                        std::string name(len - 1, '\0');
                        WideCharToMultiByte(
                            CP_UTF8, 0, var.pwszVal, -1,
                            name.data(), len, nullptr, nullptr);
                        result.push_back(std::move(name));
                    }
                }
                PropVariantClear(&var);
                store->Release();
            }
            dev->Release();
        }
    }

    collection->Release();
    enumerator->Release();
    if (SUCCEEDED(co_hr)) CoUninitialize();
    return result;
}

} // namespace diarna::capture
