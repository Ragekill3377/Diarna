#pragma once
#include <diarna/compiler_port.hpp>
#include <cstdint>
#include <vector>
#include <string>
#include <functional>
#include <atomic>
#include <thread>
#include <memory>
#include <chrono>
#include <span>

struct ID3D11Device;
struct ID3D11DeviceContext;
struct IDXGIOutputDuplication;
struct ID3D11Texture2D;

namespace diarna::capture {

struct MonitorInfo {
    int index;
    RECT rect;
    bool is_primary;
    std::wstring device_name;
};

class Screenshot {
public:
    Screenshot();
    ~Screenshot();

    Screenshot(const Screenshot&) = delete;
    Screenshot& operator=(const Screenshot&) = delete;

    std::vector<uint8_t> capture_jpeg(int quality = 80);
    std::vector<uint8_t> capture_png();
    std::vector<uint8_t> capture_bmp();
    std::vector<MonitorInfo> enumerate_monitors();

private:
    ULONG_PTR gdiplus_token_ = 0;
    static std::atomic<int> gdiplus_ref_count_;
    static std::mutex gdiplus_mutex_;

    void ensure_gdiplus();
    void release_gdiplus();
    int get_encoder_clsid(const wchar_t* mime_type, CLSID* clsid) const;
    std::vector<uint8_t> capture_encoded(const CLSID& encoder_clsid);
};

class DesktopDuplicator {
public:
    using FrameCallback = std::function<void(const uint8_t* bgra_data,
                                              int width, int height,
                                              int pitch)>;

    DesktopDuplicator(int output_index = 0);
    ~DesktopDuplicator();

    DesktopDuplicator(const DesktopDuplicator&) = delete;
    DesktopDuplicator& operator=(const DesktopDuplicator&) = delete;

    bool start(int fps, FrameCallback callback);
    void stop();
    bool capture_single_frame(std::vector<uint8_t>& out_bgra,
                               int& width, int& height);
    bool is_capturing() const { return running_.load(); }

private:
    void capture_loop(int fps, FrameCallback callback);
    bool acquire_frame(const FrameCallback& callback);
    bool acquire_frame_raw(std::vector<uint8_t>& out_bgra,
                            int& width, int& height);
    void cleanup();

    ID3D11Device* device_ = nullptr;
    ID3D11DeviceContext* context_ = nullptr;
    IDXGIOutputDuplication* duplication_ = nullptr;
    ID3D11Texture2D* staging_texture_ = nullptr;
    int output_index_;
    std::atomic<bool> running_{false};
    std::thread capture_thread_;
    int last_width_ = 0;
    int last_height_ = 0;
};

struct WebRTCConfig {
    std::string signaling_server;
    int quality = 80;
    int fps = 15;
    int bitrate_kbps = 500;
    bool resize_to_720p = true;
};

class WebRTCStreamer {
public:
    WebRTCStreamer();
    ~WebRTCStreamer();

    WebRTCStreamer(const WebRTCStreamer&) = delete;
    WebRTCStreamer& operator=(const WebRTCStreamer&) = delete;

    bool initialize(const WebRTCConfig& config);
    bool start();
    void stop();
    void send_frame(const uint8_t* data, size_t size);

    using FrameCallback = std::function<void(const std::vector<uint8_t>& jpeg_frame)>;
    void set_frame_callback(FrameCallback callback);
    bool is_streaming() const { return running_.load(); }

private:
    void stream_loop();
    std::vector<uint8_t> encode_bgra_to_jpeg(const uint8_t* bgra,
                                              int width, int height,
                                              int stride, int quality);
    std::vector<uint8_t> resize_nearest(const uint8_t* bgra,
                                         int src_width, int src_height,
                                         int stride,
                                         int target_w, int target_h);

    WebRTCConfig config_;
    FrameCallback frame_callback_;
    std::atomic<bool> running_{false};
    std::thread stream_thread_;
    std::unique_ptr<DesktopDuplicator> duplicator_;
    SOCKET socket_ = INVALID_SOCKET;
    bool winsock_initialized_ = false;
    ULONG_PTR gdiplus_token_ = 0;
    std::mutex frame_mutex_;
};

class Audio {
public:
    using AudioCallback = std::function<void(std::span<const uint8_t> wav_data)>;

    Audio();
    ~Audio();

    Audio(const Audio&) = delete;
    Audio& operator=(const Audio&) = delete;

    Audio(Audio&&) noexcept;
    Audio& operator=(Audio&&) noexcept;

    bool start_capture(uint32_t sample_rate = 44100,
                       uint8_t channels = 2,
                       AudioCallback callback = nullptr);
    void stop_capture();
    bool is_capturing() const;

    std::vector<uint8_t> capture_seconds(uint32_t seconds,
                                         uint32_t sample_rate = 44100,
                                         uint8_t channels = 2);

    static std::vector<std::string> enumerate_devices();

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

class Webcam {
public:
    struct DeviceInfo {
        uint32_t index;
        std::string name;
        std::vector<std::pair<uint32_t, uint32_t>> supported_resolutions;
    };

    Webcam();
    ~Webcam();

    Webcam(const Webcam&) = delete;
    Webcam& operator=(const Webcam&) = delete;

    Webcam(Webcam&&) noexcept;
    Webcam& operator=(Webcam&&) noexcept;

    bool open(uint32_t device_index = 0,
              uint32_t width = 640,
              uint32_t height = 480);
    void close();
    bool is_open() const;

    std::vector<uint8_t> capture_frame_jpeg(uint32_t quality = 85);
    std::vector<uint8_t> capture_frame_png();
    std::vector<uint8_t> capture_frame_bmp();

    static std::vector<std::string> enumerate_devices();
    static std::vector<DeviceInfo> enumerate_devices_info();

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace diarna::capture
