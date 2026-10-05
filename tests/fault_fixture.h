// 测试专用：在测试自身安排的条件下稳定制造两类真实文件访问错误，
// 不依赖碰巧出现的磁盘故障，也不需要 root。
//
//  1. 文件确实存在却无法打开：AF_UNIX 套接字路径。套接字在文件系统中
//     有名字（不是缺失路径），但用 open(2)/fopen 以普通文件方式打开必然
//     失败（Linux 上为 ENXIO）。
//
//  2. 文件已成功打开、已经读到真实内容后，后续读取出错：伪终端从端。
//     采用“填满缓冲 + 非阻塞写重试”的内核级握手，从根本上避免用户态轮询竞态：
//       a) raw 模式下，先以非阻塞写把主端写到 EAGAIN（从端缓冲被填满，
//          此时读取方尚未启动）；
//       b) 启动读取方；
//       c) 保持非阻塞，再尝试写 kForcedBytes 个字节。对端不读时一直 EAGAIN；
//          对端每读走一段、腾出缓冲，下一次写才会成功——因此“在 EAGAIN 之后
//          又成功写满 kForcedBytes”由内核证明读取方已消费确定数量的真实字节；
//       d) 再等从端队列排空（此时读取确已发生，TIOCINQ 计数可信），随后
//          关闭全部写端与主端，使读取方阻塞中的下一次 read(2) 以 EIO 失败。
//     已读到的内容必须被文件计算丢弃，不能被当作正常 EOF 或部分成功。
//
//     之所以不用 TIOCINQ 单独做同步：在读取方第一次读取之前，对从端写端
//     查询 TIOCINQ 会谎报 0，用户态据此可能在一个字节都没被读到时就挂断；
//     上述写握手不依赖该计数来证明“已读到内容”。全程非阻塞写也保证：若
//     读取方根本不读文件（仅伪造一个带错误文字的返回值），注入会在超时后
//     干净判失败，而不会把测试挂死。
//
// 这些机制只在本仓库的回归测试中使用，不属于公开 API；仅在 Linux/glibc
// 风格系统上可用，在其他平台上报告为不支持（supported() 为假），测试据此
// 跳过，而不是把“无法触发”算作通过。

#pragma once

#include <cerrno>
#include <chrono>
#include <algorithm>
#include <cstring>
#include <fcntl.h>
#include <filesystem>
#include <string>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <termios.h>
#include <thread>
#include <unistd.h>
#include <utility>
#include <vector>

#include <pty.h>

namespace fault_fixture {

namespace fs = std::filesystem;

// 该平台是否支持两种故障机制。不支持时所有测试必须显式跳过并报告，
// 绝不能静默当作检查通过。
inline bool supported() {
#ifdef __linux__
    return true;
#else
    return false;
#endif
}

// 确定性字节序列（与其余测试使用的 pattern 相同构造），覆盖 0x00/0xff。
inline unsigned char pattern_byte(std::size_t i) {
    return static_cast<unsigned char>((i * 31 + 7) % 256);
}

// 阻塞写阶段强制读取方至少消费的字节数（“确实读到过内容”的下界证明）。
inline constexpr std::size_t kForcedBytes = 8192;
// 预置载荷上限：足以填满任何常见 tty 输入缓冲并仍留下 kForcedBytes 可写。
inline constexpr std::size_t kPayloadSize = 96 * 1024;

// ---- 故障一：存在但无法以普通文件方式打开 ---------------------------------

// 在 dir 下创建一个名为 name 的 AF_UNIX 套接字节点，返回其路径。
// 节点在文件系统中真实存在，但打开它做普通读必然失败。
struct UnopenableSocket {
    fs::path path;
    int fd = -1;
    bool ready = false;

    UnopenableSocket() = default;
    UnopenableSocket(const fs::path& dir, const std::string& name) {
        path = dir / name;
        fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
        if (fd < 0) return;
        sockaddr_un addr{};
        addr.sun_family = AF_UNIX;
        const std::string p = path.string();
        // 留一个字节给 sun_path 的结尾 NUL。
        if (p.size() >= sizeof(addr.sun_path)) {
            ::close(fd);
            fd = -1;
            return;
        }
        std::memcpy(addr.sun_path, p.data(), p.size());
        if (::bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
            ::close(fd);
            fd = -1;
            return;
        }
        // 确认节点确实在文件系统中，且它不是普通文件/目录/缺失路径。
        struct stat st{};
        if (::stat(path.c_str(), &st) != 0 || !S_ISSOCK(st.st_mode)) {
            ::close(fd);
            fd = -1;
            return;
        }
        ready = true;
    }

    UnopenableSocket(const UnopenableSocket&) = delete;
    UnopenableSocket& operator=(const UnopenableSocket&) = delete;

    ~UnopenableSocket() {
        if (fd >= 0) ::close(fd);
        if (ready) {
            std::error_code ec;
            fs::remove(path, ec);
        }
    }
};

// ---- 故障二：读到真实内容后读取失败 ---------------------------------------

// 伪终端从端故障文件。用法：
//
//   PartiallyReadablePty pty;
//   pty.start_then_fail_after_real_bytes([&](const std::string& p){
//       // 在独立线程内对路径 p 执行真正的被测读取；它会读到确定的一段
//       // 真实字节后阻塞，随后收到读取失败。
//   });
//   pty.delivered_bytes()  // 已被证明送达读取方的字节数（> kForcedBytes）
//
class PartiallyReadablePty {
public:
    PartiallyReadablePty() = default;
    PartiallyReadablePty(const PartiallyReadablePty&) = delete;
    PartiallyReadablePty& operator=(const PartiallyReadablePty&) = delete;

    ~PartiallyReadablePty() {
        if (master_ >= 0) ::close(master_);
        if (writer_ >= 0) ::close(writer_);
    }

    bool ready() const { return ready_; }
    const std::string& path() const { return name_; }
    // 挂断前已成功写入（因而已送达或在队列中等待被唯一的读取者取走）的
    // 字节数。结合 forced_consumed()，这是读取方已读到真实内容的证据。
    std::size_t delivered_bytes() const { return delivered_; }
    // 阻塞写阶段是否完整写入了 kForcedBytes：内核据此保证读取方至少消费了
    // 这么多字节。为假时“先读到内容”的前提不成立，测试必须判失败。
    bool forced_consumed() const { return forced_ == kForcedBytes; }

    template <class Fn>
    void start_then_fail_after_real_bytes(Fn&& reader) {
        std::string payload(kPayloadSize, '\0');
        for (std::size_t i = 0; i < payload.size(); ++i) {
            payload[i] = static_cast<char>(pattern_byte(i));
        }

        int master = -1;
        int slave = -1;
        if (openpty(&master, &slave, nullptr, nullptr, nullptr) != 0) return;
        master_ = master;

        // raw：关闭回显、规范模式、信号与一切加工，字节原样到达。
        termios tio{};
        if (tcgetattr(master_, &tio) != 0) { ::close(slave); return; }
        cfmakeraw(&tio);
        tio.c_cc[VMIN] = 1;
        tio.c_cc[VTIME] = 0;
        if (tcsetattr(slave, TCSANOW, &tio) != 0) { ::close(slave); return; }
        if (tcsetattr(master_, TCSANOW, &tio) != 0) { ::close(slave); return; }

        char buf[256];
        if (ttyname_r(slave, buf, sizeof(buf)) != 0) {
            ::close(slave);
            return;
        }
        name_ = buf;
        ::close(slave);  // 读取方按路径自行打开，与真实用法一致。

        // 持有一个从端写端，避免读取方首次 read 前提前挂断；也用于查询队列。
        writer_ = ::open(name_.c_str(), O_WRONLY | O_NOCTTY);
        if (writer_ < 0) return;

        // (a) 非阻塞写直到 EAGAIN：从端缓冲被填满，读取方尚未启动。
        const int flags = fcntl(master_, F_GETFL);
        if (flags < 0 || fcntl(master_, F_SETFL, flags | O_NONBLOCK) != 0) return;
        std::size_t off = 0;
        bool hit_eagain = false;
        while (off < payload.size()) {
            ssize_t w = ::write(master_, payload.data() + off,
                                payload.size() - off);
            if (w > 0) {
                off += static_cast<std::size_t>(w);
                continue;
            }
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                hit_eagain = true;
                break;
            }
            abort_run();
            return;
        }
        if (!hit_eagain) {
            // 缓冲未能被填满，无法用后续阻塞写证明消费发生；放弃本次注入。
            abort_run();
            return;
        }
        const std::size_t filled = off;

        // (b) 启动读取方。
        ready_ = true;
        std::thread worker([fn = std::forward<Fn>(reader), this]() mutable {
            fn(name_);
        });

        // (c) 主端保持非阻塞（缓冲此前已填满到 EAGAIN），再写入 kForcedBytes：
        // 对端不读时一直 EAGAIN；对端每读走一段腾出缓冲，下一次非阻塞写才
        // 成功。因此“在 EAGAIN 之后又成功写满 kForcedBytes”由内核证明读取方
        // 确实消费了这些字节。若对端不真正读文件（仅伪造一个带错误文字的
        // 结果），则始终 EAGAIN，超时后干净判失败而不阻塞。
        std::size_t forced = 0;
        const std::size_t want =
            std::min(kForcedBytes, payload.size() - filled);
        const auto give_up =
            std::chrono::steady_clock::now() + std::chrono::seconds(3);
        while (forced < want) {
            if (std::chrono::steady_clock::now() >= give_up) break;
            ssize_t w = ::write(master_, payload.data() + filled + forced,
                                want - forced);
            if (w > 0) {
                forced += static_cast<std::size_t>(w);
                continue;
            }
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
                continue;
            }
            break;
        }
        forced_ = forced;
        delivered_ = filled + forced;

        // 恢复主端标志后，无论成功与否都由下方统一关闭。
        fcntl(master_, F_SETFL, flags);

        if (forced != want) {
            // 挂断以解除任何真实阻塞的读取方，再回收线程；伪造读取方则早已
            // 返回，join 立即完成。
            ::close(writer_);
            writer_ = -1;
            ::close(master_);
            master_ = -1;
            worker.join();
            ready_ = false;
            return;
        }

        // (d) 此时读取确已发生，TIOCINQ 可信：等待残留队列排空，确保读取方
        // 已取走全部已送达字节并进入下一次阻塞读取。
        int queued = -1;
        bool drained = false;
        while (std::chrono::steady_clock::now() < give_up) {
            if (ioctl(writer_, TIOCINQ, &queued) == 0 && queued == 0) {
                drained = true;
                break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        if (!drained) {
            ::close(writer_);
            writer_ = -1;
            ::close(master_);
            master_ = -1;
            worker.join();
            ready_ = false;
            return;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(20));

        // 挂断：阻塞中的下一次 read(2) 以 EIO 失败。
        ::close(writer_);
        writer_ = -1;
        ::close(master_);
        master_ = -1;
        worker.join();
    }

private:
    void abort_run() {
        if (writer_ >= 0) {
            ::close(writer_);
            writer_ = -1;
        }
        if (master_ >= 0) {
            ::close(master_);
            master_ = -1;
        }
        ready_ = false;
    }

    int master_ = -1;
    int writer_ = -1;
    std::string name_;
    bool ready_ = false;
    std::size_t delivered_ = 0;
    std::size_t forced_ = 0;
};

}  // namespace fault_fixture
