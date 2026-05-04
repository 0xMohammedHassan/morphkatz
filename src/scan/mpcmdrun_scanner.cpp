#include "morphkatz/scan/mpcmdrun_scanner.hpp"

#include "morphkatz/common/logging.hpp"
#include "morphkatz/scan/threat_classify.hpp"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <fstream>
#include <random>
#include <sstream>
#include <utility>

#if defined(_WIN32)
    #ifndef WIN32_LEAN_AND_MEAN
    #define WIN32_LEAN_AND_MEAN
    #endif
    #ifndef NOMINMAX
    #define NOMINMAX
    #endif
    #include <windows.h>
    #include <shlobj.h>
#endif

namespace morphkatz::scan {

namespace {

constexpr std::string_view kEngineLabel = "MpCmdRun-Tier1";

#if defined(_WIN32)

// Read an environment variable as a wide path. Returns empty path on
// missing/empty - callers fall through to the next probe.
std::filesystem::path env_path(const wchar_t* name) {
    wchar_t buf[MAX_PATH * 2] = {};
    DWORD n = ::GetEnvironmentVariableW(name, buf,
                                        static_cast<DWORD>(std::size(buf)));
    if (n == 0 || n >= std::size(buf)) return {};
    return std::filesystem::path(buf, buf + n);
}

// Resolve the latest Defender platform directory under
// %ProgramData%\Microsoft\Windows Defender\Platform\. Microsoft drops
// each engine update into a versioned subdirectory and we want the
// newest one (highest semver).
std::filesystem::path latest_platform_dir() {
    std::error_code ec;
    auto root = env_path(L"ProgramData");
    if (root.empty()) return {};
    root /= L"Microsoft";
    root /= L"Windows Defender";
    root /= L"Platform";
    if (!std::filesystem::exists(root, ec)) return {};

    std::filesystem::path best;
    for (auto& entry : std::filesystem::directory_iterator(root, ec)) {
        if (ec) break;
        if (!entry.is_directory(ec)) continue;
        const auto candidate = entry.path() / L"MpCmdRun.exe";
        if (!std::filesystem::exists(candidate, ec)) continue;
        // Lexicographic compare on path component is good enough for
        // semver-shaped Defender platform directories ("4.18.24080.4")
        // - the leading numeric components mean a string sort agrees
        // with the version sort across all observed Defender releases.
        if (best.empty() || entry.path().filename().wstring() >
                            best.parent_path().filename().wstring()) {
            best = candidate;
        }
    }
    return best;
}

std::filesystem::path probe_program_files_x86_or_64() {
    std::error_code ec;
    for (const wchar_t* var : {L"ProgramFiles", L"ProgramW6432",
                               L"ProgramFiles(x86)"}) {
        auto p = env_path(var);
        if (p.empty()) continue;
        p /= L"Windows Defender";
        p /= L"MpCmdRun.exe";
        if (std::filesystem::exists(p, ec)) return p;
    }
    return {};
}

std::filesystem::path search_path_for(const wchar_t* exe) {
    wchar_t buf[MAX_PATH * 2] = {};
    LPWSTR file_part = nullptr;
    DWORD n = ::SearchPathW(nullptr, exe, nullptr,
                            static_cast<DWORD>(std::size(buf)),
                            buf, &file_part);
    if (n == 0 || n >= std::size(buf)) return {};
    return std::filesystem::path(buf, buf + n);
}

#endif  // _WIN32

// Trim and lowercase first colon-segment of a key from a "Foo : value"
// MpCmdRun line. Used by parse_mpcmdrun_output.
std::pair<std::string, std::string> kv_split(std::string_view line) {
    auto colon = line.find(':');
    if (colon == std::string_view::npos) return {std::string(line), {}};
    auto key = line.substr(0, colon);
    auto val = line.substr(colon + 1);
    auto trim = [](std::string_view s) {
        size_t a = 0, b = s.size();
        while (a < b && std::isspace(static_cast<unsigned char>(s[a]))) ++a;
        while (b > a && std::isspace(static_cast<unsigned char>(s[b - 1]))) --b;
        return std::string(s.substr(a, b - a));
    };
    auto k = trim(key);
    std::transform(k.begin(), k.end(), k.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    return {std::move(k), trim(val)};
}

}  // namespace

std::optional<std::filesystem::path>
discover_mpcmdrun(const std::vector<std::filesystem::path>& extra_search_dirs) {
    std::error_code ec;
    for (const auto& dir : extra_search_dirs) {
#if defined(_WIN32)
        const auto candidate = dir / L"MpCmdRun.exe";
#else
        const auto candidate = dir / "MpCmdRun.exe";
#endif
        if (std::filesystem::exists(candidate, ec)) return candidate;
    }

#if defined(_WIN32)
    if (auto p = latest_platform_dir(); !p.empty()) return p;
    if (auto p = probe_program_files_x86_or_64(); !p.empty()) return p;
    if (auto p = search_path_for(L"MpCmdRun.exe"); !p.empty()) return p;
#endif
    return std::nullopt;
}

ScanVerdict parse_mpcmdrun_output(std::string raw_stdout, int exit_code) {
    ScanVerdict v;
    v.raw_stdout    = sanitize_scanner_output(raw_stdout);
    v.raw_exit_code = exit_code;

    std::string current_severity;
    std::istringstream is(v.raw_stdout);
    std::string line;
    while (std::getline(is, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        auto [k, value] = kv_split(line);
        if (k.empty()) continue;
        if (k == "threat") {
            if (!value.empty()) {
                Threat t;
                t.name   = value;
                t.is_ml  = false;
                t.is_pua = false;
                if (auto cls = classify(t); !cls.family.empty()) {
                    t.is_ml  = cls.is_ml;
                    t.is_pua = cls.is_pua;
                }
                v.threats.push_back(std::move(t));
            }
        } else if (k == "severity") {
            current_severity = value;
            if (!v.threats.empty() && v.threats.back().severity.empty()) {
                v.threats.back().severity = current_severity;
            }
        } else if (k == "engine version") {
            v.engine_version = value;
        } else if (k == "antivirus signature version") {
            v.vdm_version = value;
        }
    }
    v.infected = !v.threats.empty();
    // Defender uses exit code 2 when one or more threats are found; 0
    // when clean. Anything else is an environmental error and we leave
    // `infected` at whatever the parser inferred so callers can still
    // surface partial information.
    return v;
}

// --- MpCmdRunScanner::Impl ---------------------------------------------------

struct MpCmdRunScanner::Impl {
    Options opts;

    Impl() = default;

#if defined(_WIN32)

    // Spawn MpCmdRun.exe with a redirected stdout pipe and read until
    // process exit (or timeout). Returns the captured bytes and the
    // process exit code. On internal failure (CreateProcess, etc.) the
    // returned pair has the OS error message in stdout and a non-zero
    // exit code so the caller can propagate.
    std::pair<std::string, int> spawn_and_capture(
            const std::wstring& cmdline) {
        SECURITY_ATTRIBUTES sa{};
        sa.nLength = sizeof(sa);
        sa.bInheritHandle = TRUE;

        HANDLE rd = nullptr, wr = nullptr;
        if (!::CreatePipe(&rd, &wr, &sa, 0)) {
            return {"CreatePipe failed: " +
                    std::to_string(::GetLastError()), 1};
        }
        ::SetHandleInformation(rd, HANDLE_FLAG_INHERIT, 0);

        STARTUPINFOW si{};
        si.cb = sizeof(si);
        si.dwFlags    = STARTF_USESTDHANDLES;
        si.hStdOutput = wr;
        si.hStdError  = wr;
        si.hStdInput  = ::GetStdHandle(STD_INPUT_HANDLE);

        PROCESS_INFORMATION pi{};
        std::wstring mutable_cmdline = cmdline;  // CreateProcessW writes here
        BOOL ok = ::CreateProcessW(
            nullptr, mutable_cmdline.data(),
            nullptr, nullptr, TRUE,
            CREATE_NO_WINDOW,
            nullptr, nullptr, &si, &pi);
        ::CloseHandle(wr);

        if (!ok) {
            ::CloseHandle(rd);
            return {"CreateProcessW failed: " +
                    std::to_string(::GetLastError()), 1};
        }

        std::string out;
        char buf[4096];
        DWORD got = 0;
        while (::ReadFile(rd, buf, sizeof(buf), &got, nullptr) && got > 0) {
            out.append(buf, buf + got);
            // Bound the buffer so a runaway scanner can't OOM us.
            if (out.size() > 4 * 1024 * 1024) {
                out += "\n[truncated]\n";
                break;
            }
        }
        ::CloseHandle(rd);

        DWORD wait = ::WaitForSingleObject(pi.hProcess,
            static_cast<DWORD>(opts.timeout.count()));
        DWORD code = 1;
        if (wait == WAIT_TIMEOUT) {
            ::TerminateProcess(pi.hProcess, 1);
            out += "\n[scan timeout]\n";
        } else {
            ::GetExitCodeProcess(pi.hProcess, &code);
        }
        ::CloseHandle(pi.hProcess);
        ::CloseHandle(pi.hThread);
        return {std::move(out), static_cast<int>(code)};
    }

    std::wstring quote_arg(const std::filesystem::path& p) {
        auto s = p.wstring();
        std::wstring out;
        out.reserve(s.size() + 2);
        out.push_back(L'"');
        out.append(s);
        out.push_back(L'"');
        return out;
    }

    std::filesystem::path ensure_temp_dir() {
        std::error_code ec;
        auto dir = opts.temp_dir;
        if (dir.empty()) {
            dir = std::filesystem::temp_directory_path(ec) / "morphkatz-scan";
        }
        std::filesystem::create_directories(dir, ec);
        return dir;
    }

    // Materialise an in-memory buffer to a randomly-named file inside
    // the configured temp directory. The caller is expected to delete
    // it after the scan; this method does not own the file lifetime.
    Result<std::filesystem::path> write_temp(
            std::span<const uint8_t> bytes,
            std::string_view name_hint) {
        auto dir = ensure_temp_dir();
        std::error_code ec;
        if (!std::filesystem::exists(dir, ec)) {
            return Error::make(ErrorKind::Io,
                "scan temp_dir does not exist", dir.string());
        }

        std::random_device rd;
        std::mt19937_64 gen(rd());
        const auto stem = std::string(name_hint.empty() ? "buf" : name_hint);
        auto path = dir / (stem + "-" + std::to_string(gen()) + ".bin");

        std::ofstream f(path, std::ios::binary | std::ios::trunc);
        if (!f) {
            return Error::make(ErrorKind::Io,
                "cannot write scan temp file", path.string());
        }
        if (!bytes.empty()) {
            f.write(reinterpret_cast<const char*>(bytes.data()),
                    static_cast<std::streamsize>(bytes.size()));
        }
        f.close();
        return path;
    }
#endif  // _WIN32
};

// --- ctor / dtor ------------------------------------------------------------

MpCmdRunScanner::MpCmdRunScanner(std::unique_ptr<Impl> i)
    : impl_(std::move(i)) {}

MpCmdRunScanner::~MpCmdRunScanner() = default;
MpCmdRunScanner::MpCmdRunScanner(MpCmdRunScanner&&) noexcept = default;
MpCmdRunScanner& MpCmdRunScanner::operator=(MpCmdRunScanner&&) noexcept = default;

Result<std::unique_ptr<MpCmdRunScanner>>
MpCmdRunScanner::create(Options opts) {
    auto impl = std::make_unique<Impl>();
    impl->opts = std::move(opts);

    if (impl->opts.mpcmdrun_path.empty()) {
        auto found = discover_mpcmdrun();
        if (!found) {
            return Error::make(ErrorKind::NotSupported,
                "MpCmdRun.exe not found - Defender not installed or "
                "not on the PATH; pass --mpcmdrun <path> to override",
                "discovery");
        }
        impl->opts.mpcmdrun_path = *found;
    }

    if (impl->opts.enforce_preconditions) {
        auto state = query_state();
        auto check = validate(state, impl->opts.expectations);
        if (!check.ok()) return check.error();
    }

    return std::unique_ptr<MpCmdRunScanner>(
        new MpCmdRunScanner(std::move(impl)));
}

std::string MpCmdRunScanner::engine_label() const {
    return std::string(kEngineLabel);
}

Result<ScanVerdict>
MpCmdRunScanner::scan_file(const std::filesystem::path& path) {
#if defined(_WIN32)
    if (!impl_) {
        return Error::make(ErrorKind::Invalid, "scanner not initialised");
    }
    std::error_code ec;
    if (!std::filesystem::exists(path, ec)) {
        return Error::make(ErrorKind::Io,
            "scan input does not exist", path.string());
    }

    // MpCmdRun is spawned as a child process whose working directory may
    // differ from ours, so relative paths would resolve to the wrong file
    // (or to nothing). Canonicalize before passing.
    const auto abs_path = std::filesystem::absolute(path, ec);
    if (ec) {
        return Error::make(ErrorKind::Io,
            "failed to resolve absolute path: " + ec.message(), path.string());
    }

    // Build:  "<mpcmdrun>" -Scan -ScanType 3 -File "<path>" -DisableRemediation
    // -DisableRemediation prevents Defender from quarantining the file
    // mid-scan, which would otherwise break our subsequent reads.
    // We deliberately omit -Trace / -Level: those route output to a
    // separate log file and starve our stdout pipe.
    std::wstring cmd;
    cmd += impl_->quote_arg(impl_->opts.mpcmdrun_path);
    cmd += L" -Scan -ScanType 3 -File ";
    cmd += impl_->quote_arg(abs_path);
    cmd += L" -DisableRemediation";

    const auto t0 = std::chrono::steady_clock::now();
    auto [out, code] = impl_->spawn_and_capture(cmd);
    const auto t1 = std::chrono::steady_clock::now();

    auto v = parse_mpcmdrun_output(std::move(out), code);
    v.elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0);
    MK_DEBUG("MpCmdRun scan_file path={} infected={} threats={} elapsed={}ms",
             path.string(), v.infected, v.threats.size(), v.elapsed.count());
    return v;
#else
    (void)path;
    return Error::make(ErrorKind::NotSupported,
        "MpCmdRunScanner is Windows-only");
#endif
}

Result<ScanVerdict>
MpCmdRunScanner::scan_buffer(std::span<const uint8_t> bytes,
                             std::string_view name_hint) {
#if defined(_WIN32)
    if (!impl_) {
        return Error::make(ErrorKind::Invalid, "scanner not initialised");
    }
    auto path = impl_->write_temp(bytes, name_hint);
    if (!path.ok()) return path.error();

    auto v = scan_file(path.value());
    std::error_code ec;
    std::filesystem::remove(path.value(), ec);
    return v;
#else
    (void)bytes;
    (void)name_hint;
    return Error::make(ErrorKind::NotSupported,
        "MpCmdRunScanner is Windows-only");
#endif
}

}
