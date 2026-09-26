#pragma once

#ifndef RAKUTENAI_HPP
#define RAKUTENAI_HPP

#include <windows.h>
#include <winhttp.h>
#include <bcrypt.h>
#include <string>
#include <vector>
#include <map>
#include <sstream>
#include <functional>
#include <chrono>
#include <random>
#include <regex>

#ifdef _MSC_VER
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "bcrypt.lib")
#endif

namespace rakutenai {

const std::string BASE_URL_HOST = "ai.rakuten.co.jp";
const std::string WS_BASE_URL_HOST = "companion.ai.rakuten.co.jp";
const std::string SECRET_KEY = "4f0465bfea7761a510dda451ff86a935bf0c8ed6fb37f80441509c64328788c8";
const std::string DEFAULT_AGENT_ID = "6812e64f9dfaf301f7000001";

inline std::string base64url_encode(const unsigned char* data, size_t len) {
    static const char table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    std::string out;
    out.reserve(((len + 2) / 3) * 4);

    size_t i = 0;
    while (i < len) {
        size_t rem = len - i;
        unsigned int octet_a = data[i++];
        unsigned int octet_b = (rem > 1) ? data[i++] : 0;
        unsigned int octet_c = (rem > 2) ? data[i++] : 0;

        unsigned int triple = (octet_a << 16) | (octet_b << 8) | octet_c;

        out.push_back(table[(triple >> 18) & 0x3F]);
        out.push_back(table[(triple >> 12) & 0x3F]);
        if (rem > 1) out.push_back(table[(triple >> 6) & 0x3F]);
        if (rem > 2) out.push_back(table[triple & 0x3F]);
    }
    return out;
}

inline std::string generate_uuid_v4() {
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint64_t> dis;

    uint64_t part1 = dis(gen);
    uint64_t part2 = dis(gen);

    part1 = (part1 & 0xFFFFFFFFFFFF0FFFULL) | 0x0000000000004000ULL;
    part2 = (part2 & 0x3FFFFFFFFFFFFFFFULL) | 0x8000000000000000ULL;

    char buf[37];
    snprintf(buf, sizeof(buf), "%08x-%04x-%04x-%04x-%012llx",
        static_cast<uint32_t>(part1 >> 32),
        static_cast<uint16_t>(part1 >> 16),
        static_cast<uint16_t>(part1),
        static_cast<uint16_t>(part2 >> 48),
        static_cast<unsigned long long>(part2 & 0xFFFFFFFFFFFFULL));
    return std::string(buf);
}

inline std::string generate_device_id() {
    static const char alphanum[] = "0123456789abcdefghijklmnopqrstuvwxyz";
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int> dis(0, 35);

    std::string suffix;
    for (int i = 0; i < 6; ++i) {
        suffix.push_back(alphanum[dis(gen)]);
    }
    return generate_uuid_v4() + "-" + suffix;
}

inline std::string hmac_sha256(const std::string& message, const std::string& secret) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    std::vector<unsigned char> hash(32);

    NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if (status >= 0) {
        status = BCryptCreateHash(hAlg, &hHash, NULL, 0, reinterpret_cast<PBYTE>(const_cast<char*>(secret.data())), static_cast<ULONG>(secret.size()), 0);
        if (status >= 0) {
            status = BCryptHashData(hHash, reinterpret_cast<PBYTE>(const_cast<char*>(message.data())), static_cast<ULONG>(message.size()), 0);
            if (status >= 0) {
                BCryptFinishHash(hHash, hash.data(), static_cast<ULONG>(hash.size()), 0);
            }
            BCryptDestroyHash(hHash);
        }
        BCryptCloseAlgorithmProvider(hAlg, 0);
    }

    return base64url_encode(hash.data(), hash.size());
}

inline std::string json_extract_string(const std::string& json, const std::string& key) {
    std::string pattern = "\"" + key + "\":\"";
    size_t pos = json.find(pattern);
    if (pos == std::string::npos) return "";
    pos += pattern.length();
    size_t end = json.find("\"", pos);
    if (end == std::string::npos) return "";
    return json.substr(pos, end - pos);
}

inline std::string json_escape(const std::string& s) {
    std::ostringstream o;
    for (char c : s) {
        if (c == '"') o << "\\\"";
        else if (c == '\\') o << "\\\\";
        else if (c == '\b') o << "\\b";
        else if (c == '\f') o << "\\f";
        else if (c == '\n') o << "\\n";
        else if (c == '\r') o << "\\r";
        else if (c == '\t') o << "\\t";
        else o << c;
    }
    return o.str();
}

struct SignedHeaders {
    std::string timestamp;
    std::string nonce;
    std::string signature;
};

inline SignedHeaders get_signed_headers(const std::string& method, const std::string& url_path, const std::map<std::string, std::string>& params = {}) {
    auto now = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
    std::string timestamp = std::to_string(now);
    std::string nonce = generate_uuid_v4();

    std::string sorted_params;
    for (const auto& kv : params) {
        sorted_params += kv.first + "=" + kv.second;
    }

    std::string raw_string = method + url_path + sorted_params + timestamp + nonce;
    std::string signature = hmac_sha256(raw_string, SECRET_KEY);

    return {timestamp, nonce, signature};
}

inline std::string get_signed_ws_path(const std::string& path, const std::string& access_token) {
    auto now = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
    std::string timestamp = std::to_string(now);
    std::string nonce = generate_uuid_v4();

    size_t q_pos = path.find('?');
    std::string pathname = (q_pos != std::string::npos) ? path.substr(0, q_pos) : path;
    std::string querystr = (q_pos != std::string::npos) ? path.substr(q_pos + 1) : "";

    std::map<std::string, std::string> params;
    params["accessToken"] = access_token;
    params["platform"] = "WEB";

    if (!querystr.empty()) {
        std::stringstream ss(querystr);
        std::string item;
        while (std::getline(ss, item, '&')) {
            size_t eq = item.find('=');
            if (eq != std::string::npos) {
                std::string k = item.substr(0, eq);
                std::string v = item.substr(eq + 1);
                if (k.rfind("x-", 0) != 0 && k.rfind("X-", 0) != 0) {
                    params[k] = v;
                }
            }
        }
    }

    std::string sorted_params;
    for (const auto& kv : params) {
        sorted_params += kv.first + "=" + kv.second;
    }

    std::string raw_string = "GET" + pathname + sorted_params + timestamp + nonce;
    std::string signature = hmac_sha256(raw_string, SECRET_KEY);

    std::ostringstream full_url;
    full_url << pathname << "?";
    bool first = true;
    for (const auto& kv : params) {
        if (!first) full_url << "&";
        full_url << kv.first << "=" << kv.second;
        first = false;
    }
    full_url << "&x-timestamp=" << timestamp
             << "&x-nonce=" << nonce
             << "&x-signature=" << signature;

    return full_url.str();
}

class HttpClient {
public:
    static std::string request(const std::wstring& host, const std::wstring& path, const std::wstring& verb, const std::wstring& headers, const std::string& body = "") {
        HINTERNET hSession = WinHttpOpen(L"RakutenAI-Cpp/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
        if (!hSession) return "";

        HINTERNET hConnect = WinHttpConnect(hSession, host.c_str(), INTERNET_DEFAULT_HTTPS_PORT, 0);
        if (!hConnect) { WinHttpCloseHandle(hSession); return ""; }

        HINTERNET hRequest = WinHttpOpenRequest(hConnect, verb.c_str(), path.c_str(), NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
        if (!hRequest) { WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); return ""; }

        BOOL bResults = WinHttpSendRequest(hRequest, headers.c_str(), static_cast<DWORD>(headers.length()), body.empty() ? NULL : const_cast<char*>(body.data()), static_cast<DWORD>(body.length()), static_cast<DWORD>(body.length()), 0);
        if (bResults) bResults = WinHttpReceiveResponse(hRequest, NULL);

        std::string response;
        if (bResults) {
            DWORD dwSize = 0;
            DWORD dwDownloaded = 0;
            do {
                dwSize = 0;
                if (!WinHttpQueryDataAvailable(hRequest, &dwSize)) break;
                if (dwSize == 0) break;

                std::vector<char> buffer(dwSize + 1);
                if (WinHttpReadData(hRequest, buffer.data(), dwSize, &dwDownloaded)) {
                    response.append(buffer.data(), dwDownloaded);
                }
            } while (dwSize > 0);
        }

        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return response;
    }
};

enum class ChatMode {
    UserInput,
    DeepThink,
    AiRead
};

inline const char* mode_to_string(ChatMode mode) {
    switch (mode) {
        case ChatMode::UserInput: return "USER_INPUT";
        case ChatMode::DeepThink: return "DEEP_THINK";
        case ChatMode::AiRead: return "AI_READ";
    }
    return "USER_INPUT";
}

struct StreamEvent {
    enum Type {
        ACK,
        REASONING_START,
        REASONING_DELTA,
        TEXT_DELTA,
        IMAGE_THUMBNAIL,
        IMAGE,
        TOOL_CALL_DETAIL,
        TOOL_CALL,
        NOTIFICATION,
        USAGE,
        DONE,
        ERR,
        DISCONNECTED
    } type = ACK;
    std::string text;
    std::string url;
    int input_tokens = 0;
    int output_tokens = 0;
    std::string error_message;
};

struct UploadedFile {
    std::string file_id;
    std::string file_url;
    std::string file_name;
    bool is_image = false;
};

struct MessageContent {
    enum Type { TEXT, FILE } type = TEXT;
    std::string text;
    UploadedFile file;

    static MessageContent from_text(const std::string& t) {
        MessageContent c;
        c.type = TEXT;
        c.text = t;
        return c;
    }

    static MessageContent from_file(const UploadedFile& f) {
        MessageContent c;
        c.type = FILE;
        c.file = f;
        return c;
    }
};

struct CreateThreadOptions {
    std::string title = "新しいスレッド";
    std::string scenario_agent_id = DEFAULT_AGENT_ID;
    std::string shareable_link_id = "";
};

class Thread;

class User {
public:
    std::string device_id;
    std::string access_token;
    std::string refresh_token;

    static User create() {
        User u;
        u.device_id = generate_device_id();

        std::string endpoint = "/api/v2/auth/anonymous";
        SignedHeaders sh = get_signed_headers("GET", endpoint);

        std::wostringstream wh;
        wh << L"Content-Type: application/json\r\n"
           << L"X-Platform: WEB\r\n"
           << L"X-Country-Code: JP\r\n"
           << L"Device-ID: " << std::wstring(u.device_id.begin(), u.device_id.end()) << L"\r\n"
           << L"X-Timestamp: " << std::wstring(sh.timestamp.begin(), sh.timestamp.end()) << L"\r\n"
           << L"X-Nonce: " << std::wstring(sh.nonce.begin(), sh.nonce.end()) << L"\r\n"
           << L"X-Signature: " << std::wstring(sh.signature.begin(), sh.signature.end()) << L"\r\n";

        std::string res = HttpClient::request(L"ai.rakuten.co.jp", L"/api/v2/auth/anonymous", L"GET", wh.str());
        u.access_token = json_extract_string(res, "accessToken");
        u.refresh_token = json_extract_string(res, "refreshToken");

        return u;
    }

    std::string create_thread(const CreateThreadOptions& opts = CreateThreadOptions()) {
        std::string endpoint = "/api/v1/thread";
        SignedHeaders sh = get_signed_headers("POST", endpoint);

        std::wostringstream wh;
        wh << L"Content-Type: application/json\r\n"
           << L"Authorization: Bearer " << std::wstring(access_token.begin(), access_token.end()) << L"\r\n"
           << L"X-Platform: WEB\r\n"
           << L"X-Country-Code: JP\r\n"
           << L"Device-ID: " << std::wstring(device_id.begin(), device_id.end()) << L"\r\n"
           << L"X-Timestamp: " << std::wstring(sh.timestamp.begin(), sh.timestamp.end()) << L"\r\n"
           << L"X-Nonce: " << std::wstring(sh.nonce.begin(), sh.nonce.end()) << L"\r\n"
           << L"X-Signature: " << std::wstring(sh.signature.begin(), sh.signature.end()) << L"\r\n";

        std::ostringstream body;
        body << "{\"scenarioAgentId\":\"" << opts.scenario_agent_id << "\",\"title\":\"" << json_escape(opts.title) << "\"";
        if (!opts.shareable_link_id.empty()) {
            body << ",\"shareableLinkId\":\"" << opts.shareable_link_id << "\",\"multipleThreadMode\":true";
        }
        body << "}";

        std::string res = HttpClient::request(L"ai.rakuten.co.jp", L"/api/v1/thread", L"POST", wh.str(), body.str());
        return json_extract_string(res, "id");
    }

    UploadedFile upload_file(const std::vector<unsigned char>& file_data, const std::string& filename, const std::string& mime_type, bool is_image, const std::string& thread_id = "") {
        std::string endpoint = "/api/v1/files/upload";
        SignedHeaders sh = get_signed_headers("POST", endpoint);

        std::string boundary = "----WebKitFormBoundary" + generate_uuid_v4();

        std::ostringstream head_part;
        head_part << "--" << boundary << "\r\n"
                  << "Content-Disposition: form-data; name=\"file\"; filename=\"" << filename << "\"\r\n"
                  << "Content-Type: " << mime_type << "\r\n\r\n";
        std::string head_str = head_part.str();

        std::string act_thread_id = thread_id.empty() ? generate_uuid_v4() : thread_id;
        std::ostringstream json_part;
        json_part << "\r\n--" << boundary << "\r\n"
                  << "Content-Disposition: form-data; name=\"request\"; filename=\"blob\"\r\n"
                  << "Content-Type: application/json\r\n\r\n"
                  << "{\"type\":\"" << (is_image ? "VISION_DATA" : "USER_DATA") << "\",\"agentId\":\"" << DEFAULT_AGENT_ID << "\",\"threadId\":\"" << act_thread_id << "\"}\r\n"
                  << "--" << boundary << "--\r\n";
        std::string json_str = json_part.str();

        std::vector<char> full_body;
        full_body.insert(full_body.end(), head_str.begin(), head_str.end());
        full_body.insert(full_body.end(), file_data.begin(), file_data.end());
        full_body.insert(full_body.end(), json_str.begin(), json_str.end());

        std::wostringstream wh;
        wh << L"Content-Type: multipart/form-data; boundary=" << std::wstring(boundary.begin(), boundary.end()) << L"\r\n"
           << L"Authorization: Bearer " << std::wstring(access_token.begin(), access_token.end()) << L"\r\n"
           << L"X-Platform: WEB\r\n"
           << L"X-Country-Code: JP\r\n"
           << L"Device-ID: " << std::wstring(device_id.begin(), device_id.end()) << L"\r\n"
           << L"X-Timestamp: " << std::wstring(sh.timestamp.begin(), sh.timestamp.end()) << L"\r\n"
           << L"X-Nonce: " << std::wstring(sh.nonce.begin(), sh.nonce.end()) << L"\r\n"
           << L"X-Signature: " << std::wstring(sh.signature.begin(), sh.signature.end()) << L"\r\n";

        std::string body_s(full_body.begin(), full_body.end());
        std::string res = HttpClient::request(L"ai.rakuten.co.jp", L"/api/v1/files/upload", L"POST", wh.str(), body_s);

        UploadedFile uf;
        uf.file_id = json_extract_string(res, "fileId");
        uf.file_url = json_extract_string(res, "fileUrl");
        uf.file_name = json_extract_string(res, "originalFilename");
        uf.is_image = is_image;
        return uf;
    }
};

class Thread {
private:
    std::string thread_id_;
    User user_;
    HINTERNET hSession_ = NULL;
    HINTERNET hConnect_ = NULL;
    HINTERNET hRequest_ = NULL;
    HINTERNET hWebSocket_ = NULL;

public:
    Thread(const std::string& thread_id, const User& user)
        : thread_id_(thread_id), user_(user) {}

    ~Thread() {
        close();
    }

    const std::string& id() const { return thread_id_; }

    static Thread from_shared(const std::string& share_id, User& user) {
        std::string endpoint = "/api/v1/share/" + share_id;
        SignedHeaders sh = get_signed_headers("GET", endpoint);

        std::wostringstream wh;
        wh << L"Authorization: Bearer " << std::wstring(user.access_token.begin(), user.access_token.end()) << L"\r\n"
           << L"X-Platform: WEB\r\n"
           << L"X-Country-Code: JP\r\n"
           << L"Device-ID: " << std::wstring(user.device_id.begin(), user.device_id.end()) << L"\r\n"
           << L"X-Timestamp: " << std::wstring(sh.timestamp.begin(), sh.timestamp.end()) << L"\r\n"
           << L"X-Nonce: " << std::wstring(sh.nonce.begin(), sh.nonce.end()) << L"\r\n"
           << L"X-Signature: " << std::wstring(sh.signature.begin(), sh.signature.end()) << L"\r\n";

        std::wstring wendpoint(endpoint.begin(), endpoint.end());
        std::string res = HttpClient::request(L"ai.rakuten.co.jp", wendpoint, L"GET", wh.str());
        std::string title = json_extract_string(res, "title");
        std::string agent_id = json_extract_string(res, "scenarioAgentId");
        if (agent_id.empty()) agent_id = DEFAULT_AGENT_ID;

        CreateThreadOptions opts;
        opts.title = "Continue: " + title;
        opts.scenario_agent_id = agent_id;
        opts.shareable_link_id = share_id;

        std::string new_thread_id = user.create_thread(opts);
        Thread t(new_thread_id, user);
        t.connect();
        return t;
    }

    UploadedFile upload_file(const std::vector<unsigned char>& file_data, const std::string& filename, const std::string& mime_type, bool is_image) {
        return user_.upload_file(file_data, filename, mime_type, is_image, thread_id_);
    }

    std::string create_share(const std::vector<std::string>& message_ids) {
        std::string endpoint = "/api/v1/share/create";
        SignedHeaders sh = get_signed_headers("POST", endpoint);

        std::wostringstream wh;
        wh << L"Content-Type: application/json\r\n"
           << L"Authorization: Bearer " << std::wstring(user_.access_token.begin(), user_.access_token.end()) << L"\r\n"
           << L"X-Platform: WEB\r\n"
           << L"X-Country-Code: JP\r\n"
           << L"Device-ID: " << std::wstring(user_.device_id.begin(), user_.device_id.end()) << L"\r\n"
           << L"X-Timestamp: " << std::wstring(sh.timestamp.begin(), sh.timestamp.end()) << L"\r\n"
           << L"X-Nonce: " << std::wstring(sh.nonce.begin(), sh.nonce.end()) << L"\r\n"
           << L"X-Signature: " << std::wstring(sh.signature.begin(), sh.signature.end()) << L"\r\n";

        std::ostringstream body;
        body << "{\"threadId\":\"" << thread_id_ << "\",\"messageIds\":[";
        for (size_t i = 0; i < message_ids.size(); ++i) {
            if (i > 0) body << ",";
            body << "\"" << message_ids[i] << "\"";
        }
        body << "]}";

        std::string res = HttpClient::request(L"ai.rakuten.co.jp", L"/api/v1/share/create", L"POST", wh.str(), body.str());
        return json_extract_string(res, "shareUrl");
    }

    bool connect() {
        std::string raw_path = "/ws/v1/chat?deviceId=" + user_.device_id;
        std::string signed_path = get_signed_ws_path(raw_path, user_.access_token);
        std::wstring wpath(signed_path.begin(), signed_path.end());

        hSession_ = WinHttpOpen(L"RakutenAI-Cpp/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
        if (!hSession_) return false;

        hConnect_ = WinHttpConnect(hSession_, L"companion.ai.rakuten.co.jp", INTERNET_DEFAULT_HTTPS_PORT, 0);
        if (!hConnect_) return false;

        hRequest_ = WinHttpOpenRequest(hConnect_, L"GET", wpath.c_str(), NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
        if (!hRequest_) return false;

        if (!WinHttpSetOption(hRequest_, WINHTTP_OPTION_UPGRADE_TO_WEB_SOCKET, NULL, 0)) {
            return false;
        }

        if (!WinHttpSendRequest(hRequest_, WINHTTP_NO_ADDITIONAL_HEADERS, 0, NULL, 0, 0, 0)) {
            return false;
        }

        if (!WinHttpReceiveResponse(hRequest_, NULL)) {
            return false;
        }

        hWebSocket_ = WinHttpWebSocketCompleteUpgrade(hRequest_, 0);
        return (hWebSocket_ != NULL);
    }

    void send_message(const std::vector<MessageContent>& contents, ChatMode mode, std::function<void(const StreamEvent&)> callback) {
        if (!hWebSocket_) return;

        std::string user_msg_id = generate_uuid_v4();
        auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();

        std::ostringstream ss;
        ss << "{\"message\":{\"type\":\"CONVERSATION\",\"payload\":{\"action\":\"" << mode_to_string(mode)
           << "\",\"data\":{\"chatRequestType\":\"" << mode_to_string(mode)
           << "\",\"role\":\"user\",\"userId\":\"" << user_.device_id
           << "\",\"threadId\":\"" << thread_id_
           << "\",\"messageId\":\"" << user_msg_id
           << "\",\"language\":\"ja\",\"platform\":\"WEB\",\"timestamp\":" << now_ms
           << ",\"contents\":[";

        for (size_t i = 0; i < contents.size(); ++i) {
            if (i > 0) ss << ",";
            const auto& c = contents[i];
            if (c.type == MessageContent::TEXT) {
                ss << "{\"contentType\":\"TEXT\",\"textData\":{\"text\":\"" << json_escape(c.text) << "\"}}";
            } else {
                if (c.file.is_image) {
                    ss << "{\"contentType\":\"INPUT_IMAGE\",\"inputImageData\":{\"src\":\"" << c.file.file_url << "\",\"resourceId\":\"" << c.file.file_id << "\"}}";
                } else {
                    ss << "{\"contentType\":\"INPUT_FILE\",\"inputFileData\":{\"src\":\"" << c.file.file_url << "\",\"resourceId\":\"" << c.file.file_id << "\",\"name\":\"" << json_escape(c.file.file_name) << "\"}}";
                }
            }
        }

        ss << "],\"retry\":false,\"debug\":false,\"timezoneString\":\"Asia/Tokyo\",\"countryCode\":\"JP\",\"city\":\"Nerima\",\"explicitSearch\":\"AUTO\"}},"
           << "\"metadata\":{\"messageId\":\"" << user_msg_id << "\",\"timestamp\":" << now_ms << "}}}";

        std::string payload = ss.str();
        DWORD err = WinHttpWebSocketSend(hWebSocket_, WINHTTP_WEB_SOCKET_UTF8_MESSAGE_BUFFER_TYPE, reinterpret_cast<PVOID>(const_cast<char*>(payload.data())), static_cast<DWORD>(payload.length()));
        if (err != ERROR_SUCCESS) return;

        std::vector<char> buffer(65536);
        DWORD bytesRead = 0;
        WINHTTP_WEB_SOCKET_BUFFER_TYPE bufType;

        std::string message_accumulator;

        while (true) {
            err = WinHttpWebSocketReceive(hWebSocket_, buffer.data(), static_cast<DWORD>(buffer.size()), &bytesRead, &bufType);
            if (err != ERROR_SUCCESS) {
                StreamEvent ev;
                ev.type = StreamEvent::DISCONNECTED;
                callback(ev);
                break;
            }

            if (bufType == WINHTTP_WEB_SOCKET_CLOSE_BUFFER_TYPE) {
                StreamEvent ev;
                ev.type = StreamEvent::DISCONNECTED;
                callback(ev);
                break;
            }

            message_accumulator.append(buffer.data(), bytesRead);

            if (bufType == WINHTTP_WEB_SOCKET_UTF8_MESSAGE_BUFFER_TYPE) {
                std::string msg = message_accumulator;
                message_accumulator.clear();

                if (msg.find("\"type\":\"ACK\"") != std::string::npos) {
                    StreamEvent ev;
                    ev.type = StreamEvent::ACK;
                    callback(ev);
                } else if (msg.find("\"chatResponseStatus\":\"DONE\"") != std::string::npos) {
                    StreamEvent ev;
                    ev.type = StreamEvent::DONE;
                    callback(ev);
                    break;
                } else if (msg.find("\"action\":\"EVENT\"") != std::string::npos) {
                    if (msg.find("思考中...") != std::string::npos) {
                        StreamEvent ev;
                        ev.type = StreamEvent::REASONING_START;
                        callback(ev);
                    }
                } else if (msg.find("\"chatResponseStatus\":\"APPEND\"") != std::string::npos) {
                    size_t text_pos = msg.find("\"text\":\"");
                    if (text_pos != std::string::npos) {
                        text_pos += 8;
                        size_t end_pos = text_pos;
                        std::string unescaped;
                        while (end_pos < msg.size()) {
                            if (msg[end_pos] == '\\' && end_pos + 1 < msg.size()) {
                                char next_c = msg[end_pos + 1];
                                if (next_c == 'n') unescaped += '\n';
                                else if (next_c == 'r') unescaped += '\r';
                                else if (next_c == 't') unescaped += '\t';
                                else if (next_c == '"') unescaped += '"';
                                else if (next_c == '\\') unescaped += '\\';
                                else unescaped += next_c;
                                end_pos += 2;
                            } else if (msg[end_pos] == '"') {
                                break;
                            } else {
                                unescaped += msg[end_pos];
                                end_pos++;
                            }
                        }

                        StreamEvent ev;
                        if (msg.find("\"contentType\":\"SUMMARY_TEXT\"") != std::string::npos) {
                            ev.type = StreamEvent::REASONING_DELTA;
                        } else {
                            ev.type = StreamEvent::TEXT_DELTA;
                        }
                        ev.text = unescaped;
                        callback(ev);
                    }

                    if (msg.find("\"contentType\":\"OUTPUT_IMAGE\"") != std::string::npos) {
                        std::string thumb = json_extract_string(msg, "thumbnail");
                        if (!thumb.empty()) {
                            StreamEvent ev;
                            ev.type = StreamEvent::IMAGE_THUMBNAIL;
                            ev.url = thumb;
                            callback(ev);
                        }
                        std::string preview = json_extract_string(msg, "preview");
                        if (!preview.empty()) {
                            StreamEvent ev;
                            ev.type = StreamEvent::IMAGE;
                            ev.url = preview;
                            callback(ev);
                        }
                    }

                    if (msg.find("\"responseMetricsData\"") != std::string::npos) {
                        StreamEvent ev;
                        ev.type = StreamEvent::USAGE;
                        std::smatch m;
                        std::regex in_reg("\"inputTokens\":([0-9]+)");
                        std::regex out_reg("\"outputTokens\":([0-9]+)");
                        if (std::regex_search(msg, m, in_reg)) ev.input_tokens = std::stoi(m[1]);
                        if (std::regex_search(msg, m, out_reg)) ev.output_tokens = std::stoi(m[1]);
                        callback(ev);
                    }
                }
            }
        }
    }

    void close() {
        if (hWebSocket_) {
            WinHttpWebSocketClose(hWebSocket_, WINHTTP_WEB_SOCKET_SUCCESS_CLOSE_STATUS, NULL, 0);
            WinHttpCloseHandle(hWebSocket_);
            hWebSocket_ = NULL;
        }
        if (hRequest_) { WinHttpCloseHandle(hRequest_); hRequest_ = NULL; }
        if (hConnect_) { WinHttpCloseHandle(hConnect_); hConnect_ = NULL; }
        if (hSession_) { WinHttpCloseHandle(hSession_); hSession_ = NULL; }
    }
};

} // namespace rakutenai

#endif // RAKUTENAI_HPP
