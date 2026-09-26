#pragma once

#ifndef RAKUTENAI_THREAD_HPP
#define RAKUTENAI_THREAD_HPP

#include "types.hpp"
#include "crypto.hpp"
#include "client.hpp"
#include <string>
#include <vector>
#include <functional>
#include <regex>

namespace rakutenai {

class Thread {
private:
    std::string thread_id_;
    User user_;
#ifdef _WIN32
    HINTERNET hSession_ = NULL;
    HINTERNET hConnect_ = NULL;
    HINTERNET hRequest_ = NULL;
    HINTERNET hWebSocket_ = NULL;
#endif

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

        std::vector<std::string> headers = {
            "Authorization: Bearer " + user.access_token,
            "X-Platform: WEB",
            "X-Country-Code: JP",
            "Device-ID: " + user.device_id,
            "X-Timestamp: " + sh.timestamp,
            "X-Nonce: " + sh.nonce,
            "X-Signature: " + sh.signature
        };

        std::string res = HttpClient::request(BASE_URL_HOST, endpoint, "GET", headers);
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

        std::vector<std::string> headers = {
            "Content-Type: application/json",
            "Authorization: Bearer " + user_.access_token,
            "X-Platform: WEB",
            "X-Country-Code: JP",
            "Device-ID: " + user_.device_id,
            "X-Timestamp: " + sh.timestamp,
            "X-Nonce: " + sh.nonce,
            "X-Signature: " + sh.signature
        };

        std::ostringstream body;
        body << "{\"threadId\":\"" << thread_id_ << "\",\"messageIds\":[";
        for (size_t i = 0; i < message_ids.size(); ++i) {
            if (i > 0) body << ",";
            body << "\"" << message_ids[i] << "\"";
        }
        body << "]}";

        std::string res = HttpClient::request(BASE_URL_HOST, endpoint, "POST", headers, body.str());
        return json_extract_string(res, "shareUrl");
    }

    bool connect() {
#ifdef _WIN32
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
#else
        return true;
#endif
    }

    void send_message(const std::vector<MessageContent>& contents, ChatMode mode, std::function<void(const StreamEvent&)> callback) {
#ifdef _WIN32
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
                        if (std::regex_search(msg, m, in_reg)) ev.input_tokens = std::stoull(m[1]);
                        if (std::regex_search(msg, m, out_reg)) ev.output_tokens = std::stoull(m[1]);
                        callback(ev);
                    }
                }
            }
        }
#else
        (void)contents; (void)mode; (void)callback;
#endif
    }

    void close() {
#ifdef _WIN32
        if (hWebSocket_) {
            WinHttpWebSocketClose(hWebSocket_, WINHTTP_WEB_SOCKET_SUCCESS_CLOSE_STATUS, NULL, 0);
            WinHttpCloseHandle(hWebSocket_);
            hWebSocket_ = NULL;
        }
        if (hRequest_) { WinHttpCloseHandle(hRequest_); hRequest_ = NULL; }
        if (hConnect_) { WinHttpCloseHandle(hConnect_); hConnect_ = NULL; }
        if (hSession_) { WinHttpCloseHandle(hSession_); hSession_ = NULL; }
#endif
    }
};

} // namespace rakutenai

#endif // RAKUTENAI_THREAD_HPP
