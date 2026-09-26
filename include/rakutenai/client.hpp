#pragma once

#ifndef RAKUTENAI_CLIENT_HPP
#define RAKUTENAI_CLIENT_HPP

#include "types.hpp"
#include "crypto.hpp"
#include <string>
#include <vector>
#include <sstream>

#ifdef _WIN32
#include <windows.h>
#include <winhttp.h>
#ifdef _MSC_VER
#pragma comment(lib, "winhttp.lib")
#endif
#else
#include <curl/curl.h>
#endif

namespace rakutenai {

class HttpClient {
public:
    static std::string request(const std::string& host, const std::string& path, const std::string& verb, const std::vector<std::string>& headers, const std::string& body = "") {
#ifdef _WIN32
        std::wstring whost(host.begin(), host.end());
        std::wstring wpath(path.begin(), path.end());
        std::wstring wverb(verb.begin(), verb.end());

        HINTERNET hSession = WinHttpOpen(L"RakutenAI-Cpp/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
        if (!hSession) return "";

        HINTERNET hConnect = WinHttpConnect(hSession, whost.c_str(), INTERNET_DEFAULT_HTTPS_PORT, 0);
        if (!hConnect) { WinHttpCloseHandle(hSession); return ""; }

        HINTERNET hRequest = WinHttpOpenRequest(hConnect, wverb.c_str(), wpath.c_str(), NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
        if (!hRequest) { WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); return ""; }

        std::wstring wheaders;
        for (const auto& h : headers) {
            wheaders += std::wstring(h.begin(), h.end()) + L"\r\n";
        }

        BOOL bResults = WinHttpSendRequest(hRequest, wheaders.c_str(), static_cast<DWORD>(wheaders.length()), body.empty() ? NULL : const_cast<char*>(body.data()), static_cast<DWORD>(body.length()), static_cast<DWORD>(body.length()), 0);
        if (bResults) bResults = WinHttpReceiveResponse(hRequest, NULL);

        std::string response;
        if (bResults) {
            DWORD dwSize = 0;
            DWORD dwDownloaded = 0;
            do {
                dwSize = 0;
                if (!WinHttpQueryDataAvailable(hRequest, &dwSize) || dwSize == 0) break;

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
#else
        std::string response;
        CURL* curl = curl_easy_init();
        if (curl) {
            std::string url = "https://" + host + path;
            curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
            curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, verb.c_str());

            struct curl_slist* chunk = NULL;
            for (const auto& h : headers) {
                chunk = curl_slist_append(chunk, h.c_str());
            }
            curl_easy_setopt(curl, CURLOPT_HTTPHEADER, chunk);

            if (!body.empty()) {
                curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.c_str());
            }

            auto write_cb = [](void* contents, size_t size, size_t nmemb, void* userp) -> size_t {
                size_t total = size * nmemb;
                static_cast<std::string*>(userp)->append(static_cast<char*>(contents), total);
                return total;
            };
            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, +write_cb);
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

            curl_easy_perform(curl);
            curl_slist_free_all(chunk);
            curl_easy_cleanup(curl);
        }
        return response;
#endif
    }
};

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

        std::vector<std::string> headers = {
            "Content-Type: application/json",
            "X-Platform: WEB",
            "X-Country-Code: JP",
            "Device-ID: " + u.device_id,
            "X-Timestamp: " + sh.timestamp,
            "X-Nonce: " + sh.nonce,
            "X-Signature: " + sh.signature
        };

        std::string res = HttpClient::request(BASE_URL_HOST, endpoint, "GET", headers);
        u.access_token = json_extract_string(res, "accessToken");
        u.refresh_token = json_extract_string(res, "refreshToken");

        return u;
    }

    std::string create_thread(const CreateThreadOptions& opts = CreateThreadOptions()) {
        std::string endpoint = "/api/v1/thread";
        SignedHeaders sh = get_signed_headers("POST", endpoint);

        std::vector<std::string> headers = {
            "Content-Type: application/json",
            "Authorization: Bearer " + access_token,
            "X-Platform: WEB",
            "X-Country-Code: JP",
            "Device-ID: " + device_id,
            "X-Timestamp: " + sh.timestamp,
            "X-Nonce: " + sh.nonce,
            "X-Signature: " + sh.signature
        };

        std::ostringstream body;
        body << "{\"scenarioAgentId\":\"" << opts.scenario_agent_id << "\",\"title\":\"" << json_escape(opts.title) << "\"";
        if (!opts.shareable_link_id.empty()) {
            body << ",\"shareableLinkId\":\"" << opts.shareable_link_id << "\",\"multipleThreadMode\":true";
        }
        body << "}";

        std::string res = HttpClient::request(BASE_URL_HOST, endpoint, "POST", headers, body.str());
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

        std::vector<std::string> headers = {
            "Content-Type: multipart/form-data; boundary=" + boundary,
            "Authorization: Bearer " + access_token,
            "X-Platform: WEB",
            "X-Country-Code: JP",
            "Device-ID: " + device_id,
            "X-Timestamp: " + sh.timestamp,
            "X-Nonce: " + sh.nonce,
            "X-Signature: " + sh.signature
        };

        std::string body_s(full_body.begin(), full_body.end());
        std::string res = HttpClient::request(BASE_URL_HOST, endpoint, "POST", headers, body_s);

        UploadedFile uf;
        uf.file_id = json_extract_string(res, "fileId");
        uf.file_url = json_extract_string(res, "fileUrl");
        uf.file_name = json_extract_string(res, "originalFilename");
        uf.is_image = is_image;
        return uf;
    }
};

} // namespace rakutenai

#endif // RAKUTENAI_CLIENT_HPP
