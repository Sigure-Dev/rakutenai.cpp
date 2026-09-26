#pragma once

#ifndef RAKUTENAI_CRYPTO_HPP
#define RAKUTENAI_CRYPTO_HPP

#include "types.hpp"
#include <string>
#include <vector>
#include <map>
#include <chrono>
#include <sstream>

#ifdef _WIN32
#include <windows.h>
#include <bcrypt.h>
#ifdef _MSC_VER
#pragma comment(lib, "bcrypt.lib")
#endif
#else
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#endif

namespace rakutenai {

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
    unsigned char b[16];
#ifdef _WIN32
    BCryptGenRandom(NULL, b, 16, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
#else
    RAND_bytes(b, 16);
#endif
    b[6] = (b[6] & 0x0F) | 0x40; // v4
    b[8] = (b[8] & 0x3F) | 0x80; // variant

    char buf[37];
    snprintf(buf, sizeof(buf), "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]);
    return std::string(buf);
}

inline std::string generate_device_id() {
    static const char alphanum[] = "0123456789abcdefghijklmnopqrstuvwxyz";
    unsigned char rnd[6];
#ifdef _WIN32
    BCryptGenRandom(NULL, rnd, 6, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
#else
    RAND_bytes(rnd, 6);
#endif
    std::string suffix;
    for (int i = 0; i < 6; ++i) {
        suffix.push_back(alphanum[rnd[i] % 36]);
    }
    return generate_uuid_v4() + "-" + suffix;
}

inline std::string hmac_sha256(const std::string& message, const std::string& secret) {
    std::vector<unsigned char> hash(32);
#ifdef _WIN32
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
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
#else
    unsigned int len = 32;
    HMAC(EVP_sha256(), secret.data(), secret.size(), reinterpret_cast<const unsigned char*>(message.data()), message.size(), hash.data(), &len);
#endif
    return base64url_encode(hash.data(), hash.size());
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

} // namespace rakutenai

#endif // RAKUTENAI_CRYPTO_HPP
