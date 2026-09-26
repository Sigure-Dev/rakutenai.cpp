#pragma once

#ifndef RAKUTENAI_TYPES_HPP
#define RAKUTENAI_TYPES_HPP

#include <string>
#include <vector>
#include <cstdint>

namespace rakutenai {

const std::string BASE_URL_HOST = "ai.rakuten.co.jp";
const std::string WS_BASE_URL_HOST = "companion.ai.rakuten.co.jp";
const std::string SECRET_KEY = "4f0465bfea7761a510dda451ff86a935bf0c8ed6fb37f80441509c64328788c8";
const std::string DEFAULT_AGENT_ID = "6812e64f9dfaf301f7000001";

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
    uint64_t input_tokens = 0;
    uint64_t output_tokens = 0;
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

} // namespace rakutenai

#endif // RAKUTENAI_TYPES_HPP
