#include "eventLogCollector.h"

#include <windows.h>
#include <winevt.h>

#include <iostream>
#include <mutex>
#include <string>
#include <vector>

#pragma comment(lib, "wevtapi.lib")

namespace {

std::string wideToUtf8(const std::wstring& value) {
    if (value.empty()) {
        return "";
    }

    int size = WideCharToMultiByte(CP_UTF8, 0, value.data(),
                                   static_cast<int>(value.size()), nullptr, 0,
                                   nullptr, nullptr);

    if (size <= 0) {
        return "";
    }

    std::string result(size, '\0');

    WideCharToMultiByte(CP_UTF8, 0, value.data(),
                        static_cast<int>(value.size()), result.data(), size,
                        nullptr, nullptr);

    return result;
}

std::wstring renderEvent(EVT_HANDLE event) {
    DWORD bufferSize = 0;
    DWORD bufferUsed = 0;
    DWORD propertyCount = 0;

    EvtRender(nullptr, event, EvtRenderEventXml, 0, nullptr, &bufferSize,
              &propertyCount);

    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        return L"";
    }

    std::vector<wchar_t> buffer(bufferSize);

    if (!EvtRender(nullptr, event, EvtRenderEventXml, bufferSize, buffer.data(),
                   &bufferUsed, &propertyCount)) {
        return L"";
    }

    return std::wstring(buffer.data());
}

std::wstring extractValue(const std::wstring& xml, const std::wstring& tag) {
    std::wstring openTag = L"<" + tag + L">";

    std::wstring closeTag = L"</" + tag + L">";

    size_t start = xml.find(openTag);

    if (start == std::wstring::npos) {
        return L"";
    }

    start += openTag.size();

    size_t end = xml.find(closeTag, start);

    if (end == std::wstring::npos) {
        return L"";
    }

    return xml.substr(start, end - start);
}

std::string extractAttribute(const std::wstring& xml,
                             const std::wstring& attribute) {
    std::wstring single = attribute + L"='";

    size_t start = xml.find(single);

    if (start != std::wstring::npos) {
        start += single.size();

        size_t end = xml.find(L"'", start);

        if (end != std::wstring::npos) {
            return wideToUtf8(xml.substr(start, end - start));
        }
    }

    std::wstring doubleQuote = attribute + L"=\"";

    start = xml.find(doubleQuote);

    if (start != std::wstring::npos) {
        start += doubleQuote.size();

        size_t end = xml.find(L"\"", start);

        if (end != std::wstring::npos) {
            return wideToUtf8(xml.substr(start, end - start));
        }
    }

    return "";
}

std::string extractTimestamp(const std::wstring& xml) {
    const std::wstring singlePrefix = L"SystemTime='";

    size_t start = xml.find(singlePrefix);

    if (start != std::wstring::npos) {
        start += singlePrefix.size();

        size_t end = xml.find(L"'", start);

        if (end != std::wstring::npos) {
            return wideToUtf8(xml.substr(start, end - start));
        }
    }

    const std::wstring doublePrefix = L"SystemTime=\"";

    start = xml.find(doublePrefix);

    if (start != std::wstring::npos) {
        start += doublePrefix.size();

        size_t end = xml.find(L"\"", start);

        if (end != std::wstring::npos) {
            return wideToUtf8(xml.substr(start, end - start));
        }
    }

    return "";
}

}  // namespace

std::vector<Evidence> EventLogCollector::collect() {
    evidence_.clear();

    std::cout << "[EventLog] Collecting historical "
                 "Windows events...\n";

    collectChannel(L"System");
    collectChannel(L"Application");
    collectChannel(L"Security");

    std::cout << "[EventLog] Collection complete. "
                 "Events: "
              << evidence_.size() << '\n';

    return evidence_;
}

void EventLogCollector::collectChannel(const wchar_t* channel) {
    std::wcout << L"[EventLog] Reading " << channel << L"...\n";

    std::wstring query;

    if (std::wstring(channel) == L"Security") {
        query =
            L"*[System["
            L"(EventID != 4688) and "
            L"(EventID != 5156)"
            L"]]";
    } else {
        query = L"*";
    }

    EVT_HANDLE queryHandle =
        EvtQuery(nullptr, channel, query.c_str(), EvtQueryChannelPath);

    if (!queryHandle) {
        std::cerr << "[EventLog] EvtQuery failed for " << wideToUtf8(channel)
                  << ": " << GetLastError() << '\n';

        return;
    }

    while (true) {
        EVT_HANDLE events[16];

        DWORD returned = 0;

        BOOL result = EvtNext(queryHandle, 16, events, INFINITE, 0, &returned);

        if (!result) {
            DWORD error = GetLastError();

            if (error == ERROR_NO_MORE_ITEMS) {
                break;
            }

            std::cerr << "[EventLog] EvtNext failed for " << wideToUtf8(channel)
                      << ": " << error << '\n';

            break;
        }

        for (DWORD i = 0; i < returned; ++i) {
            handleEvent(events[i]);

            EvtClose(events[i]);
        }
    }

    EvtClose(queryHandle);

    std::wcout << L"[EventLog] " << channel << L" complete.\n";
}

void EventLogCollector::handleEvent(void* eventHandle) {
    EVT_HANDLE event = static_cast<EVT_HANDLE>(eventHandle);

    std::wstring xml = renderEvent(event);

    if (xml.empty()) {
        return;
    }

    std::string provider = extractAttribute(xml, L"Name");

    std::string computer = wideToUtf8(extractValue(xml, L"Computer"));

    std::string channel = extractAttribute(xml, L"Channel");

    std::wstring eventIdValue = extractValue(xml, L"EventID");

    if (eventIdValue.empty()) {
        return;
    }

    uint32_t eventId = 0;

    try {
        eventId = static_cast<uint32_t>(std::stoul(eventIdValue));
    } catch (...) {
        return;
    }

    EventLogEvidence data;

    data.channel = channel;

    data.eventId = eventId;

    data.provider = provider;

    data.computer = computer;

    Evidence evidence;

    evidence.id = "eventlog-" + std::to_string(evidence_.size());

    evidence.type = EvidenceType::EventLog;

    evidence.source = channel.empty() ? "Windows Event Log" : channel;

    evidence.timestamp = extractTimestamp(xml);

    evidence.description = "Windows event " + std::to_string(eventId);

    evidence.data = data;

    evidence.raw = wideToUtf8(xml);

    evidence_.push_back(std::move(evidence));
}