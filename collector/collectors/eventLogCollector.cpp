#include "eventLogCollector.h"

#include <windows.h>
#include <winevt.h>

#include <iostream>
#include <string>
#include <vector>

#pragma comment(lib, "wevtapi.lib")

namespace {

std::wstring getXmlValue(const std::wstring& xml, const std::wstring& element) {
    std::wstring open = L"<" + element + L">";

    std::wstring close = L"</" + element + L">";

    size_t start = xml.find(open);

    if (start == std::wstring::npos) {
        return L"";
    }

    start += open.length();

    size_t end = xml.find(close, start);

    if (end == std::wstring::npos) {
        return L"";
    }

    return xml.substr(start, end - start);
}

std::wstring getAttribute(const std::wstring& xml, const std::wstring& element,
                          const std::wstring& attribute) {
    std::wstring elementStart = L"<" + element;

    size_t start = xml.find(elementStart);

    if (start == std::wstring::npos) {
        return L"";
    }

    size_t end = xml.find(L">", start);

    if (end == std::wstring::npos) {
        return L"";
    }

    std::wstring section = xml.substr(start, end - start);

    std::wstring search = attribute + L"='";

    size_t attributeStart = section.find(search);

    if (attributeStart == std::wstring::npos) {
        search = attribute + L"=\"";

        attributeStart = section.find(search);

        if (attributeStart == std::wstring::npos) {
            return L"";
        }

        attributeStart += search.length();

        size_t attributeEnd = section.find(L"\"", attributeStart);

        if (attributeEnd == std::wstring::npos) {
            return L"";
        }

        return section.substr(attributeStart, attributeEnd - attributeStart);
    }

    attributeStart += search.length();

    size_t attributeEnd = section.find(L"'", attributeStart);

    if (attributeEnd == std::wstring::npos) {
        return L"";
    }

    return section.substr(attributeStart, attributeEnd - attributeStart);
}

std::string toUtf8(const std::wstring& value) {
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

std::string extractTimestamp(const std::wstring& xml) {
    return toUtf8(getAttribute(xml, L"TimeCreated", L"SystemTime"));
}

}  // namespace

std::vector<Evidence> EventLogCollector::collect() {
    std::vector<Evidence> evidence;

    const wchar_t* channel = L"System";

    EVT_HANDLE query = EvtQuery(nullptr, channel, L"*",
                                EvtQueryChannelPath | EvtQueryForwardDirection);

    if (!query) {
        std::cerr << "EvtQuery failed: " << GetLastError() << '\n';

        return evidence;
    }

    EVT_HANDLE events[16]{};

    DWORD returned = 0;

    while (EvtNext(query, 16, events, INFINITE, 0, &returned)) {
        for (DWORD i = 0; i < returned; ++i) {
            DWORD bufferUsed = 0;
            DWORD propertyCount = 0;

            EvtRender(nullptr, events[i], EvtRenderEventXml, 0, nullptr,
                      &bufferUsed, &propertyCount);

            if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
                EvtClose(events[i]);
                continue;
            }

            std::vector<wchar_t> buffer(bufferUsed / sizeof(wchar_t) + 1);

            if (!EvtRender(nullptr, events[i], EvtRenderEventXml, bufferUsed,
                           buffer.data(), &bufferUsed, &propertyCount)) {
                EvtClose(events[i]);
                continue;
            }

            std::wstring xml(buffer.data());

            std::string timestamp = extractTimestamp(xml);

            std::string provider =
                toUtf8(getAttribute(xml, L"Provider", L"Name"));

            std::string eventIdString = toUtf8(getXmlValue(xml, L"EventID"));

            uint32_t eventId = 0;

            if (!eventIdString.empty()) {
                try {
                    eventId = static_cast<uint32_t>(std::stoul(eventIdString));
                } catch (...) {
                    eventId = 0;
                }
            }

            std::string computer = toUtf8(getXmlValue(xml, L"Computer"));

            EventLogEvidence data;

            data.channel = "System";

            data.eventId = eventId;

            data.provider = provider;

            data.computer = computer;

            Evidence item;
            item.type = EvidenceType::EventLog;

            item.id = "event-" + std::to_string(evidence.size() + 1);

            item.source = "Windows Event Log";

            item.timestamp = timestamp;

            item.description =
                "Windows System event " + std::to_string(eventId);

            if (!provider.empty()) {
                item.description += " from " + provider;
            }

            item.raw = toUtf8(xml);

            item.data = std::move(data);

            evidence.push_back(std::move(item));

            EvtClose(events[i]);
        }
    }

    EvtClose(query);

    return evidence;
}