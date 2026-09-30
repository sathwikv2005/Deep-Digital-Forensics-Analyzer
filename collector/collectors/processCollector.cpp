#include "processCollector.h"

#include <windows.h>
#include <winevt.h>

#include <iostream>
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

std::wstring extractDataValue(const std::wstring& xml,
                              const std::wstring& name) {
    std::wstring patterns[] = {L"<Data Name=\"" + name + L"\">",
                               L"<Data Name='" + name + L"'>"};

    for (const auto& pattern : patterns) {
        size_t start = xml.find(pattern);

        if (start == std::wstring::npos) {
            continue;
        }

        start += pattern.size();

        size_t end = xml.find(L"</Data>", start);

        if (end == std::wstring::npos) {
            return L"";
        }

        return xml.substr(start, end - start);
    }

    return L"";
}

}  // namespace

std::vector<Evidence> ProcessCollector::collect() {
    evidence_.clear();

    std::cout << "[Process] Collecting historical process creation events...\n";

    EVT_HANDLE query =
        EvtQuery(nullptr, L"Security", L"*[System[(EventID=4688)]]",
                 EvtQueryChannelPath);

    if (!query) {
        std::cerr << "[Process] EvtQuery failed: " << GetLastError() << '\n';

        return evidence_;
    }

    while (true) {
        EVT_HANDLE events[16];
        DWORD returned = 0;

        BOOL result = EvtNext(query, 16, events, INFINITE, 0, &returned);

        if (!result) {
            DWORD error = GetLastError();

            if (error == ERROR_NO_MORE_ITEMS) {
                break;
            }

            std::cerr << "[Process] EvtNext failed: " << error << '\n';

            break;
        }

        for (DWORD i = 0; i < returned; ++i) {
            handleEvent(events[i]);
            EvtClose(events[i]);
        }
    }

    EvtClose(query);

    std::cout << "[Process] Collection complete. Events: " << evidence_.size()
              << '\n';

    return evidence_;
}

void ProcessCollector::handleEvent(void* eventHandle) {
    EVT_HANDLE event = static_cast<EVT_HANDLE>(eventHandle);

    std::wstring xml = renderEvent(event);

    if (xml.empty()) {
        return;
    }

    std::wstring processIdValue = extractDataValue(xml, L"NewProcessId");

    std::wstring parentProcessIdValue = extractDataValue(xml, L"ProcessId");

    std::wstring processNameValue = extractDataValue(xml, L"NewProcessName");

    std::wstring parentProcessNameValue =
        extractDataValue(xml, L"ParentProcessName");

    std::wstring commandLineValue = extractDataValue(xml, L"CommandLine");

    std::wstring targetUserNameValue = extractDataValue(xml, L"TargetUserName");

    if (processNameValue.empty()) {
        return;
    }

    uint32_t processId = 0;
    uint32_t parentProcessId = 0;

    try {
        if (!processIdValue.empty()) {
            processId =
                static_cast<uint32_t>(std::stoul(processIdValue, nullptr, 0));
        }

        if (!parentProcessIdValue.empty()) {
            parentProcessId = static_cast<uint32_t>(
                std::stoul(parentProcessIdValue, nullptr, 0));
        }
    } catch (...) {
        return;
    }

    ProcessEvidence data;

    data.processId = processId;
    data.parentProcessId = parentProcessId;

    data.processName = wideToUtf8(processNameValue);

    data.processPath = wideToUtf8(processNameValue);

    data.parentProcessName = wideToUtf8(parentProcessNameValue);

    data.commandLine = wideToUtf8(commandLineValue);

    data.username = wideToUtf8(targetUserNameValue);

    Evidence evidence;

    evidence.id = "process-" + std::to_string(evidence_.size());

    evidence.type = EvidenceType::Process;

    evidence.source = "Windows Security";

    evidence.timestamp = extractTimestamp(xml);

    evidence.description = "Process created: " + data.processName;

    evidence.data = data;

    evidence.raw = wideToUtf8(xml);

    evidence_.push_back(std::move(evidence));
}