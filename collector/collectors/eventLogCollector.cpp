#include "eventLogCollector.h"

#include <windows.h>
#include <winevt.h>

#include <iostream>
#include <string>
#include <vector>

#pragma comment(lib, "wevtapi.lib")

std::vector<Evidence> EventLogCollector::collect() {
    std::vector<Evidence> evidence;

    const wchar_t* channel = L"System";

    EVT_HANDLE query = EvtQuery(nullptr, channel, L"*",
                                EvtQueryChannelPath | EvtQueryForwardDirection);

    if (!query) {
        std::cerr << "EvtQuery failed: " << GetLastError() << '\n';
        return evidence;
    }

    EVT_HANDLE events[16];
    DWORD returned = 0;

    while (EvtNext(query, 16, events, INFINITE, 0, &returned)) {
        for (DWORD i = 0; i < returned; i++) {
            DWORD bufferUsed = 0;
            DWORD propertyCount = 0;

            EvtRender(nullptr, events[i], EvtRenderEventXml, 0, nullptr,
                      &bufferUsed, &propertyCount);

            if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
                EvtClose(events[i]);
                continue;
            }

            std::vector<wchar_t> buffer(bufferUsed / sizeof(wchar_t));

            if (EvtRender(nullptr, events[i], EvtRenderEventXml, bufferUsed,
                          buffer.data(), &bufferUsed, &propertyCount)) {
                std::wstring xml(buffer.data());

                Evidence item;

                item.source = "Windows Event Log";
                item.category = "System";
                item.timestamp = "";
                item.description = std::string(xml.begin(), xml.end());

                evidence.push_back(std::move(item));
            }

            EvtClose(events[i]);
        }
    }

    EvtClose(query);

    return evidence;
}