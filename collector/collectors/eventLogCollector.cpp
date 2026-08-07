#include "eventLogCollector.h"

#include <windows.h>
#include <winevt.h>

#include <iostream>
#include <vector>

#pragma comment(lib, "wevtapi.lib")

bool EventLogCollector::collect() {
    const wchar_t* channel = L"System";

    EVT_HANDLE query = EvtQuery(nullptr, channel, L"*",
                                EvtQueryChannelPath | EvtQueryForwardDirection);

    if (!query) {
        std::cerr << "EvtQuery failed: " << GetLastError() << '\n';
        return false;
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
                std::wcout << buffer.data() << L"\n\n";
            }

            EvtClose(events[i]);
        }
    }

    EvtClose(query);
    return true;
}