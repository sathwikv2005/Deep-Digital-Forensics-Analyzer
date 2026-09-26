#include "processCollector.h"

// clang-format off
#include <windows.h>
#include <tlhelp32.h>
// clang-format on

#include <iostream>
#include <string>
#include <vector>

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

std::string getProcessPath(DWORD pid) {
    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);

    if (!process) {
        return "";
    }

    wchar_t path[32768]{};

    DWORD size = static_cast<DWORD>(std::size(path));

    std::string result;

    if (QueryFullProcessImageNameW(process, 0, path, &size)) {
        result = wideToUtf8(std::wstring(path, size));
    }

    CloseHandle(process);

    return result;
}

std::string fileNameFromPath(const std::string& path) {
    if (path.empty()) {
        return "";
    }

    size_t position = path.find_last_of("\\/");

    if (position == std::string::npos) {
        return path;
    }

    return path.substr(position + 1);
}

std::string currentTimestamp() {
    SYSTEMTIME time{};

    GetSystemTime(&time);

    char buffer[64]{};

    snprintf(buffer, sizeof(buffer), "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ",
             time.wYear, time.wMonth, time.wDay, time.wHour, time.wMinute,
             time.wSecond, time.wMilliseconds);

    return buffer;
}

}  // namespace

std::vector<Evidence> ProcessCollector::collect() {
    std::vector<Evidence> evidence;

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (snapshot == INVALID_HANDLE_VALUE) {
        std::cerr << "CreateToolhelp32Snapshot failed: " << GetLastError()
                  << '\n';

        return evidence;
    }

    PROCESSENTRY32W processEntry{};

    processEntry.dwSize = sizeof(PROCESSENTRY32W);

    if (!Process32FirstW(snapshot, &processEntry)) {
        CloseHandle(snapshot);

        return evidence;
    }

    do {
        DWORD pid = processEntry.th32ProcessID;

        DWORD parentPid = processEntry.th32ParentProcessID;

        std::string processPath = getProcessPath(pid);

        std::string processName = wideToUtf8(processEntry.szExeFile);

        ProcessEvidence data;

        data.processId = pid;
        data.parentProcessId = parentPid;

        data.processName = processName;

        data.processPath = processPath;

        Evidence item;
        item.type = EvidenceType::Process;

        item.id = "process-" + std::to_string(evidence.size() + 1);

        item.source = "Windows Process";

        item.timestamp = currentTimestamp();

        item.description = processName + " (" + std::to_string(pid) + ")";

        item.raw = "pid=" + std::to_string(pid) +
                   "; ppid=" + std::to_string(parentPid) +
                   "; process=" + processName + "; path=" + processPath;

        item.data = std::move(data);

        evidence.push_back(std::move(item));

    } while (Process32NextW(snapshot, &processEntry));

    CloseHandle(snapshot);

    return evidence;
}