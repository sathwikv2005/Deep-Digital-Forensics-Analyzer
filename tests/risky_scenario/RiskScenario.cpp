#include <windows.h>
#include <winhttp.h>

#include <fstream>
#include <iostream>
#include <string>
#include <vector>

#pragma comment(lib, "winhttp.lib")

int main() {
    char tempPath[MAX_PATH];

    if (!GetTempPathA(MAX_PATH, tempPath)) {
        std::cerr << "Failed to get TEMP path.\n";
        return 1;
    }

    std::string testDir = std::string(tempPath) + "DeepForensicsTest";
    std::string testFile = testDir + "\\downloaded_test.txt";
    std::string childFile = testDir + "\\child_process.txt";

    CreateDirectoryA(testDir.c_str(), nullptr);

    std::cout << "[TEST] Test directory: " << testDir << '\n';

    {
        std::ofstream file(testFile);
        file << "Deep AI Digital Forensics test file\n";
        file << "This file is completely harmless.\n";
    }

    std::cout << "[TEST] Created file: " << testFile << '\n';

    STARTUPINFOA si{};
    PROCESS_INFORMATION pi{};

    si.cb = sizeof(si);

    std::string command =
        "cmd.exe /c echo Child process executed > \"" + childFile + "\"";

    std::vector<char> commandBuffer(command.begin(), command.end());
    commandBuffer.push_back('\0');

    if (CreateProcessA(nullptr, commandBuffer.data(), nullptr, nullptr, FALSE,
                       CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
        std::cout << "[TEST] Created child process.\n";

        WaitForSingleObject(pi.hProcess, 5000);

        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    } else {
        std::cerr << "[TEST] Failed to create child process.\n";
    }

    std::cout << "[TEST] Connecting to example.com...\n";

    HINTERNET session =
        WinHttpOpen(L"DeepForensicsTest/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                    WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);

    if (session) {
        HINTERNET connection = WinHttpConnect(session, L"example.com",
                                              INTERNET_DEFAULT_HTTP_PORT, 0);

        if (connection) {
            HINTERNET request = WinHttpOpenRequest(
                connection, L"GET", L"/", nullptr, WINHTTP_NO_REFERER,
                WINHTTP_DEFAULT_ACCEPT_TYPES, 0);

            if (request) {
                BOOL result =
                    WinHttpSendRequest(request, WINHTTP_NO_ADDITIONAL_HEADERS,
                                       0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0);

                if (result) {
                    WinHttpReceiveResponse(request, nullptr);

                    std::cout << "[TEST] HTTP request completed.\n";
                }

                CloseHandle(request);
            }

            CloseHandle(connection);
        }

        WinHttpCloseHandle(session);
    }

    std::cout << "[TEST] Scenario completed.\n";

    Sleep(3000);

    return 0;
}