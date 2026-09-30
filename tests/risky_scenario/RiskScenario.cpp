#include <windows.h>
#include <winhttp.h>

#include <fstream>
#include <iostream>
#include <string>
#include <vector>

#pragma comment(lib, "winhttp.lib")

static std::string getTempDirectory() {
    char buffer[MAX_PATH];

    DWORD length = GetTempPathA(MAX_PATH, buffer);

    if (length == 0 || length >= MAX_PATH) {
        return ".";
    }

    return std::string(buffer) + "DeepForensicsThreat";
}

static void createFile(const std::string& path, const std::string& content) {
    std::ofstream file(path);
    file << content;
}

static bool runProcess(const std::string& command) {
    STARTUPINFOA si{};
    PROCESS_INFORMATION pi{};

    si.cb = sizeof(si);

    std::vector<char> buffer(command.begin(), command.end());
    buffer.push_back('\0');

    BOOL result =
        CreateProcessA(nullptr, buffer.data(), nullptr, nullptr, FALSE,
                       CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi);

    if (!result) {
        return false;
    }

    WaitForSingleObject(pi.hProcess, 5000);

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    return true;
}

static void generateSuspiciousFiles(const std::string& directory) {
    std::cout << "[SIM] Creating suspicious-looking files...\n";

    for (int i = 0; i < 20; ++i) {
        std::string path =
            directory + "\\document_" + std::to_string(i) + ".txt";

        createFile(path, "Synthetic forensic test document " +
                             std::to_string(i) + "\n");
    }
}

static void renameFiles(const std::string& directory) {
    std::cout << "[SIM] Simulating suspicious file modification...\n";

    for (int i = 0; i < 20; ++i) {
        std::string original =
            directory + "\\document_" + std::to_string(i) + ".txt";

        std::string renamed =
            directory + "\\document_" + std::to_string(i) + ".locked";

        MoveFileA(original.c_str(), renamed.c_str());
    }
}

static void createChildProcess() {
    std::cout << "[SIM] Creating process chain...\n";

    runProcess(
        "cmd.exe /c powershell.exe -NoProfile -Command "
        "\"Write-Output 'Synthetic forensic test event'\"");
}

static void createNetworkActivity() {
    std::cout << "[SIM] Generating network activity...\n";

    HINTERNET session = WinHttpOpen(
        L"DeepForensicsThreatSimulator/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);

    if (!session) {
        return;
    }

    HINTERNET connection =
        WinHttpConnect(session, L"example.com", INTERNET_DEFAULT_HTTP_PORT, 0);

    if (!connection) {
        WinHttpCloseHandle(session);
        return;
    }

    HINTERNET request =
        WinHttpOpenRequest(connection, L"GET", L"/", nullptr,
                           WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);

    if (request) {
        WinHttpSendRequest(request, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                           WINHTTP_NO_REQUEST_DATA, 0, 0, 0);

        WinHttpReceiveResponse(request, nullptr);

        CloseHandle(request);
    }

    CloseHandle(connection);
    WinHttpCloseHandle(session);
}

int main() {
    std::string directory = getTempDirectory();

    CreateDirectoryA(directory.c_str(), nullptr);

    std::cout << "\n";
    std::cout << "========================================\n";
    std::cout << " Deep Forensics Threat Simulator\n";
    std::cout << "========================================\n";
    std::cout << "\n";

    std::cout << "[SIM] Working directory: " << directory << "\n";

    std::cout << "[SIM] Phase 1: Initial file activity\n";

    createFile(directory + "\\invoice.pdf.exe",
               "Synthetic suspicious executable placeholder\n");

    createFile(directory + "\\update.exe",
               "Synthetic suspicious executable placeholder\n");

    generateSuspiciousFiles(directory);

    Sleep(1000);

    std::cout << "[SIM] Phase 2: Process activity\n";

    createChildProcess();

    Sleep(1000);

    std::cout << "[SIM] Phase 3: Network activity\n";

    createNetworkActivity();

    Sleep(1000);

    std::cout << "[SIM] Phase 4: File modification activity\n";

    renameFiles(directory);

    Sleep(1000);

    std::cout << "[SIM] Phase 5: Additional process activity\n";

    runProcess("cmd.exe /c whoami.exe");

    runProcess("cmd.exe /c hostname.exe");

    Sleep(1000);

    std::cout << "\n";
    std::cout << "========================================\n";
    std::cout << " Synthetic threat scenario completed\n";
    std::cout << "========================================\n";
    std::cout << "\n";

    std::cout << "[SIM] No persistence was created.\n";
    std::cout << "[SIM] No credentials were accessed.\n";
    std::cout << "[SIM] No destructive operations were performed.\n";

    return 0;
}