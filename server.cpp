#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <windows.h>
#include <iostream>
#include <string>
#include <thread>
#include <chrono>
#include <atomic>
#include <sstream>
#include <iomanip>
#include <vector>
#include <fstream>
#include <winreg.h>
#include <winternl.h>

#pragma comment(lib, "Ntdll.lib")
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Iphlpapi.lib")
#pragma comment(lib, "Advapi32.lib")

typedef NTSTATUS(NTAPI *NtQuerySystemInformation_t)(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength);

static NtQuerySystemInformation_t NtQuerySystemInformationFunc =
    (NtQuerySystemInformation_t)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");

std::vector<SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION> prevInfo;
std::vector<double> perCoreUsage;

bool initCoreData()
{
    ULONG len = 0;
    NtQuerySystemInformationFunc(SystemProcessorPerformanceInformation, NULL, 0, &len);
    size_t count = len / sizeof(SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION);
    prevInfo.resize(count);
    perCoreUsage.resize(count, 0.0);
    if (NtQuerySystemInformationFunc(SystemProcessorPerformanceInformation, prevInfo.data(), (ULONG)(count * sizeof(SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION)), &len) != 0)
        return false;
    return true;
}

void getPerCoreCpuUsage(std::vector<double> &usageOut)
{
    ULONG len = 0;
    NtQuerySystemInformationFunc(SystemProcessorPerformanceInformation, NULL, 0, &len);
    size_t count = len / sizeof(SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION);
    std::vector<SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION> curInfo(count);
    if (NtQuerySystemInformationFunc(SystemProcessorPerformanceInformation, curInfo.data(), (ULONG)(count * sizeof(SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION)), &len) != 0)
        return;

    for (size_t i = 0; i < count; i++)
    {
        ULONGLONG idleDiff = curInfo[i].IdleTime.QuadPart - prevInfo[i].IdleTime.QuadPart;
        ULONGLONG kernelDiff = curInfo[i].KernelTime.QuadPart - prevInfo[i].KernelTime.QuadPart;
        ULONGLONG userDiff = curInfo[i].UserTime.QuadPart - prevInfo[i].UserTime.QuadPart;

        ULONGLONG total = kernelDiff + userDiff;
        double cpu = total == 0 ? 0.0 : (double)(total - idleDiff) * 100.0 / (double)total;
        usageOut[i] = cpu;
    }

    prevInfo = curInfo;
}

struct Stats
{
    std::vector<std::string> cpuUsage_perc;
    std::string cpuUsage;
    std::string hostname;
    std::string uptime_str;
    std::string cpuModel;
    std::string lanIPv4;

    std::string mem_total_raw, mem_total_human;
    std::string mem_used_raw, mem_used_human;
    std::string mem_free_raw, mem_free_human;

    std::string disk_read_kBps, disk_write_kBps;
    std::string net_rx_kBps, net_tx_kBps;

    std::string disk_total_raw, disk_total_human;
    std::string disk_used_raw, disk_used_human;
    std::string disk_free_raw, disk_free_human;
};

static Stats g_stats;
static std::atomic<bool> g_running(true);

// Utility: human-readable bytes
std::string humanReadableBytes(unsigned long long bytes)
{
    const char *suffix[] = {"B", "KiB", "MiB", "GiB", "TiB"};
    double dbl = (double)bytes;
    int i = 0;
    while (dbl > 1024.0 && i < 4)
    {
        dbl /= 1024.0;
        i++;
    }
    char buf[64];
    sprintf_s(buf, "%.2f %s", dbl, suffix[i]);
    return std::string(buf);
}

// Get hostname
std::string getHostname()
{
    WCHAR wname[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD size = MAX_COMPUTERNAME_LENGTH + 1;
    GetComputerNameExW(ComputerNameDnsHostname, wname, &size);
    char name[256];
    WideCharToMultiByte(CP_UTF8, 0, wname, -1, name, 256, NULL, NULL);
    return std::string(name);
}

// Format uptime as DD:HH:MM:SS
std::string formatUptime()
{
    ULONGLONG ms = GetTickCount64();
    unsigned long sec = (unsigned long)(ms / 1000ULL);
    int days = sec / 86400;
    sec %= 86400;
    int hours = sec / 3600;
    sec %= 3600;
    int mins = sec / 60;
    sec %= 60;
    char buf[64];
    sprintf_s(buf, "%d:%02d:%02d:%02d", days, hours, mins, (int)sec);
    return std::string(buf);
}

// Get CPU model from registry
std::string getCpuModel()
{
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                      "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0",
                      0, KEY_READ, &hKey) == ERROR_SUCCESS)
    {
        char buffer[256];
        DWORD size = sizeof(buffer);
        if (RegQueryValueExA(hKey, "ProcessorNameString", NULL, NULL, (LPBYTE)buffer, &size) == ERROR_SUCCESS)
        {
            RegCloseKey(hKey);
            return std::string(buffer);
        }
        RegCloseKey(hKey);
    }
    return "Unknown CPU";
}

// Get LAN IPv4 - use GetAdaptersAddresses
std::string getLanIPv4()
{
    ULONG outBufLen = 15000;
    std::vector<BYTE> buf(outBufLen);
    PIP_ADAPTER_ADDRESSES pAddresses = (PIP_ADAPTER_ADDRESSES)buf.data();

    ULONG ret = GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_PREFIX, NULL, pAddresses, &outBufLen);
    if (ret == NO_ERROR)
    {
        for (PIP_ADAPTER_ADDRESSES addr = pAddresses; addr; addr = addr->Next)
        {
            if (addr->IfType == IF_TYPE_ETHERNET_CSMACD && addr->OperStatus == IfOperStatusUp)
            {
                for (PIP_ADAPTER_UNICAST_ADDRESS ua = addr->FirstUnicastAddress; ua; ua = ua->Next)
                {
                    SOCKADDR_IN *sa = (SOCKADDR_IN *)ua->Address.lpSockaddr;
                    if (sa->sin_family == AF_INET)
                    {
                        char ip[INET_ADDRSTRLEN];
                        inet_ntop(AF_INET, &sa->sin_addr, ip, sizeof(ip));
                        return std::string(ip);
                    }
                }
            }
        }
    }
    return "0.0.0.0";
}

// CPU usage using GetSystemTimes
double getCpuUsage()
{
    static FILETIME prevIdle = {0}, prevKernel = {0}, prevUser = {0};

    FILETIME idle, kernel, user;
    GetSystemTimes(&idle, &kernel, &user);

    ULONGLONG idleT = ((ULONGLONG)idle.dwHighDateTime << 32) | idle.dwLowDateTime;
    ULONGLONG kernelT = ((ULONGLONG)kernel.dwHighDateTime << 32) | kernel.dwLowDateTime;
    ULONGLONG userT = ((ULONGLONG)user.dwHighDateTime << 32) | user.dwLowDateTime;

    ULONGLONG prevIdleT = ((ULONGLONG)prevIdle.dwHighDateTime << 32) | prevIdle.dwLowDateTime;
    ULONGLONG prevKernelT = ((ULONGLONG)prevKernel.dwHighDateTime << 32) | prevKernel.dwLowDateTime;
    ULONGLONG prevUserT = ((ULONGLONG)prevUser.dwHighDateTime << 32) | prevUser.dwLowDateTime;

    ULONGLONG idleDiff = idleT - prevIdleT;
    ULONGLONG kernelDiff = kernelT - prevKernelT;
    ULONGLONG userDiff = userT - prevUserT;

    ULONGLONG totalDiff = kernelDiff + userDiff;
    double cpu = 0.0;
    if (totalDiff > 0)
    {
        cpu = (double)(totalDiff - idleDiff) * 100.0 / (double)totalDiff;
    }

    prevIdle = idle;
    prevKernel = kernel;
    prevUser = user;
    return cpu;
}

// Memory info
void getMemory(std::string &total_raw, std::string &total_h, std::string &used_raw,
               std::string &used_h, std::string &free_raw, std::string &free_h)
{
    MEMORYSTATUSEX mem = {0};
    mem.dwLength = sizeof(mem);
    GlobalMemoryStatusEx(&mem);
    unsigned long long total = mem.ullTotalPhys;
    unsigned long long freeb = mem.ullAvailPhys;
    unsigned long long used = total - freeb;
    total_raw = std::to_string(total);
    total_h = humanReadableBytes(total);
    used_raw = std::to_string(used);
    used_h = humanReadableBytes(used);
    free_raw = std::to_string(freeb);
    free_h = humanReadableBytes(freeb);
}

// Disk usage: for C:
void getDiskUsage(std::string &total_raw, std::string &total_h,
                  std::string &used_raw, std::string &used_h,
                  std::string &free_raw, std::string &free_h)
{
    ULARGE_INTEGER freeBytesAvailable, totalBytes, freeBytes;
    if (GetDiskFreeSpaceExA("C:\\", &freeBytesAvailable, &totalBytes, &freeBytes))
    {
        unsigned long long total = totalBytes.QuadPart;
        unsigned long long freeb = freeBytes.QuadPart;
        unsigned long long used = total - freeb;
        total_raw = std::to_string(total);
        total_h = humanReadableBytes(total);
        used_raw = std::to_string(used);
        used_h = humanReadableBytes(used);
        free_raw = std::to_string(freeb);
        free_h = humanReadableBytes(freeb);
    }
    else
    {
        total_raw = "0";
        total_h = "0B";
        used_raw = "0";
        used_h = "0B";
        free_raw = "0";
        free_h = "0B";
    }
}

static unsigned long long prevNetIn = 0, prevNetOut = 0;
static auto lastNet = std::chrono::steady_clock::now();

void getDiskIO(std::string &read_kBps, std::string &write_kBps)
{
    // A full solution requires ETW or performance counters. For simplicity, return 0.
    read_kBps = "0";
    write_kBps = "0";
}

void getNetwork(std::string &rx_kBps, std::string &tx_kBps)
{
    MIB_IF_TABLE2 *pTable = nullptr;
    if (GetIfTable2(&pTable) == NO_ERROR)
    {
        // Sum up all non-loopback interfaces
        unsigned long long inOctets = 0, outOctets = 0;
        for (ULONG i = 0; i < pTable->NumEntries; i++)
        {
            MIB_IF_ROW2 row = pTable->Table[i];
            if (row.Type != IF_TYPE_SOFTWARE_LOOPBACK && row.OperStatus == IfOperStatusUp)
            {
                inOctets += row.InOctets;
                outOctets += row.OutOctets;
            }
        }
        FreeMibTable(pTable);

        auto now = std::chrono::steady_clock::now();
        double sec = std::chrono::duration<double>(now - lastNet).count();
        if (sec <= 0)
            sec = 1;
        double rx_rate = (double)(inOctets - prevNetIn) / 1024.0 / sec;
        double tx_rate = (double)(outOctets - prevNetOut) / 1024.0 / sec;
        prevNetIn = inOctets;
        prevNetOut = outOctets;
        lastNet = now;

        rx_kBps = std::to_string(rx_rate);
        tx_kBps = std::to_string(tx_rate);
    }
    else
    {
        rx_kBps = "0";
        tx_kBps = "0";
    }
}

// Background thread
void statsThread()
{
    // Initialize CPU usage
    getCpuUsage();
    getPerCoreCpuUsage(perCoreUsage);
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    while (g_running)
    {
        double cpu = getCpuUsage();
        getPerCoreCpuUsage(perCoreUsage);
        std::string mt, mth, mu, muh, mf, mfh;
        getMemory(mt, mth, mu, muh, mf, mfh);

        std::string dr, dw;
        getDiskIO(dr, dw);

        std::string rx, tx;
        getNetwork(rx, tx);

        std::string dt, dth, du, duh, df, dfh;
        getDiskUsage(dt, dth, du, duh, df, dfh);

        std::string host = getHostname();
        std::string uptime = formatUptime();
        std::string cpuModel = getCpuModel();
        std::string lan = getLanIPv4();

        g_stats.cpuUsage = std::to_string(cpu);
        g_stats.hostname = host;
        g_stats.uptime_str = uptime;
        g_stats.cpuModel = cpuModel;
        g_stats.lanIPv4 = lan;
        g_stats.mem_total_raw = mt;
        g_stats.mem_total_human = mth;
        g_stats.mem_used_raw = mu;
        g_stats.mem_used_human = muh;
        g_stats.mem_free_raw = mf;
        g_stats.mem_free_human = mfh;
        g_stats.disk_read_kBps = dr;
        g_stats.disk_write_kBps = dw;
        g_stats.net_rx_kBps = rx;
        g_stats.net_tx_kBps = tx;
        g_stats.disk_total_raw = dt;
        g_stats.disk_total_human = dth;
        g_stats.disk_used_raw = du;
        g_stats.disk_used_human = duh;
        g_stats.disk_free_raw = df;
        g_stats.disk_free_human = dfh;
        g_stats.cpuUsage_perc.clear();
        // float sum = 0;
        // size_t count = 0;
        for (auto val : perCoreUsage)
        {
            // sum += (float)val;
            // count += 1;
            g_stats.cpuUsage_perc.push_back(std::to_string(val));
        }
        // std::cout << (sum/count) << " " << g_stats.cpuUsage << std::endl; sanity check

        HKEY hKey;
        DWORD mhz;
        DWORD size = sizeof(mhz);

        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                          "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0",
                          0, KEY_READ, &hKey) == ERROR_SUCCESS)
        {
            if (RegQueryValueExA(hKey, "~MHz", NULL, NULL, (LPBYTE)&mhz, &size) == ERROR_SUCCESS)
            {
                std::cout << "Current CPU speed: " << mhz << " MHz" << std::endl;
            }
            RegCloseKey(hKey);
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }
}

std::string getAllNetworkInterfacesJSON()
{
    std::ostringstream json;
    json << "[";

    ULONG outBufLen = 15000;
    std::vector<BYTE> buf(outBufLen);
    PIP_ADAPTER_ADDRESSES pAddresses = (PIP_ADAPTER_ADDRESSES)buf.data();

    ULONG ret = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, NULL, pAddresses, &outBufLen);
    if (ret == NO_ERROR)
    {
        bool first = true;
        for (auto addr = pAddresses; addr; addr = addr->Next)
        {
            if (addr->OperStatus == IfOperStatusUp)
            {
                std::wstring wFriendlyName(addr->FriendlyName);
                int size = WideCharToMultiByte(CP_UTF8, 0, wFriendlyName.c_str(), -1, NULL, 0, NULL, NULL);
                std::string friendlyName(size - 1, '\0');
                WideCharToMultiByte(CP_UTF8, 0, wFriendlyName.c_str(), -1, &friendlyName[0], size, NULL, NULL);

                // std::cout << friendlyName << std::endl;
                // std::cout << friendlyName << "\n";
                if (!first)
                    json << ",";

                json << "{"
                     << "\"name\":\"" << friendlyName << "\","
                     << "\"type\":" << (int)addr->IfType << ",";
                //<< "\"status\":" << (addr->OperStatus == IfOperStatusUp ? "\"up\"" : "\"down\"") << ",";

                // Get all IP addresses for this interface
                std::ostringstream ips;
                ips << "[";
                bool first_ip = true;
                for (auto ua = addr->FirstUnicastAddress; ua; ua = ua->Next)
                {
                    SOCKADDR *sa = ua->Address.lpSockaddr;
                    char ipStr[INET6_ADDRSTRLEN];
                    if (sa->sa_family == AF_INET)
                    {
                        inet_ntop(AF_INET, &((SOCKADDR_IN *)sa)->sin_addr, ipStr, sizeof(ipStr));
                    }
                    else if (sa->sa_family == AF_INET6)
                    {
                        inet_ntop(AF_INET6, &((SOCKADDR_IN6 *)sa)->sin6_addr, ipStr, sizeof(ipStr));
                    }
                    else
                    {
                        continue;
                    }
                    if (!first_ip)
                        ips << ",";
                    ips << "\"" << ipStr << "\"";
                    first_ip = false;
                }
                ips << "]";

                json << "\"addresses\":" << ips.str() << "}";
                first = false;
            }
        }
    }

    json << "]";
    return json.str();
}
// Example function to list all volumes and their usage
std::string getAllDiskUsageJSON()
{
    std::ostringstream json;
    json << "[";

    // Enumerate volumes
    HANDLE hFind;
    WCHAR volumeName[MAX_PATH];
    hFind = FindFirstVolumeW(volumeName, MAX_PATH);
    if (hFind == INVALID_HANDLE_VALUE)
    {
        json << "]";
        return json.str();
    }

    bool first = true;
    do
    {
        // Skip volumes that are not drive letters (e.g., system volumes)
        // We can query for drive paths associated with this volume:
        WCHAR pathNames[4096];
        DWORD pathLen = 0;
        if (GetVolumePathNamesForVolumeNameW(volumeName, pathNames, 4096, &pathLen))
        {
            std::wstring driveLetter(pathNames);
            if (!driveLetter.empty())
            {
                // Get disk usage
                ULARGE_INTEGER freeBytesAvailable, totalBytes, freeBytes;
                if (GetDiskFreeSpaceExW(driveLetter.c_str(), &freeBytesAvailable, &totalBytes, &freeBytes))
                {
                    std::wstring driveLetterW(pathNames);
                    std::string driveLetter(driveLetterW.begin(), driveLetterW.end());

                    // If the drive letter is something like "C:\", just trim the backslash
                    if (!driveLetter.empty() && driveLetter.back() == '\\')
                    {
                        driveLetter.pop_back();
                    }
                    unsigned long long total = totalBytes.QuadPart;
                    unsigned long long freeb = freeBytes.QuadPart;
                    unsigned long long used = total - freeb;
                    if (!first)
                        json << ",";
                    json << "{"
                         << "\"volume\":\"" << driveLetter << "\","
                         << "\"total\":[" << total << ",\"" << humanReadableBytes(total) << "\"],"
                         << "\"used\":[" << used << ",\"" << humanReadableBytes(used) << "\"],"
                         << "\"free\":[" << freeb << ",\"" << humanReadableBytes(freeb) << "\"]"
                         << "}";
                    first = false;
                }
            }
        }

    } while (FindNextVolumeW(hFind, volumeName, MAX_PATH));
    FindVolumeClose(hFind);

    json << "]";
    return json.str();
}

// Simple HTTP server on Windows
void serveClient(SOCKET client)
{
    char buffer[1024];
    int n = recv(client, buffer, sizeof(buffer) - 1, 0);
    if (n <= 0)
    {
        closesocket(client);
        return;
    }
    buffer[n] = 0;
    std::string req(buffer);
    if (req.find("GET /status") == 0)
    {
        std::string diskJSON = getAllDiskUsageJSON();
        std::string netJSON = getAllNetworkInterfacesJSON();

        std::stringstream json;
        json << "{"
             << "\"cpuUsage\":\"" << g_stats.cpuUsage << "\","
             << "\"cpuCoreUsage\":[";
        for (size_t i = 0; i < g_stats.cpuUsage_perc.size(); i++)
        {
            if (i > 0)
                json << ",";
            json << "\"" << g_stats.cpuUsage_perc[i] << "\"";
        }
        json << "],"
             << "\"allDiskUsage\":" << diskJSON << ","
             << "\"allNetworkInterfaces\":" << netJSON << ","
             << "\"system\":{"
             << "\"hostname\":\"" << g_stats.hostname << "\","
             << "\"uptime\":\"" << g_stats.uptime_str << "\","
             << "\"cpu\":\"" << g_stats.cpuModel << "\","
             << "\"lan_ipv4\":\"" << g_stats.lanIPv4 << "\""
             << "}"
             << "}";

        std::string response = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n" + json.str();
        send(client, response.c_str(), (int)response.size(), 0);
    }
    else
    {
        std::string response = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
        send(client, response.c_str(), (int)response.size(), 0);
    }
    closesocket(client);
}

int main()
{
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);

    if (!initCoreData())
    {
        std::cerr << "Failed to init per-core data\n";
    }

    std::thread th(statsThread);

    SOCKET server_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, (const char *)&opt, sizeof(opt));

    sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(8080);
    bind(server_fd, (struct sockaddr *)&addr, sizeof(addr));
    listen(server_fd, 10);

    std::cout << "Server running on port 8080 (Windows)\n";

    while (true)
    {
        SOCKET client = accept(server_fd, NULL, NULL);
        if (client == INVALID_SOCKET)
            break;
        serveClient(client);
    }

    g_running = false;
    th.join();

    closesocket(server_fd);
    WSACleanup();

    return 0;
}
