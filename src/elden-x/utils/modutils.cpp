#include <array>
#include <codecvt>
#include <filesystem>
#include <locale>
#include <span>
#include <stdexcept>
#include <string>

#include <MinHook.h>
#include <Pattern16.h>
#include <spdlog/spdlog.h>
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winver.h>
#include <TlHelp32.h>

#include "elden-x/utils/modutils.hpp"

using namespace std;

extern span<unsigned char> memory;

static string sus_filenames[] = {
    "ALI213.ini",      "ColdAPI.ini",   "ColdClientLoader.ini",  "CPY.ini",
    "ds.ini",          "hlm.ini",       "local_save.txt",        "SmartSteamEmu.ini",
    "steam_api.ini",   "steam_emu.ini", "steam_interfaces.ini",  "steam_settings",
    "SteamConfig.ini", "valve.ini",     "Language Selector.exe",
};

void modutils::initialize()
{
    HMODULE module_handle = GetModuleHandleA("eldenring.exe");
    if (!module_handle)
    {
        throw runtime_error("Failed to get handle for eldenring.exe process");
    }

    wstring_convert<codecvt_utf8_utf16<wchar_t>, wchar_t> convert;

    wchar_t exe_filename[MAX_PATH] = {0};
    GetModuleFileNameW(module_handle, exe_filename, MAX_PATH);
    SPDLOG_INFO("Found handle for eldenring.exe process: {}", convert.to_bytes(exe_filename));

    auto exe_directory = filesystem::path(exe_filename).parent_path();
    for (auto i = 0; i < size(sus_filenames); i++)
    {
        if (filesystem::exists(exe_directory / sus_filenames[i]))
        {
            SPDLOG_ERROR("Game may be modified, compatibility is unlikely [{}]", i);
        }
    }

    MEMORY_BASIC_INFORMATION memory_info;
    if (VirtualQuery((void *)module_handle, &memory_info, sizeof(memory_info)) == 0)
    {
        throw runtime_error("Failed to get virtual memory information");
    }

    IMAGE_DOS_HEADER *dos_header = (IMAGE_DOS_HEADER *)module_handle;
    IMAGE_NT_HEADERS *nt_headers =
        (IMAGE_NT_HEADERS *)((ULONG64)memory_info.AllocationBase + (ULONG64)dos_header->e_lfanew);

    if ((dos_header->e_magic == IMAGE_DOS_SIGNATURE) &&
        (nt_headers->Signature == IMAGE_NT_SIGNATURE))
    {
        memory = {(unsigned char *)memory_info.AllocationBase,
                  nt_headers->OptionalHeader.SizeOfImage};
    }

    auto mh_status = MH_Initialize();
    if (mh_status != MH_OK)
    {
        throw runtime_error(string("Error initializing MinHook: ") + MH_StatusToString(mh_status));
    }
}

void modutils::deinitialize()
{
    MH_Uninitialize();
}

uintptr_t modutils::impl::scan_memory(uintptr_t address, const std::string &aob)
{
    if (!address)
    {
        address = (uintptr_t)memory.data();
    }

    if (!aob.empty())
    {
        ptrdiff_t size = (uintptr_t)&memory.back() - address;
        address = (uintptr_t)Pattern16::scan((void *)address, size, aob);
    }

    return address;
}

uintptr_t modutils::impl::apply_offsets(
    uintptr_t address, ptrdiff_t offset,
    const modutils::scanopts::relative_offsets_type &relative_offsets)
{
    if (address)
    {
        address += offset;

        for (auto [first, second] : relative_offsets)
        {
            ptrdiff_t offset = *reinterpret_cast<int *>(address + first) + second;
            address += offset;
        }
    }

    return address;
}

uintptr_t modutils::impl::scan(const scanopts &opts)
{
    auto result = scan_memory((uintptr_t)opts.address, opts.aob);
    return apply_offsets(result, opts.offset, opts.relative_offsets);
}

void modutils::impl::hook(void *function, void *detour, void **trampoline)
{
    auto mh_status = MH_CreateHook(function, detour, trampoline);
    if (mh_status != MH_OK)
    {
        throw runtime_error(string("Error creating hook: ") + MH_StatusToString(mh_status));
    }
    mh_status = MH_QueueEnableHook(function);
    if (mh_status != MH_OK)
    {
        throw runtime_error(string("Error queueing hook: ") + MH_StatusToString(mh_status));
    }
}

void modutils::enable_hooks()
{
    auto mh_status = MH_ApplyQueued();
    if (mh_status != MH_OK)
    {
        throw runtime_error(string("Error enabling hooks: ") + MH_StatusToString(mh_status));
    }
}

//-----------------------------------------------------------------------------
static std::vector<HANDLE> PauseAllThreads()
{
    // Get a snapshot of all threads in the process
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) 
    {
        throw runtime_error(string("Failed to create thread snapshot."));
    }

    // Pause all threads in the current process except the calling thread
    DWORD currentThreadId = GetCurrentThreadId();
    THREADENTRY32 threadEntry;
    threadEntry.dwSize = sizeof(THREADENTRY32);

    std::vector<HANDLE> pausedThreads;
    if (Thread32First(hSnapshot, &threadEntry)) {
        do {
            if (threadEntry.th32OwnerProcessID == GetCurrentProcessId() && threadEntry.th32ThreadID != currentThreadId) 
            {
                HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, threadEntry.th32ThreadID);
                if (hThread) 
                {
                    SuspendThread(hThread);
                    pausedThreads.push_back(hThread);
                }
            }
        } while (Thread32Next(hSnapshot, &threadEntry));
    }

    CloseHandle(hSnapshot);
    return pausedThreads;
}

static void ResumeAllThreads(std::vector<HANDLE> pausedThreads)
{
    for (HANDLE hThread : pausedThreads) 
    {
        ResumeThread(hThread);
        CloseHandle(hThread);
    }
}

bool modutils::ReadMemoryWithThreadControl(LPVOID address, SIZE_T size, std::vector<BYTE>& buffer) 
{
    buffer.resize(size);
    std::vector<HANDLE> pausedThreads = PauseAllThreads();

    // Adjust memory protection to allow reading
    DWORD oldProtect;
    if (!VirtualProtect(address, size, PAGE_EXECUTE_READWRITE, &oldProtect)) 
    {
        SPDLOG_ERROR("Failed to change memory protection.");
        ResumeAllThreads(pausedThreads);
        return false;
    }

    // Read memory
    SIZE_T bytesRead;
    if (!ReadProcessMemory(GetCurrentProcess(), address, buffer.data(), size, &bytesRead) || bytesRead != size) 
    {
        SPDLOG_ERROR("Failed to read memory.");
        VirtualProtect(address, size, oldProtect, &oldProtect);
        ResumeAllThreads(pausedThreads);
        return false;
    }

    // Restore original memory protection
    VirtualProtect(address, size, oldProtect, &oldProtect);
    ResumeAllThreads(pausedThreads);

    return true;
}

//-----------------------------------------------------------------------------
bool modutils::WriteMemoryWithThreadControl(LPVOID address, SIZE_T size, const unsigned char *data) 
{
    std::vector<HANDLE> pausedThreads = PauseAllThreads();

    // Adjust memory protection to allow writing
    DWORD oldProtect;
    if (!VirtualProtect(address, size, PAGE_EXECUTE_READWRITE, &oldProtect)) 
    {
        SPDLOG_ERROR("Failed to change memory protection.");
        ResumeAllThreads(pausedThreads);
        return false;
    }

    // Write memory
    SIZE_T bytesWritten;
    if (!WriteProcessMemory(GetCurrentProcess(), address, data, size, &bytesWritten) || bytesWritten != size) 
    {
        SPDLOG_ERROR("Failed to write memory.");
        VirtualProtect(address, size, oldProtect, &oldProtect);
        ResumeAllThreads(pausedThreads);
        return false;
    }

    // Restore original memory protection
    VirtualProtect(address, size, oldProtect, &oldProtect);
    FlushInstructionCache(GetCurrentProcess(), address, size);
    ResumeAllThreads(pausedThreads);

    return true;
}
