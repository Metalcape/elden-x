#pragma once
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winver.h>

#include <span>
#include <stdexcept>
#include <vector>

static std::span<unsigned char> memory;

namespace modutils
{

void initialize();
void enable_hooks();
void deinitialize();

struct scanopts
{
    typedef std::vector<std::pair<ptrdiff_t, ptrdiff_t>> relative_offsets_type;

    std::string aob;
    void *address;
    ptrdiff_t offset = 0;
    relative_offsets_type relative_offsets = {};
};

namespace impl
{
uintptr_t scan_memory(uintptr_t, const std::string &);
uintptr_t apply_offsets(uintptr_t, ptrdiff_t offset, const scanopts::relative_offsets_type &);
uintptr_t scan(const scanopts &opts);
void hook(void *function, void *detour, void **trampoline);
}

template <typename T> inline T *scan(const scanopts &opts)
{
    return reinterpret_cast<T *>(impl::scan(opts));
}

template <typename F> inline F *hook(const scanopts &opts, F &detour, F *&trampoline)
{
    auto function = scan<F>(opts);
    if (function == nullptr)
    {
        throw std::runtime_error("Failed to find original function address");
    }
    impl::hook(reinterpret_cast<void *>(function), reinterpret_cast<void *>(&detour),
               reinterpret_cast<void **>(&trampoline));
    return function;
}

bool ReadMemoryWithThreadControl(LPVOID address, SIZE_T size, std::vector<BYTE>& buffer);
bool WriteMemoryWithThreadControl(LPVOID address, SIZE_T size, const unsigned char *data);

template <typename FunctionType>
inline void read(std::vector<unsigned char> &bytes, FunctionType address, size_t length)
{
    auto offset = reinterpret_cast<LPVOID>(address);
    ReadMemoryWithThreadControl(offset, length, bytes);
}

template <typename FunctionType>
inline void write(const unsigned char *bytes, FunctionType address, size_t length)
{
    auto offset = reinterpret_cast<LPVOID>(address);
    WriteMemoryWithThreadControl(offset, length, bytes);
}

}