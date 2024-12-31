#include <elden-x/gameman.hpp>
#include <elden-x/utils/modutils.hpp>

#include <spdlog/spdlog.h>

static from::CS::GameMan **address = nullptr;

from::CS::GameMan *from::CS::GameMan::instance()
{
    if (!address)
    {
        address = modutils::scan<from::CS::GameMan *>({
            .aob = "48 8B 05 ?? ?? ?? ??"   // mov rax, qword ptr [GLOBAL_GameMan]
                   "80 B8 ?? ?? ?? ?? 0D"   // cmp byte ptr [rax + 0xd88], 0x0d
                   "0F 94 C0"               // setz al
                   "C3",                    // ret
            .relative_offsets = {{3, 7}},
        });

        if (!address)
        {
            SPDLOG_ERROR("Unable to find GameDataMan. Incompatible game version?");
            return nullptr;
        }
    }

    return *address;
}
