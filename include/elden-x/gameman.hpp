#include <cstdint>

namespace from
{

namespace CS
{

class GameMan
{
    public:
        static GameMan * instance();

        virtual ~GameMan() = default;   // +0x0 (vtable pointer)

        void * unk8;                    // +0x8
        uint32_t quit_to_title_flag;    // +0x10
        uint32_t unk14;                 // +0x14
        uint32_t mapId;                 // +0x18
        uint32_t unk1c;                 // +0x1C
        unsigned char unk20[0xE60];     // +0x20 --> +0xE80 (end)

};

}
}