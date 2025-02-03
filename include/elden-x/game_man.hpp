#pragma once

namespace er
{
namespace CS
{

enum class ceremony_type : unsigned char
{
    none = 0
};

class GameMan
{
  public:
    static GameMan *instance();

    virtual ~GameMan() = default;   // +0x0 (vtable pointer)

    void *unk8;
    uint32_t quit_to_title_flag;
    uint32_t unk14;
    uint32_t mapId;
    uint32_t unk1c;
    unsigned char unk20[0xba8];
    bool is_in_online_mode;
    unsigned char unkbc9[0x27];
    ceremony_type ceremony_type;
    unsigned char unkbf1[0x28f];
};

static_assert(0x8 == __builtin_offsetof(GameMan, unk8));
static_assert(0x10 == __builtin_offsetof(GameMan, quit_to_title_flag));
static_assert(0x14 == __builtin_offsetof(GameMan, unk14));
static_assert(0x18 == __builtin_offsetof(GameMan, mapId));
static_assert(0x1C == __builtin_offsetof(GameMan, unk1c));
static_assert(0x20 == __builtin_offsetof(GameMan, unk20));
static_assert(0xbc8 == __builtin_offsetof(GameMan, is_in_online_mode));
static_assert(0xbc9 == __builtin_offsetof(GameMan, unkbc9));
static_assert(0xbf0 == __builtin_offsetof(GameMan, ceremony_type));
static_assert(0xbf1 == __builtin_offsetof(GameMan, unkbf1));
static_assert(0xe80 == sizeof(GameMan));

}
}
