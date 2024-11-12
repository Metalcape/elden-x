#include <array>

namespace from
{

// There are many other options, I only care about the sort by type option
enum class menu_sort : unsigned int
{
    item_type_ascending = 0x80005141
};

size_t sort_index_all_items = 12;

namespace CS
{

class PlayerGameData
{
  public:
    virtual ~PlayerGameData() = default;

    unsigned char unk8[0xda];

    unsigned char max_reinforce_level;
};

class CSMenuSystemSaveLoad
{
  public:
    virtual ~CSMenuSystemSaveLoad() = default;

    unsigned char unk8[0x1438];

    std::array<menu_sort, 20> sorts;
};

class GameDataMan
{
  public:
    static GameDataMan *instance();

    virtual ~GameDataMan() = default;

    CS::PlayerGameData *player_game_data;

    unsigned char unk10[0x50];

    CS::CSMenuSystemSaveLoad *menu_system_save_load;
};

}
}