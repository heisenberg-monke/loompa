#include "group.hpp"
#include "utils.hpp"

namespace loompa
{
    static inline const std::vector<std::string> GROUP_HEADERS = {
        "Group",
        "GID",
        "Members"
    };

    group::group(std::string_view view)
    {
        name = utils::chop_by_delim(view, ':'); utils::chop_by_delim(view, ':');
        gid = std::stoi(std::string(utils::chop_by_delim(view, ':')));

        if(!view.empty())
        {
            while(true)
            {
                members.emplace_back(utils::chop_by_delim(view, ','));

                if(view.empty())
                    break;
            }
        }
    }

    std::vector<std::string> group::to_row() const
    {
        std::string list;

        for(size_t i = 0; i < members.size(); ++i)
        {
            if(i)
                list += ", ";

            list += members[i];
        }

        return {
            name,
            std::to_string(gid),
            list
        };
    }

    void group::print_groups(const std::vector<group>& groups)
    {
        std::vector<std::vector<std::string>> content;
        content.reserve(groups.size());

        for(const auto& g : groups)
            content.emplace_back(g.to_row());

        utils::print_table(GROUP_HEADERS, content);
    }
}