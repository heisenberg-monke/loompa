#pragma once

namespace loompa
{
    struct group
    {
        std::string name;
        std::vector<std::string> members;
        int gid;

        group(std::string_view view);
        std::vector<std::string> to_row() const;
        static void print_groups(const std::vector<group>& groups);
    };
}