#pragma once

#include <filesystem>
#include <ctime>
#include <string>
#include <string_view>
#include <vector>

namespace loompa
{
    class privileges_manager
    {
        std::filesystem::path data_dir;
        std::filesystem::path snapshot_path;
        std::filesystem::path changes_path;

        std::vector<std::string> collect_privileges() const;
        void update_snapshot();
        void list() const;
        void check(std::string_view username) const;
        void sudo(std::string_view username) const;
        void changes(std::string_view since, std::string_view severity) const;

    public:
        privileges_manager();
        void parse_options(int argc, char** argv);
    };
}
