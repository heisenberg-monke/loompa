#pragma once

namespace loompa
{
    class privileges_manager
    {
        std::filesystem::path data_dir;
        std::filesystem::path snapshot_path;
        std::filesystem::path changes_path;
        std::unordered_map<std::string, std::string> privilege_records;
        std::vector<std::string> change_history;

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
