#pragma once

namespace loompa
{
    struct user
    {
        std::string username;
        std::string home;
        std::string shell;
        int uid;
        int gid;
        bool privileged;

        user(std::string_view view);
        
        std::vector<std::string> to_row() const;
        static void print_users(const std::vector<user>& users);
    };
}