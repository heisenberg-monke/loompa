#pragma once

namespace loompa
{
    struct user
    {
        std::string username;
        std::string gecos;
        std::string home;
        std::string shell;
        std::vector<std::string> groups;
        uid_t uid;
        gid_t gid;
    };

    struct group 
    {
        std::string name;
        std::vector<std::string> members;
        gid_t gid;
    };

    class user_manager
    {
        std::unordered_map<std::string, user> users;
        std::unordered_map<std::string, group> groups;
        std::unordered_map<uid_t, std::string> usernames_by_uid;

        std::string field_string(const char* field, size_t size) const;

        const user* find_user(const std::string_view& username) const;
        const group* find_group(const std::string_view& group_name) const;

        void list_users() const;
        void show_user(const std::string_view& user);
        void show_groups(const std::string_view& group_name);
        void show_active_sesssions();

    public:

        user_manager();
        std::string username_for_uid(uid_t uid) const;
    
        void parse_user_options(int argc, char** argv);
    };
}
