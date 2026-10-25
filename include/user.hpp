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

        std::vector<utmpx> read_login_records(const char* path) const;
        std::string field_string(const char* field, size_t size) const;
        std::string format_login_time(std::time_t timestamp) const;
        std::time_t parse_time_filter(std::string_view value, bool end_of_day) const;
        size_t parse_limit(std::string_view value) const;
        bool in_time_range(std::time_t timestamp, std::time_t since, std::time_t until) const;

        const user* find_user(const std::string_view& username) const;
        const group* find_group(const std::string_view& group_name) const;

        void list_users() const;
        void show_user(const std::string_view& user);
        void show_groups(const std::string_view& group_name);
        void show_active_sesssions();
        void show_history(const std::string_view& user, const std::string_view& since, const std::string_view& until, const std::string_view& limit);
        void show_failed_logins(const std::string_view& since, const std::string_view& until, const std::string_view& limit);

    public:

        user_manager();
    
        void parse_user_options(int argc, char** argv);
    };
}
