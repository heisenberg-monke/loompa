#pragma once

namespace loompa
{
    class user_manager;

    struct login_failure
    {
        static std::string lowercase(std::string_view value);

        std::time_t timestamp{};
        std::string username;
        std::string origin;
        std::string evidence;
        std::string source;

        bool matches(std::time_t since, std::time_t until, std::string_view user) const;
        bool merge_duplicate(const login_failure& other);
        static bool is_failure(std::string_view message);
        static std::string summarize(std::string_view message);
        static std::string extract_user(std::string_view message);
        static std::string extract_origin(std::string_view message);
        static std::time_t parse_syslog_time(std::string_view line);
        static std::time_t parse_audit_time(std::string_view line);
        static std::string json_field(std::string_view object, std::string_view key);
        static bool newest_first(const login_failure& left, const login_failure& right);
    };

    class activity_manager
    {
        const user_manager& users;
        std::pair<std::time_t, std::time_t> parse_time_range(std::string_view since, std::string_view until) const;
        size_t parse_row_limit(std::string_view limit) const;
        void add_failure(std::vector<login_failure>& events, login_failure event, std::time_t since, std::time_t until, std::string_view user) const;
        void status() const;
        void logins(std::string_view since, std::string_view until, std::string_view limit, std::string_view user) const;
        void failed_logins(std::string_view since, std::string_view until, std::string_view limit, std::string_view user) const;
        void sudo(std::string_view since, std::string_view until, std::string_view limit, std::string_view user) const;
        void processes(std::string_view user, std::string_view limit) const;

    public:
        explicit activity_manager(const user_manager& user_data);
        void parse_options(int argc, char** argv) const;
    };
}
