#include "user.hpp"
#include "app.hpp"
#include "utils.hpp"

namespace loompa
{
    std::vector<utmpx> user_manager::read_login_records(const char* path) const
    {
        const std::string data = utils::file_system::read_entire_file(path);

        if(data.size() % sizeof(utmpx) != 0)
            throw loompa_exception(std::format("Login record file has an incomplete record: {}\n", path));

        std::vector<utmpx> records(data.size() / sizeof(utmpx));

        for(size_t i = 0; i < records.size(); ++i)
            std::memcpy(&records[i], data.data() + i * sizeof(utmpx), sizeof(utmpx));

        return records;
    }

    std::string user_manager::field_string(const char* field, size_t size) const {
        return std::string(field, strnlen(field, size));
    }

    std::string user_manager::format_login_time(std::time_t timestamp) const
    {
        std::tm local_time{};

        if(!localtime_r(&timestamp, &local_time))
            return "Unknown";

        std::ostringstream output;

        output << std::put_time(&local_time, "%Y-%m-%d %H:%M:%S");

        return output.str();
    }

    std::time_t user_manager::parse_time_filter(std::string_view value, bool end_of_day) const
    {
        std::string expression(value);

        if(expression.size() > 1 && std::isdigit(static_cast<unsigned char>(expression[expression.size() - 2])))
        {
            const char unit = expression.back();

            const std::string_view amount(expression.data(), expression.size() - 1);
            std::string unit_name;

            switch(unit)
            {
                case 's': unit_name = "second"; break;
                case 'm': unit_name = "minute"; break;
                case 'h': unit_name = "hour"; break;
                case 'd': unit_name = "day"; break;
                case 'w': unit_name = "week"; break;
                default: break;
            }

            size_t amount_value{};
            const auto [amount_end, amount_error] = std::from_chars(amount.data(), amount.data() + amount.size(), amount_value);

            if(!unit_name.empty() && amount_error == std::errc{} && amount_end == amount.data() + amount.size())
                expression = std::format("{} {}{} ago", amount_value, unit_name, amount_value == 1 ? "" : "s");
        }

        bool date_only = expression.size() == 10 && expression[4] == '-' && expression[7] == '-';

        for(size_t i = 0; date_only && i < expression.size(); ++i)
        {
            if(i != 4 && i != 7 && !std::isdigit(static_cast<unsigned char>(expression[i])))
                date_only = false;
        }

        if(end_of_day && date_only)
            expression += " 23:59:59";

        int output_pipe[2];

        if(pipe(output_pipe) == -1)
            throw loompa_exception(std::format("Failed to create date parser pipe: {}\n", std::strerror(errno)));

        const pid_t child = fork();

        if(child == -1)
        {
            close(output_pipe[0]);
            close(output_pipe[1]);

            throw loompa_exception(std::format("Failed to start date parser: {}\n", std::strerror(errno)));
        }

        if(child == 0)
        {
            close(output_pipe[0]);

            if(dup2(output_pipe[1], STDOUT_FILENO) == -1)
                _exit(127);

            close(output_pipe[1]);

            const int null_device = open("/dev/null", O_WRONLY);

            if(null_device != -1)
            {
                dup2(null_device, STDERR_FILENO);
                close(null_device);
            }

            const std::string date_argument = "--date=" + expression;

            execlp("date", "date", date_argument.c_str(), "+%s", static_cast<char*>(nullptr));
            _exit(127);
        }

        close(output_pipe[1]);

        char output[64]{};
        size_t output_size = 0;

        while(output_size < sizeof(output) - 1)
        {
            const ssize_t count = read(output_pipe[0], output + output_size, sizeof(output) - 1 - output_size);

            if(count > 0)
                output_size += static_cast<size_t>(count);

            else if(count == -1 && errno == EINTR)
                continue;

            else
                break;
        }

        close(output_pipe[0]);

        int status{};

        while(waitpid(child, &status, 0) == -1)
        {
            if(errno != EINTR)
                throw loompa_exception(std::format("Failed to wait for date parser: {}\n", std::strerror(errno)));
        }

        size_t output_length = output_size;

        if(output_length > 0 && output[output_length - 1] == '\n')
            --output_length;

        std::time_t timestamp{};
        const auto [parsed_end, parse_error] = std::from_chars(output, output + output_length, timestamp);
        
        if(!WIFEXITED(status) || WEXITSTATUS(status) != 0 || parse_error != std::errc{} || parsed_end != output + output_length)
            throw loompa_exception(std::format("Invalid date/time: {}\n", value));

        return timestamp;
    }

    size_t user_manager::parse_limit(std::string_view value) const
    {
        size_t limit{};
        const auto [end, error] = std::from_chars(value.data(), value.data() + value.size(), limit);

        if(error != std::errc{} || end != value.data() + value.size())
            throw loompa_exception(std::format("Invalid limit: {}\n", value));

        return limit;
    }

    bool user_manager::in_time_range(std::time_t timestamp, std::time_t since, std::time_t until) const {
        return timestamp >= since && timestamp <= until;
    }

    const user* user_manager::find_user(const std::string_view& username) const
    {
        std::string user_str(username);
        auto it = users.find(user_str);

        if(it == users.end())
            throw loompa_exception(std::format("Unknown user: {}\n", user_str));

        return &it->second;
    }

    const group* user_manager::find_group(const std::string_view& group_name) const
    {
        std::string group_str(group_name);
        const auto it = groups.find(group_str);

        if(it == groups.end())
            throw loompa_exception(std::format("Unknown group: {}\n", group_name));

        return &it->second;
    }

    void user_manager::list_users() const
    {
        const std::vector<std::string> headers = {"Username", "UID", "GID", "Home", "Shell"};

        std::vector<std::vector<std::string>> rows;

        rows.reserve(users.size());

        for(const auto& [name, account] : users)
            rows.push_back({name, std::to_string(account.uid), std::to_string(account.gid), account.home, account.shell});

        std::sort(rows.begin(), rows.end(), [](const auto& a, const auto& b) {
            return a[0] < b[0];
        });

        utils::table::print_table(headers, rows);

        LOG_INFO(std::format("Listed {} users.\n", rows.size()));
    }

    void user_manager::show_user(const std::string_view &user)
    {
        auto account = find_user(user);

        std::string groups;

        for(const auto& group : account->groups)
        {
            if(!groups.empty())
                groups += ", ";

            groups += group;
        }

        static const std::vector<std::string> headers = {"Property", "Value"};

        const std::vector<std::vector<std::string>> rows = 
        {
            {"Username",    account->username},
            {"UID",         std::to_string(account->uid)},
            {"GID",         std::to_string(account->gid)},
            {"GECOS",       account->gecos},
            {"Home",        account->home},
            {"Shell",       account->shell},
            {"Groups",      groups}
        };

        utils::table::print_table(headers, rows);
        LOG_INFO(std::format("Displayed user {}.\n", user));
    }

    void user_manager::show_groups(const std::string_view &group_name)
    {
        static const std::vector<std::string> headers = {"Username"};

        const auto* group_entry = find_group(group_name);
        std::vector<std::vector<std::string>> rows;

        for(const auto& [username, account] : users)
        {
            const bool primary = account.gid == group_entry->gid;
            const bool supplementary = std::find(group_entry->members.begin(), group_entry->members.end(), username) != group_entry->members.end();

            if(primary || supplementary)
                rows.push_back({username});
        }

        std::sort(rows.begin(), rows.end(), [](const auto& a, const auto& b) {
            return a[0] < b[0];
        });

        utils::table::print_table(headers, rows);
        LOG_INFO(std::format("Displayed {} members of group {}.\n", rows.size(), group_name));
    }

    void user_manager::show_history(const std::string_view &user, const std::string_view &since, const std::string_view &until, const std::string_view &limit)
    {
        std::time_t since_time = std::numeric_limits<std::time_t>::lowest();
        std::time_t until_time = std::numeric_limits<std::time_t>::max();
        size_t max_rows = std::numeric_limits<size_t>::max();

        if(!since.empty())
            since_time = parse_time_filter(since, false);

        if(!until.empty())
            until_time = parse_time_filter(until, true);

        if(!limit.empty())
            max_rows = parse_limit(limit);

        const auto records = read_login_records("/var/log/wtmp");

        static const std::vector<std::string> headers = {"Username", "Terminal", "Remote Host", "Login Time", "Logout Time"};
        std::vector<std::vector<std::string>> rows;

        for(size_t i = 0; i < records.size(); ++i)
        {
            const auto& login = records[i];

            if(login.ut_type != USER_PROCESS || field_string(login.ut_user, sizeof(login.ut_user)) != user)
                continue;

            const std::time_t login_timestamp = login.ut_tv.tv_sec;

            if(!in_time_range(login_timestamp, since_time, until_time))
                continue;

            const std::string terminal = field_string(login.ut_line, sizeof(login.ut_line));
            std::string logout_time = "Still logged in";

            for(size_t j = i + 1; j < records.size(); ++j)
            {
                const auto& logout = records[j];

                if
                (
                    logout.ut_type == DEAD_PROCESS && logout.ut_pid == login.ut_pid && 
                    field_string(logout.ut_line, sizeof(logout.ut_line)) == terminal
                )
                {
                    logout_time = format_login_time(logout.ut_tv.tv_sec);
                    break;
                }
            }

            rows.push_back
            ({
                std::string(user),
                terminal,
                field_string(login.ut_host, sizeof(login.ut_host)),
                format_login_time(login_timestamp),
                logout_time
            });
        }

        std::reverse(rows.begin(), rows.end());

        if(rows.size() > max_rows)
            rows.resize(max_rows);

        utils::table::print_table(headers, rows);

        LOG_INFO(std::format("Displayed {} history records for {}.\n", rows.size(), user));
    }

    void user_manager::show_active_sesssions()
    {
        static const std::vector<std::string> headers = {"Username", "Terminal", "Remote Host", "Login Time"};
        std::vector<std::vector<std::string>> rows;

        setutxent();

        while(const auto* entry = getutxent())
        {
            if(entry->ut_type != USER_PROCESS)
                continue;

            const std::string username(entry->ut_user, strnlen(entry->ut_user, sizeof(entry->ut_user)));
            const std::string terminal(entry->ut_line, strnlen(entry->ut_line, sizeof(entry->ut_line)));
            const std::string remote_host(entry->ut_host, strnlen(entry->ut_host, sizeof(entry->ut_host)));

            const std::time_t login_timestamp = entry->ut_tv.tv_sec;
            std::tm login_time{};
            std::string formatted_time = "Unknown";

            if(localtime_r(&login_timestamp, &login_time))
            {
                std::ostringstream time_stream;

                time_stream << std::put_time(&login_time, "%Y-%m-%d %H:%M:%S");
                formatted_time = time_stream.str();
            }

            rows.push_back({username, terminal, remote_host, formatted_time});
        }

        endutxent();

        utils::table::print_table(headers, rows);
        
        LOG_INFO(std::format("Displayed {} active sessions.\n", rows.size()));
    }

    void user_manager::show_failed_logins(const std::string_view &since, const std::string_view &until, const std::string_view &limit)
    {
        std::time_t since_time = std::numeric_limits<std::time_t>::lowest();
        std::time_t until_time = std::numeric_limits<std::time_t>::max();
        size_t max_rows = std::numeric_limits<size_t>::max();

        if(!since.empty())
            since_time = parse_time_filter(since, false);

        if(!until.empty())
            until_time = parse_time_filter(until, true);

        if(!limit.empty())
            max_rows = parse_limit(limit);

        const auto records = read_login_records("/var/log/btmp");

        static const std::vector<std::string> headers = {"Username", "Terminal", "Remote Host", "Time"};
        std::vector<std::vector<std::string>> rows;

        for(const auto& record : records)
        {
            const std::string username = field_string(record.ut_user, sizeof(record.ut_user));

            if(username.empty())
                continue;

            const std::time_t timestamp = record.ut_tv.tv_sec;

            if(!in_time_range(timestamp, since_time, until_time))
                continue;

            rows.push_back
            ({
                username,
                field_string(record.ut_line, sizeof(record.ut_line)),
                field_string(record.ut_host, sizeof(record.ut_host)),
                format_login_time(timestamp)
            });
        }

        std::reverse(rows.begin(), rows.end());

        if(rows.size() > max_rows)
            rows.resize(max_rows);

        utils::table::print_table(headers, rows);

        LOG_INFO(std::format("Displayed {} failed login records.\n", rows.size()));
    }

    user_manager::user_manager()
    {
        LOG_INFO("Loading groups and users.\n");

        setgrent();

        while(const auto* entry = getgrent())
        {
            group item;

            item.name   = entry->gr_name ? entry->gr_name : "";
            item.gid    = entry->gr_gid;

            if(entry->gr_mem)
            {
                for(char** member = entry->gr_mem; *member; ++member)
                    item.members.emplace_back(*member);
            }

            groups.try_emplace(item.name, std::move(item));
        }

        endgrent();

        setpwent();

        while(auto* entry = getpwent())
        {
            user u;

            u.username    = entry->pw_name ? entry->pw_name : "";
            u.gecos       = entry->pw_gecos ? entry->pw_gecos : "";
            u.home        = entry->pw_dir ? entry->pw_dir : "";
            u.shell       = entry->pw_shell ? entry->pw_shell : "";
            u.uid         = entry->pw_uid;
            u.gid         = entry->pw_gid;

            users.try_emplace(u.username, std::move(u));
        }
        
        endpwent();

        for(auto& [username, account] : users)
        {
            for(const auto& [groupname, group_entry] : groups)
            {
                const bool primary = group_entry.gid == account.gid;
                const bool supplementary = std::find(group_entry.members.begin(), group_entry.members.end(), username) != group_entry.members.end();

                if(primary || supplementary)
                    account.groups.emplace_back(groupname);
            }

            std::sort(account.groups.begin(), account.groups.end());
            account.groups.erase(std::unique(account.groups.begin(), account.groups.end()), account.groups.end());
        }

        LOG_INFO(std::format("Loaded {} users and {} groups.\n", users.size(), groups.size()));
    }

    void user_manager::parse_user_options(int argc, char** argv)
    {
        std::string_view arg = utils::string_view::shift_args(argc, argv);
        
        LOG_INFO(std::format("Running user subcommand: {}.\n", arg));

        if(arg == "list")
            list_users();

        else if(arg == "show")
        {
            if(argc == 0)
            {
                throw loompa_exception("No username provided to show.");
            }

            show_user(utils::string_view::shift_args(argc, argv));
        }

        else if(arg == "groups")
        {
            if(argc == 0)
            {
                throw loompa_exception("No group name provided.\n");
            }

            show_groups(utils::string_view::shift_args(argc, argv));
        }

        else if(arg == "sessions")
            show_active_sesssions();

        else if(arg == "history")
        {
            if(argc == 0)
            {
                throw loompa_exception("No username provided for history.");
            }

            std::string_view username = utils::string_view::shift_args(argc, argv);

            std::string_view since;
            std::string_view until;
            std::string_view limit;

            while(argc > 0)
            {
                std::string_view option = utils::string_view::shift_args(argc, argv);

                if(option == "--since")
                {
                    if(argc == 0)
                    {
                        throw loompa_exception("No argument provided for --since.");
                    }

                    since = utils::string_view::shift_args(argc, argv);
                }

                if(option == "--until")
                {
                    if(argc == 0)
                    {
                        throw loompa_exception("No argument provided for --until.");
                    }

                    until = utils::string_view::shift_args(argc, argv);
                }

                if(option == "--limit")
                {
                    if(argc == 0)
                    {
                        throw loompa_exception("No argument provided for --limit.");
                    }

                    limit = utils::string_view::shift_args(argc, argv);
                }
            }

            show_history(username, since, until, limit);
        }

        else if(arg == "failed-logins")
        {
            std::string_view since;
            std::string_view until;
            std::string_view limit;

            while(argc > 0)
            {
                std::string_view option = utils::string_view::shift_args(argc, argv);

                if(option == "--since")
                {
                    if(argc == 0)
                    {
                        throw loompa_exception("No argument provided for --since.");
                    }

                    since = utils::string_view::shift_args(argc, argv);
                }

                if(option == "--until")
                {
                    if(argc == 0)
                    {
                        throw loompa_exception("No argument provided for --until.");
                    }

                    until = utils::string_view::shift_args(argc, argv);
                }

                if(option == "--limit")
                {
                    if(argc == 0)
                    {
                        throw loompa_exception("No argument provided for --limit.");
                    }

                    limit = utils::string_view::shift_args(argc, argv);
                }
            }

            show_failed_logins(since, until, limit);
        }

        else 
            throw loompa_exception(std::format("Unknown subcommand: {}\n", arg));
    }
}
