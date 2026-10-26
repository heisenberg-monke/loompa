#include "app.hpp"
#include "activity.hpp"
#include "utils.hpp"
#include "user.hpp"

namespace loompa
{
    bool login_failure::matches(std::time_t since, std::time_t until, std::string_view user) const
    {
        return timestamp >= since && timestamp <= until && (user.empty() || username == user);
    }

    bool login_failure::merge_duplicate(const login_failure& other)
    {
        if(timestamp != other.timestamp || username != other.username || origin != other.origin || evidence != other.evidence)
            return false;
        if(source.find(other.source) == std::string::npos)
            source += ", " + other.source;
        return true;
    }

    std::string login_failure::lowercase(std::string_view value)
    {
        std::string text(value);
        std::transform(text.begin(), text.end(), text.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        return text;
    }

    bool login_failure::is_failure(std::string_view message)
    {
        const auto text = lowercase(message);
        return text.find("failed password") != std::string::npos ||
            text.find("authentication failure") != std::string::npos ||
            text.find("failed login") != std::string::npos ||
            text.find("invalid password") != std::string::npos ||
            text.find("user unknown") != std::string::npos ||
            text.find("authentification failure") != std::string::npos ||
            (text.find("type=user_auth") != std::string::npos && text.find("res=failed") != std::string::npos);
    }

    std::string login_failure::summarize(std::string_view message)
    {
        const auto text = lowercase(message);
        if(text.find("failed password") != std::string::npos || text.find("invalid password") != std::string::npos)
            return "Password rejected";
        if(text.find("type=user_auth") != std::string::npos)
            return "Audit authentication failure";
        if(text.find("authentication failure") != std::string::npos || text.find("authentification failure") != std::string::npos)
            return "PAM authentication failure";
        if(text.find("user unknown") != std::string::npos)
            return "Unknown account";
        return "Login rejected";
    }

    std::string login_failure::extract_user(std::string_view message)
    {
        auto marker = message.find("user=");
        if(marker != std::string_view::npos)
        {
            const auto begin = marker + 5;
            const auto end = message.find_first_of(" ;,]", begin);
            if(begin < message.size())
                return std::string(message.substr(begin, end == std::string_view::npos ? end : end - begin));
        }
        marker = message.find("acct=\"");
        if(marker != std::string_view::npos)
        {
            const auto begin = marker + 6;
            const auto end = message.find('"', begin);
            if(begin < message.size())
                return std::string(message.substr(begin, end == std::string_view::npos ? end : end - begin));
        }
        marker = message.find("Failed password for ");
        if(marker != std::string_view::npos)
        {
            size_t begin = marker + 20;
            if(message.substr(begin, 13) == "invalid user ")
                begin += 13;
            const auto end = message.find(' ', begin);
            if(begin < message.size())
                return std::string(message.substr(begin, end == std::string_view::npos ? end : end - begin));
        }
        return "Unknown";
    }

    std::string login_failure::extract_origin(std::string_view message)
    {
        auto marker = message.find(" from ");
        if(marker != std::string_view::npos)
        {
            const auto begin = marker + 6;
            const auto end = message.find(' ', begin);
            if(begin < message.size())
                return std::string(message.substr(begin, end == std::string_view::npos ? end : end - begin));
        }
        marker = message.find("addr=");
        if(marker != std::string_view::npos)
        {
            const auto begin = marker + 5;
            const auto end = message.find_first_of(" ;,]\"", begin);
            if(begin < message.size())
                return std::string(message.substr(begin, end == std::string_view::npos ? end : end - begin));
        }
        marker = message.find("rhost=");
        if(marker != std::string_view::npos)
        {
            const auto begin = marker + 6;
            const auto end = message.find_first_of(" ;,]", begin);
            if(begin < message.size())
                return std::string(message.substr(begin, end == std::string_view::npos ? end : end - begin));
        }
        return "Unknown";
    }

    std::time_t login_failure::parse_syslog_time(std::string_view line)
    {
        std::tm parsed{};
        std::istringstream input(std::string(line.substr(0, std::min<size_t>(15, line.size()))));
        input >> std::get_time(&parsed, "%b %d %H:%M:%S");
        if(input.fail())
            return {};
        const auto now = std::time(nullptr);
        std::tm current{};
        localtime_r(&now, &current);
        parsed.tm_year = current.tm_year;
        auto timestamp = std::mktime(&parsed);
        if(timestamp > now + 86400)
        {
            parsed.tm_year -= 1;
            timestamp = std::mktime(&parsed);
        }
        return timestamp;
    }

    std::time_t login_failure::parse_audit_time(std::string_view line)
    {
        const auto marker = line.find("msg=audit(");
        if(marker == std::string_view::npos)
            return {};
        const auto begin = marker + 10;
        const auto end = line.find_first_of(".:)", begin);
        const auto finish = end == std::string_view::npos ? line.size() : end;
        long long timestamp{};
        const auto [parsed_end, error] = std::from_chars(line.data() + begin, line.data() + finish, timestamp);
        return error == std::errc{} && parsed_end == line.data() + finish ? static_cast<std::time_t>(timestamp) : std::time_t{};
    }

    std::string login_failure::json_field(std::string_view object, std::string_view key)
    {
        const std::string marker = std::format("\"{}\":\"", key);
        const auto begin = object.find(marker);
        if(begin == std::string_view::npos)
            return {};
        std::string value;
        bool escaped = false;
        for(size_t i = begin + marker.size(); i < object.size(); ++i)
        {
            const char c = object[i];
            if(escaped)
            {
                if(c == 'n') value.push_back('\n');
                else if(c == 'r') value.push_back('\r');
                else if(c == 't') value.push_back('\t');
                else value.push_back(c);
                escaped = false;
            }
            else if(c == '\\') escaped = true;
            else if(c == '"') break;
            else value.push_back(c);
        }
        return value;
    }

    bool login_failure::newest_first(const login_failure& left, const login_failure& right)
    {
        return left.timestamp > right.timestamp;
    }

    bool sudo_activity::matches(std::time_t since, std::time_t until, std::string_view user) const
    {
        return timestamp >= since && timestamp <= until && (user.empty() || username == user);
    }

    bool sudo_activity::merge_duplicate(const sudo_activity& other)
    {
        if(timestamp != other.timestamp || username != other.username || target_user != other.target_user || command != other.command)
            return false;
        if(source.find(other.source) == std::string::npos)
            source += ", " + other.source;
        return true;
    }

    bool sudo_activity::parse(std::string_view message, std::time_t time, std::string_view source, sudo_activity& result)
    {
        const auto command_marker = message.find("COMMAND=");
        if(command_marker == std::string_view::npos)
            return false;
        auto prefix_end = message.find(" :", 0);
        if(prefix_end == std::string_view::npos || prefix_end > command_marker)
            return false;

        auto username_start = message.find("sudo:");
        username_start = username_start == std::string_view::npos ? 0 : username_start + 5;
        auto username_end = prefix_end;
        while(username_start < username_end && std::isspace(static_cast<unsigned char>(message[username_start]))) ++username_start;
        while(username_end > username_start && std::isspace(static_cast<unsigned char>(message[username_end - 1]))) --username_end;
        if(username_start == username_end)
            return false;

        const auto target_marker = message.find("USER=");
        std::string target = "root";
        if(target_marker != std::string_view::npos)
        {
            const auto begin = target_marker + 5;
            const auto end = message.find_first_of(" ;,]", begin);
            if(begin < message.size())
                target = std::string(message.substr(begin, end == std::string_view::npos ? end : end - begin));
        }

        const auto command_start = command_marker + 8;
        auto command_end = message.find_first_of("\r\n", command_start);
        if(command_end == std::string_view::npos)
            command_end = message.size();
        while(command_end > command_start && std::isspace(static_cast<unsigned char>(message[command_end - 1]))) --command_end;
        if(command_start == command_end)
            return false;

        result = {time, std::string(message.substr(username_start, username_end - username_start)), target,
            std::string(message.substr(command_start, command_end - command_start)), std::string(source)};
        return true;
    }

    bool sudo_activity::newest_first(const sudo_activity& left, const sudo_activity& right)
    {
        return left.timestamp > right.timestamp;
    }

    activity_manager::activity_manager(const user_manager& user_data) : users(user_data) {}

    std::pair<std::time_t, std::time_t> activity_manager::parse_time_range(std::string_view since, std::string_view until) const
    {
        return {
            since.empty() ? std::numeric_limits<std::time_t>::lowest() : utils::time::parse_time(since),
            until.empty() ? std::numeric_limits<std::time_t>::max() : utils::time::parse_time(until, true)
        };
    }

    size_t activity_manager::parse_row_limit(std::string_view limit) const
    {
        return limit.empty() ? std::numeric_limits<size_t>::max() : utils::string_view::parse_limit(limit);
    }

    void activity_manager::add_failure(std::vector<login_failure>& events, login_failure event,
        std::time_t since, std::time_t until, std::string_view user) const
    {
        if(!event.matches(since, until, user))
            return;
        for(auto& existing : events)
            if(existing.merge_duplicate(event))
                return;
        events.push_back(std::move(event));
    }

    void activity_manager::add_sudo_activity(std::vector<sudo_activity>& events, sudo_activity event,
        std::time_t since, std::time_t until, std::string_view user) const
    {
        if(!event.matches(since, until, user))
            return;
        for(auto& existing : events)
            if(existing.merge_duplicate(event))
                return;
        events.push_back(std::move(event));
    }

    void activity_manager::status() const
    {
        size_t sessions = 0;
        setutxent();
        while(const auto* entry = getutxent())
            sessions += entry->ut_type == USER_PROCESS;
        endutxent();

        size_t processes = 0;
        std::error_code error;
        for(std::filesystem::directory_iterator it("/proc", error), end; !error && it != end; it.increment(error))
        {
            const std::string name = it->path().filename().string();
            if(!name.empty() && std::all_of(name.begin(), name.end(), [](unsigned char c) { return std::isdigit(c); }))
                ++processes;
        }

        const auto available = [](const char* path) { return access(path, R_OK) == 0 ? "Available" : "Unavailable / unreadable"; };
        static const std::vector<std::string> headers = {"Activity source", "Status / count"};
        const std::vector<std::vector<std::string>> rows = {
            {"Active sessions (utmpx)", std::to_string(sessions)},
            {"Running processes (/proc)", std::to_string(processes)},
            {"Successful login history (/var/log/wtmp)", available("/var/log/wtmp")},
            {"Failed login history (/var/log/btmp)", available("/var/log/btmp")},
            {"Sudo activity (/var/log/auth.log)", available("/var/log/auth.log")},
            {"Sudo activity (/var/log/secure)", available("/var/log/secure")}
        };
        utils::table::print_table(headers, rows);
        LOG_INFO("Displayed activity status.\n");
    }

    void activity_manager::logins(std::string_view since, std::string_view until, std::string_view limit, std::string_view user) const
    {
        const auto [start, finish] = parse_time_range(since, until);
        const auto maximum = parse_row_limit(limit);
        const auto records = utils::file_system::read_login_records("/var/log/wtmp");
        static const std::vector<std::string> headers = {"Time", "User", "Terminal", "Remote host", "Event"};
        std::vector<std::vector<std::string>> rows;
        for(const auto& entry : records)
        {
            if(entry.ut_type != USER_PROCESS)
                continue;
            const std::string name(entry.ut_user, strnlen(entry.ut_user, sizeof(entry.ut_user)));
            if(!user.empty() && name != user)
                continue;
            const auto timestamp = static_cast<std::time_t>(entry.ut_tv.tv_sec);
            if(timestamp < start || timestamp > finish)
                continue;
            rows.push_back({utils::time::format_time(timestamp), name.empty() ? "—" : name,
                std::string(entry.ut_line, strnlen(entry.ut_line, sizeof(entry.ut_line))),
                std::string(entry.ut_host, strnlen(entry.ut_host, sizeof(entry.ut_host))),
                "Session started"});
        }
        std::reverse(rows.begin(), rows.end());
        if(rows.size() > maximum) rows.resize(maximum);
        utils::table::print_table(headers, rows);
        LOG_INFO(std::format("Displayed {} successful login events.\n", rows.size()));
    }

    void activity_manager::failed_logins(std::string_view since, std::string_view until, std::string_view limit, std::string_view user) const
    {
        if(geteuid() != 0)
            throw loompa_exception("activity failed-logins requires root privileges; run it with sudo.\n");

        const auto [start, finish] = parse_time_range(since, until);
        const auto maximum = parse_row_limit(limit);
        std::vector<login_failure> events;

        std::error_code file_error;
        if(std::filesystem::exists("/var/log/btmp", file_error) && access("/var/log/btmp", R_OK) == 0)
        {
            for(const auto& entry : utils::file_system::read_login_records("/var/log/btmp"))
            {
                const std::string name(entry.ut_user, strnlen(entry.ut_user, sizeof(entry.ut_user)));
                const std::string terminal(entry.ut_line, strnlen(entry.ut_line, sizeof(entry.ut_line)));
                const std::string host(entry.ut_host, strnlen(entry.ut_host, sizeof(entry.ut_host)));
                add_failure(events, {entry.ut_tv.tv_sec, name.empty() ? "Unknown" : name,
                    host.empty() ? terminal : host,
                    std::format("Failed login record (terminal {}, pid {})", terminal, entry.ut_pid), "/var/log/btmp"},
                    start, finish, user);
            }
        }

        bool readable_auth_log = false;
        for(const std::filesystem::path path : {"/var/log/auth.log", "/var/log/secure", "/var/log/audit/audit.log"})
        {
            std::ifstream input(path);
            if(input && path != "/var/log/audit/audit.log")
                readable_auth_log = true;
            std::string line;
            while(std::getline(input, line))
            {
                const bool audit_record = line.find("type=USER_AUTH") != std::string::npos;
                const auto separator = line.find(": ");
                const std::string message = audit_record || separator == std::string::npos ? line : line.substr(separator + 2);
                if(!login_failure::is_failure(message))
                    continue;
                const auto timestamp = audit_record ? login_failure::parse_audit_time(line) : login_failure::parse_syslog_time(line);
                if(timestamp == 0)
                    continue;
                add_failure(events, {timestamp, login_failure::extract_user(message), login_failure::extract_origin(message),
                    login_failure::summarize(message), path.string()}, start, finish, user);
            }
        }

        std::vector<std::string> journal_lines;
        if(!readable_auth_log)
            utils::file_system::read_system_command(
                "journalctl --no-pager --output=json -n 10000 2>/dev/null",
                journal_lines);
        for(const auto& line : journal_lines)
        {
            const std::string message = login_failure::json_field(line, "MESSAGE");
            if(!login_failure::is_failure(message))
                continue;
            const std::string raw_timestamp = login_failure::json_field(line, "__REALTIME_TIMESTAMP");
            long long microseconds{};
            const auto [end, error] = std::from_chars(raw_timestamp.data(), raw_timestamp.data() + raw_timestamp.size(), microseconds);
            if(error != std::errc{} || end != raw_timestamp.data() + raw_timestamp.size())
                continue;
            const auto timestamp = static_cast<std::time_t>(microseconds / 1000000);
            const auto identifier = login_failure::json_field(line, "SYSLOG_IDENTIFIER");
            const auto source = identifier.empty() ? "system journal" : "journal: " + identifier;
            add_failure(events, {timestamp, login_failure::extract_user(message), login_failure::extract_origin(message),
                login_failure::summarize(message), source}, start, finish, user);
        }

        std::sort(events.begin(), events.end(), login_failure::newest_first);
        static const std::vector<std::string> headers = {"Time", "User", "Origin", "Failure", "Source"};
        std::vector<std::vector<std::string>> rows;
        for(const auto& entry : events)
            rows.push_back({utils::time::format_time(entry.timestamp), entry.username, entry.origin, entry.evidence, entry.source});
        if(rows.size() > maximum) rows.resize(maximum);
        utils::table::print_table(headers, rows);
        LOG_INFO(std::format("Displayed {} failed authentication records from btmp, auth logs, and the system journal.\n", rows.size()));
    }

    void activity_manager::sudo(std::string_view since, std::string_view until, std::string_view limit, std::string_view user) const
    {
        if(geteuid() != 0)
            throw loompa_exception("activity sudo requires root privileges to read system authentication logs; run it with sudo.\n");

        const auto [start, finish] = parse_time_range(since, until);
        const auto maximum = parse_row_limit(limit);
        std::vector<sudo_activity> events;
        for(const std::filesystem::path path : {"/var/log/auth.log", "/var/log/auth.log.1", "/var/log/secure", "/var/log/secure.1"})
        {
            std::ifstream input(path);
            std::string line;
            while(std::getline(input, line))
            {
                const auto sudo_marker = line.find("sudo");
                if(sudo_marker == std::string::npos)
                    continue;
                const auto message_marker = line.find(": ", sudo_marker);
                if(message_marker == std::string::npos)
                    continue;
                const std::string_view message(line.data() + message_marker + 2, line.size() - message_marker - 2);
                const auto timestamp = login_failure::parse_syslog_time(line);
                if(timestamp == 0)
                    continue;
                sudo_activity event;
                if(sudo_activity::parse(message, timestamp, path.string(), event))
                    add_sudo_activity(events, std::move(event), start, finish, user);
            }
        }

        std::string journal_command = "journalctl --no-pager --output=json --identifier=sudo --identifier=sudo_logsrvd";
        if(!since.empty())
            journal_command += std::format(" --since=@{}", static_cast<long long>(start));
        if(!until.empty())
            journal_command += std::format(" --until=@{}", static_cast<long long>(finish));
        journal_command += " 2>/dev/null";
        std::vector<std::string> journal_lines;
        utils::file_system::read_system_command(journal_command.c_str(), journal_lines);
        for(const auto& line : journal_lines)
        {
            const auto identifier = login_failure::json_field(line, "SYSLOG_IDENTIFIER");
            const auto comm = login_failure::json_field(line, "_COMM");
            if(identifier != "sudo" && identifier != "sudo_logsrvd" && comm != "sudo")
                continue;
            const auto message = login_failure::json_field(line, "MESSAGE");
            const auto raw_timestamp = login_failure::json_field(line, "__REALTIME_TIMESTAMP");
            long long microseconds{};
            const auto [end, error] = std::from_chars(raw_timestamp.data(), raw_timestamp.data() + raw_timestamp.size(), microseconds);
            if(error != std::errc{} || end != raw_timestamp.data() + raw_timestamp.size())
                continue;
            sudo_activity event;
            const auto timestamp = static_cast<std::time_t>(microseconds / 1000000);
            const auto source = "journal: " + identifier;
            if(sudo_activity::parse(message, timestamp, source, event))
                add_sudo_activity(events, std::move(event), start, finish, user);
        }

        std::sort(events.begin(), events.end(), sudo_activity::newest_first);
        static const std::vector<std::string> headers = {"Time", "Invoking user", "Target user", "Command", "Source"};
        std::vector<std::vector<std::string>> rows;
        for(const auto& entry : events)
            rows.push_back({utils::time::format_time(entry.timestamp), entry.username, entry.target_user, entry.command, entry.source});
        if(rows.size() > maximum) rows.resize(maximum);
        utils::table::print_table(headers, rows);
        LOG_INFO(std::format("Displayed {} sudo activity records.\n", rows.size()));
    }

    void activity_manager::processes(std::string_view user, std::string_view limit) const
    {
        const auto maximum = parse_row_limit(limit);
        static const std::vector<std::string> headers = {"PID", "User", "Process"};
        std::vector<std::vector<std::string>> rows;
        std::error_code error;
        for(std::filesystem::directory_iterator it("/proc", error), end; !error && it != end; it.increment(error))
        {
            const std::string pid = it->path().filename().string();
            if(pid.empty() || !std::all_of(pid.begin(), pid.end(), [](unsigned char c) { return std::isdigit(c); }))
                continue;
            std::ifstream status(it->path() / "status");
            std::string line;
            uid_t uid = static_cast<uid_t>(-1);
            while(std::getline(status, line))
            {
                if(line.starts_with("Uid:"))
                {
                    std::istringstream values(line.substr(4));
                    values >> uid;
                    break;
                }
            }
            const std::string name = users.username_for_uid(uid);
            if(!user.empty() && name != user)
                continue;
            std::error_code link_error;
            const auto executable = std::filesystem::read_symlink(it->path() / "exe", link_error);
            std::string process = link_error ? std::string{} : executable.filename().string();
            if(process.empty())
            {
                std::ifstream comm(it->path() / "comm");
                std::getline(comm, process);
            }
            rows.push_back({pid, name, process.empty() ? "[unknown]" : process});
        }
        std::sort(rows.begin(), rows.end(), [](const auto& left, const auto& right) {
            return std::stoull(left[0]) < std::stoull(right[0]);
        });
        if(rows.size() > maximum) rows.resize(maximum);
        utils::table::print_table(headers, rows);
        LOG_INFO(std::format("Displayed {} running processes.\n", rows.size()));
    }

    void activity_manager::parse_options(int argc, char** argv) const
    {
        if(argc == 0)
            throw loompa_exception("No activity subcommand provided.\n");
        const std::string_view command = utils::string_view::shift_args(argc, argv);
        if(command != "status" && command != "logins" && command != "failed-logins" && command != "sudo" && command != "processes")
            throw loompa_exception(std::format("Unknown activity subcommand: {}\n", command));

        std::string_view since, until, limit, user;
        while(argc > 0)
        {
            const std::string_view option = utils::string_view::shift_args(argc, argv);
            if(argc == 0)
                throw loompa_exception(std::format("No value supplied for {}.\n", option));
            const std::string_view value = utils::string_view::shift_args(argc, argv);
            if((option == "--since" || option == "--until") && (command == "logins" || command == "failed-logins" || command == "sudo"))
            {
                if(option == "--since") since = value;
                else until = value;
            }
            else if(option == "--limit" && command != "status") limit = value;
            else if(option == "--user" && command != "status") user = value;
            else throw loompa_exception(std::format("Unknown activity option: {}\n", option));
        }

        if(command == "status") status();
        else if(command == "logins") logins(since, until, limit, user);
        else if(command == "failed-logins") failed_logins(since, until, limit, user);
        else if(command == "sudo") sudo(since, until, limit, user);
        else processes(user, limit);
    }
}
