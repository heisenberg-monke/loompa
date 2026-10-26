#include "app.hpp"
#include "privileges.hpp"
#include "utils.hpp"

namespace loompa
{
    privileges_manager::privileges_manager()
        : data_dir(std::filesystem::path(PROJECT_ROOT) / "data"),
          snapshot_path(data_dir / "privileges.snapshot"),
          changes_path(data_dir / "privileges.changes") {}

    std::vector<std::string> privileges_manager::collect_privileges() const
    {
        std::vector<std::string> records;
        constexpr std::array<std::string_view, 3> administrative_groups = {"sudo", "wheel", "admin"};
        const auto is_administrative_group = [&](const std::string& name) {
            return std::find(administrative_groups.begin(), administrative_groups.end(), name) != administrative_groups.end();
        };
        std::vector<std::pair<std::string, gid_t>> groups;

        setgrent();
        while(const auto* group_entry = getgrent())
        {
            const std::string group_name = group_entry->gr_name ? group_entry->gr_name : "";
            groups.emplace_back(group_name, group_entry->gr_gid);

            if(is_administrative_group(group_name))
            {
                if(group_entry->gr_mem)
                {
                    for(char** member = group_entry->gr_mem; *member; ++member)
                        records.push_back(std::format("ADMIN_GROUP|{}|{}", group_name, *member));
                }
            }
        }
        endgrent();

        setpwent();
        while(const auto* account = getpwent())
        {
            const std::string username = account->pw_name ? account->pw_name : "";
            for(const auto& [group_name, gid] : groups)
            {
                if(account->pw_gid == gid && is_administrative_group(group_name))
                    records.push_back(std::format("ADMIN_GROUP|{}|{}", group_name, username));
            }
        }
        endpwent();

        std::vector<std::filesystem::path> sudoers_files;
        const std::filesystem::path sudoers = "/etc/sudoers";
        std::error_code status_error;

        if(std::filesystem::is_regular_file(sudoers, status_error))
            sudoers_files.push_back(sudoers);

        const std::filesystem::path sudoers_dir = "/etc/sudoers.d";
        std::error_code iterator_error;
        if(std::filesystem::is_directory(sudoers_dir, iterator_error))
        {
            for(std::filesystem::directory_iterator it(sudoers_dir, iterator_error), end; !iterator_error && it != end; it.increment(iterator_error))
            {
                std::error_code status_error;

                if(it->is_regular_file(status_error) && !it->path().filename().string().starts_with('.'))
                    sudoers_files.push_back(it->path());
            }
        }

        std::sort(sudoers_files.begin(), sudoers_files.end());

        for(const auto& path : sudoers_files)
        {
            std::ifstream input(path);
            std::string line;
            size_t line_number = 0;

            while(std::getline(input, line))
            {
                ++line_number;

                const auto comment = line.find('#');

                if(comment != std::string::npos)
                    line.resize(comment);

                const auto first = line.find_first_not_of(" \t\r");

                if(first == std::string::npos)
                    continue;

                const auto last = line.find_last_not_of(" \t\r");

                line = line.substr(first, last - first + 1);

                if(line.starts_with("Defaults") || line.find('=') != std::string::npos)
                    records.push_back(std::format("SUDO_POLICY|{}:{}|{}", path.string(), line_number, line));
            }
        }

        std::vector<std::string> capability_lines;

        LOG_INFO("Scanning standard executable and helper directories for file capabilities.\n");
        utils::file_system::read_system_command(
            "getcap -r /bin /sbin /usr/bin /usr/sbin /usr/lib /usr/lib64 /usr/libexec "
            "/usr/local/bin /usr/local/sbin /usr/local/libexec /opt 2>/dev/null",
            capability_lines);

        for(const auto& line : capability_lines)
        {
            const auto first = line.find_first_not_of(" \t");

            if(first != std::string::npos)
                records.push_back(std::format("CAPABILITY|{}", line.substr(first)));
        }

        LOG_INFO(std::format("Found {} file capability entries.\n", capability_lines.size()));

        std::sort(records.begin(), records.end());
        records.erase(std::unique(records.begin(), records.end()), records.end());
        return records;
    }

    void privileges_manager::update_snapshot()
    {
        std::error_code error;
        std::filesystem::create_directories(data_dir, error);

        if(error)
            throw loompa_exception(std::format("Failed to create privilege data directory {}: {}\n", data_dir.string(), error.message()));

        const auto current_records = collect_privileges();

        privilege_records.clear();
        for(const auto& record : current_records)
        {
            const auto separator = record.find('|');
            privilege_records.emplace(record, separator == std::string::npos ? "" : record.substr(0, separator));
        }

        std::string line;
        if(!std::filesystem::exists(snapshot_path))
        {
            std::ofstream initial(snapshot_path, std::ios::trunc);

            for(const auto& record : current_records)
                initial << record << '\n';

            if(!initial)
                throw loompa_exception("Failed to write initial privilege snapshot.\n");

            std::ofstream initial_changes(changes_path, std::ios::app);

            if(!initial_changes)
                throw loompa_exception("Failed to initialize privilege change database.\n");

            change_history.clear();
            std::istringstream history_input(utils::file_system::read_entire_file(changes_path));
            while(std::getline(history_input, line))
                if(!line.empty())
                    change_history.push_back(line);

            return;
        }

        std::istringstream previous_stream(utils::file_system::read_entire_file(snapshot_path));
        std::vector<std::string> previous_records;

        while(std::getline(previous_stream, line))
        {
            if(!line.empty())
                previous_records.push_back(line);
        }

        std::sort(previous_records.begin(), previous_records.end());
        previous_records.erase(std::unique(previous_records.begin(), previous_records.end()), previous_records.end());

        std::vector<std::string> added_records;
        std::vector<std::string> removed_records;
        std::set_difference(current_records.begin(), current_records.end(), previous_records.begin(), previous_records.end(), std::back_inserter(added_records));
        std::set_difference(previous_records.begin(), previous_records.end(), current_records.begin(), current_records.end(), std::back_inserter(removed_records));

        std::ofstream changes_output(changes_path, std::ios::app);

        if(!changes_output)
            throw loompa_exception(std::format("Failed to open privilege change database {}.\n", changes_path.string()));

        const auto timestamp = static_cast<long long>(std::time(nullptr));

        for(const auto& record : added_records)
            changes_output << timestamp << "\tHIGH\tADDED\t" << record << '\n';

        for(const auto& record : removed_records)
            changes_output << timestamp << "\tMEDIUM\tREMOVED\t" << record << '\n';

        changes_output.close();

        if(!changes_output)
            throw loompa_exception("Failed to update privilege change database.\n");

        std::ofstream snapshot_output(snapshot_path, std::ios::trunc);

        for(const auto& record : current_records)
            snapshot_output << record << '\n';

        if(!snapshot_output)
            throw loompa_exception("Failed to update privilege snapshot.\n");

        change_history.clear();
        if(std::filesystem::exists(changes_path))
        {
            std::istringstream history_input(utils::file_system::read_entire_file(changes_path));
            while(std::getline(history_input, line))
                if(!line.empty())
                    change_history.push_back(line);
        }
    }

    void privileges_manager::list() const
    {
        std::vector<std::vector<std::string>> rows;
        rows.reserve(privilege_records.size());

        for(const auto& [record, category] : privilege_records)
        {
            const auto first = record.find('|');

            if(first == std::string::npos)
                continue;

            const auto second = record.find('|', first + 1);

            rows.push_back({category, record.substr(first + 1, second == std::string::npos ? second : second - first - 1),
                second == std::string::npos ? "" : record.substr(second + 1)});
        }

        std::sort(rows.begin(), rows.end());
        static const std::vector<std::string> headers = {"Privilege Type", "Account / Source", "Details"};

        utils::table::print_table(headers, rows);
    }

    void privileges_manager::check(std::string_view username) const
    {
        const std::string username_string(username);
        const passwd* account = getpwnam(username_string.c_str());

        if(!account)
            throw loompa_exception(std::format("Unknown user: {}\n", username));

        std::vector<std::string> user_groups;

        setgrent();

        while(const auto* group_entry = getgrent())
        {
            bool member = group_entry->gr_gid == account->pw_gid;

            if(group_entry->gr_mem)
            {
                for(char** entry = group_entry->gr_mem; *entry; ++entry)
                    member = member || username == *entry;
            }

            if(member)
                user_groups.emplace_back(group_entry->gr_name ? group_entry->gr_name : "");
        }

        endgrent();

        std::sort(user_groups.begin(), user_groups.end());
        user_groups.erase(std::unique(user_groups.begin(), user_groups.end()), user_groups.end());

        std::unordered_map<std::string, std::vector<std::string>> user_aliases;

        for(const auto& [record, category] : privilege_records)
        {
            if(category != "SUDO_POLICY")
                continue;

            const auto second = record.find('|', record.find('|') + 1);

            if(second == std::string::npos)
                continue;

            const std::string rule = record.substr(second + 1);

            if(!rule.starts_with("User_Alias "))
                continue;

            const auto equals = rule.find('=');

            if(equals == std::string::npos)
                continue;

            const auto alias_begin = rule.find_first_not_of(" \t", 11);
            const auto alias_end = rule.find_last_not_of(" \t", equals - 1);

            if(alias_begin == std::string::npos || alias_end < alias_begin)
                continue;

            const std::string alias = rule.substr(alias_begin, alias_end - alias_begin + 1);
            std::istringstream members(rule.substr(equals + 1));
            std::string member;

            while(std::getline(members, member, ','))
            {
                const auto begin = member.find_first_not_of(" \t");
                const auto end = member.find_last_not_of(" \t");

                if(begin != std::string::npos)
                    user_aliases[alias].push_back(member.substr(begin, end - begin + 1));
            }
        }

        const auto matches_subject = [&](auto&& self, const std::string& subject, std::vector<std::string>& visited) -> bool
        {
            if(subject == username || subject == "ALL")
                return true;

            if(subject.starts_with('%') && std::find(user_groups.begin(), user_groups.end(), subject.substr(1)) != user_groups.end())
                return true;

            const auto alias = user_aliases.find(subject);

            if(alias == user_aliases.end() || std::find(visited.begin(), visited.end(), subject) != visited.end())
                return false;

            visited.push_back(subject);

            for(const auto& member : alias->second)
            {
                if(self(self, member, visited))
                    return true;
            }
                
            return false;
        };

        std::vector<std::string> matches;

        for(const auto& [record, category] : privilege_records)
        {
            if(category == "ADMIN_GROUP")
            {
                const auto last = record.rfind('|');

                if(last != std::string::npos && record.substr(last + 1) == username)
                    matches.push_back(record);
            }

            else if(category == "SUDO_POLICY")
            {
                const auto first = record.find('|');
                const auto second = record.find('|', first + 1);

                if(second == std::string::npos)
                    continue;

                const std::string rule = record.substr(second + 1);
                const auto equals = rule.find('=');
                const std::string subjects = rule.substr(0, equals);

                std::istringstream subject_stream(subjects);
                std::string subject;

                while(std::getline(subject_stream, subject, ','))
                {
                    const auto begin = subject.find_first_not_of(" \t");
                    const auto end = subject.find_last_not_of(" \t");

                    if(begin == std::string::npos)
                        continue;

                    subject = subject.substr(begin, end - begin + 1);

                    std::vector<std::string> visited;

                    if(matches_subject(matches_subject, subject, visited))
                    {
                        matches.push_back(record);
                        break;
                    }
                }
            }
        }

        static const std::vector<std::string> headers = {"Access path", "Source", "Configured entry"};
        std::vector<std::vector<std::string>> rows;

        if(account->pw_uid == 0)
            rows.push_back({"Root account", "UID 0", "Has root privileges when logged in as this account"});

        for(const auto& match : matches)
        {
            const auto first = match.find('|');
            const auto second = first == std::string::npos ? std::string::npos : match.find('|', first + 1);

            if(first == std::string::npos || second == std::string::npos)
                continue;

            const std::string category = match.substr(0, first);
            const std::string source = match.substr(first + 1, second - first - 1);
            const std::string detail = match.substr(second + 1);

            if(category == "ADMIN_GROUP")
                rows.push_back({"Administrative group", source, "User is a member of this group"});
            else if(category == "SUDO_POLICY")
                rows.push_back({"Sudoers rule", source, detail});
        }

        std::sort(rows.begin(), rows.end());

        if(rows.empty())
            rows.push_back({"No matching access", "Checked groups and sudoers", "No configured match was detected"});

        utils::table::print_table(headers, rows);

        LOG_INFO(std::format("Checked configured privileges for {}.\n", username));
    }

    void privileges_manager::changes(std::string_view since, std::string_view severity) const
    {
        size_t severity_level = 0;
        if(!severity.empty())
        {
            std::string normalized_severity(severity);
            std::transform(normalized_severity.begin(), normalized_severity.end(), normalized_severity.begin(), [](unsigned char c) { return std::toupper(c); });

            if(normalized_severity == "LOW") severity_level = 1;
            else if(normalized_severity == "MEDIUM") severity_level = 2;
            else if(normalized_severity == "HIGH") severity_level = 3;
            else if(normalized_severity == "CRITICAL") severity_level = 4;
            else throw loompa_exception(std::format("Unknown severity level: {}. Use LOW, MEDIUM, HIGH, or CRITICAL.\n", severity));
        }

        std::string since_value(since);
        const std::time_t since_timestamp = since_value.empty() ? std::numeric_limits<std::time_t>::lowest() : utils::time::parse_time(since_value);

        std::vector<std::vector<std::string>> rows;

        for(const auto& line : change_history)
        {
            std::istringstream fields(line);
            std::string timestamp_string, row_severity, action, record;

            if(!std::getline(fields, timestamp_string, '\t') || !std::getline(fields, row_severity, '\t') ||
                !std::getline(fields, action, '\t') || !std::getline(fields, record))
                continue;

            std::time_t timestamp{};
            const auto [timestamp_end, timestamp_error] = std::from_chars(timestamp_string.data(), timestamp_string.data() + timestamp_string.size(), timestamp);

            if(timestamp_error != std::errc{} || timestamp_end != timestamp_string.data() + timestamp_string.size() || timestamp < since_timestamp)
                continue;

            size_t row_level = row_severity == "LOW" ? 1 : row_severity == "MEDIUM" ? 2 : row_severity == "HIGH" ? 3 : 4;

            if(row_level < severity_level)
                continue;

            std::time_t event_time = static_cast<std::time_t>(timestamp);
            std::tm local_time{};
            std::string formatted = "Unknown";

            if(localtime_r(&event_time, &local_time))
            {
                char buffer[32]{};
                if(std::strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", &local_time))
                    formatted = buffer;
            }

            rows.push_back({formatted, row_severity, action, record});
        }

        static const std::vector<std::string> headers = {"Time", "Severity", "Change", "Privilege Record"};
        utils::table::print_table(headers, rows);
    }

    void privileges_manager::parse_options(int argc, char** argv)
    {
        if(argc == 0)
            throw loompa_exception("No privileges subcommand provided.\n");

        const std::string_view command = utils::string_view::shift_args(argc, argv);
        if(command != "list" && command != "check" && command != "changes")
            throw loompa_exception(std::format("Unknown privileges subcommand: {}\n", command));

        update_snapshot();

        if(command == "list")
            list();
        else if(command == "check")
        {
            if(argc == 0)
                throw loompa_exception(std::format("No username provided for privileges {}.\n", command));
            const std::string_view username = utils::string_view::shift_args(argc, argv);
            check(username);
        }
        else if(command == "changes")
        {
            std::string_view since, severity;
            while(argc > 0)
            {
                const std::string_view option = utils::string_view::shift_args(argc, argv);
                if(argc == 0)
                    throw loompa_exception(std::format("No value supplied for {}.\n", option));
                const std::string_view value = utils::string_view::shift_args(argc, argv);
                if(option == "--since")
                    since = value;
                else if(option == "--severity")
                    severity = value;
                else
                    throw loompa_exception(std::format("Unknown privileges changes option: {}\n", option));
            }

            changes(since, severity);
        }
        
        else
            throw loompa_exception(std::format("Unknown privileges subcommand: {}\n", command));
    }
}
