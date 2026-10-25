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
        std::set<std::string> records;
        std::set<std::string> administrative_groups = {"sudo", "wheel", "admin"};
        std::vector<std::pair<std::string, gid_t>> groups;

        setgrent();
        while(const auto* group_entry = getgrent())
        {
            const std::string group_name = group_entry->gr_name ? group_entry->gr_name : "";
            groups.emplace_back(group_name, group_entry->gr_gid);

            if(administrative_groups.contains(group_name))
            {
                if(group_entry->gr_mem)
                {
                    for(char** member = group_entry->gr_mem; *member; ++member)
                        records.insert(std::format("ADMIN_GROUP|{}|{}", group_name, *member));
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
                if(account->pw_gid == gid && administrative_groups.contains(group_name))
                    records.insert(std::format("ADMIN_GROUP|{}|{}", group_name, username));
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
                    records.insert(std::format("SUDO_POLICY|{}:{}|{}", path.string(), line_number, line));
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
                records.insert(std::format("CAPABILITY|{}", line.substr(first)));
        }

        LOG_INFO(std::format("Found {} file capability entries.\n", capability_lines.size()));

        return {records.begin(), records.end()};
    }

    void privileges_manager::update_snapshot()
    {
        std::error_code error;
        std::filesystem::create_directories(data_dir, error);

        if(error)
            throw loompa_exception(std::format("Failed to create privilege data directory {}: {}\n", data_dir.string(), error.message()));

        const auto current_records = collect_privileges();

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

            return;
        }

        std::istringstream previous_stream(utils::file_system::read_entire_file(snapshot_path));
        std::set<std::string> previous_records;
        std::string line;

        while(std::getline(previous_stream, line))
        {
            if(!line.empty())
                previous_records.insert(line);
        }
            
        const std::set<std::string> current_set(current_records.begin(), current_records.end());
        std::ofstream changes_output(changes_path, std::ios::app);

        if(!changes_output)
            throw loompa_exception(std::format("Failed to open privilege change database {}.\n", changes_path.string()));

        const auto timestamp = static_cast<long long>(std::time(nullptr));

        for(const auto& record : current_set)
        {
            if(!previous_records.contains(record))
                changes_output << timestamp << "\tHIGH\tADDED\t" << record << '\n';
        }

        for(const auto& record : previous_records)
        {
            if(!current_set.contains(record))
                changes_output << timestamp << "\tMEDIUM\tREMOVED\t" << record << '\n';
        }

        changes_output.close();

        if(!changes_output)
            throw loompa_exception("Failed to update privilege change database.\n");

        std::ofstream snapshot_output(snapshot_path, std::ios::trunc);

        for(const auto& record : current_records)
            snapshot_output << record << '\n';

        if(!snapshot_output)
            throw loompa_exception("Failed to update privilege snapshot.\n");
    }

    void privileges_manager::list() const
    {
        std::istringstream input(utils::file_system::read_entire_file(snapshot_path));
        std::vector<std::vector<std::string>> rows;
        std::string line;

        while(std::getline(input, line))
        {
            const auto first = line.find('|');

            if(first == std::string::npos)
                continue;

            const auto second = line.find('|', first + 1);

            rows.push_back({line.substr(0, first), line.substr(first + 1, second == std::string::npos ? second : second - first - 1),
                second == std::string::npos ? "" : line.substr(second + 1)});
        }

        static const std::vector<std::string> headers = {"Privilege Type", "Account / Source", "Details"};

        utils::table::print_table(headers, rows);
    }

    void privileges_manager::check(std::string_view username) const
    {
        const std::string username_string(username);
        const passwd* account = getpwnam(username_string.c_str());

        if(!account)
            throw loompa_exception(std::format("Unknown user: {}\n", username));

        std::set<std::string> user_groups;

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
                user_groups.insert(group_entry->gr_name ? group_entry->gr_name : "");
        }

        endgrent();

        std::istringstream snapshot(utils::file_system::read_entire_file(snapshot_path));
        std::unordered_map<std::string, std::vector<std::string>> user_aliases;
        std::string line;

        while(std::getline(snapshot, line))
        {
            if(!line.starts_with("SUDO_POLICY|"))
                continue;

            const auto second = line.find('|', line.find('|') + 1);

            if(second == std::string::npos)
                continue;

            const std::string rule = line.substr(second + 1);

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

        const auto matches_subject = [&](auto&& self, const std::string& subject, std::set<std::string>& visited) -> bool 
        {
            if(subject == username || subject == "ALL")
                return true;

            if(subject.starts_with('%') && user_groups.contains(subject.substr(1)))
                return true;

            const auto alias = user_aliases.find(subject);

            if(alias == user_aliases.end() || !visited.insert(subject).second)
                return false;

            for(const auto& member : alias->second)
            {
                if(self(self, member, visited))
                    return true;
            }
                
            return false;
        };

        snapshot.clear();
        snapshot.seekg(0);

        std::vector<std::string> matches;

        while(std::getline(snapshot, line))
        {
            if(line.starts_with("ADMIN_GROUP|"))
            {
                const auto last = line.rfind('|');

                if(last != std::string::npos && line.substr(last + 1) == username)
                    matches.push_back(line);
            }

            else if(line.starts_with("SUDO_POLICY|"))
            {
                const auto first = line.find('|');
                const auto second = line.find('|', first + 1);

                if(second == std::string::npos)
                    continue;

                const std::string rule = line.substr(second + 1);
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

                    std::set<std::string> visited;

                    if(matches_subject(matches_subject, subject, visited))
                    {
                        matches.push_back(line);
                        break;
                    }
                }
            }
        }

        static const std::vector<std::string> headers = {"Configured Access"};
        std::vector<std::vector<std::string>> rows;

        for(const auto& group : user_groups)
        {
            if(group == "sudo" || group == "wheel" || group == "admin")
                rows.push_back({std::format("Member of administrative group {}", group)});
        }
            
        for(const auto& match : matches)
            rows.push_back({match});

        if(rows.empty())
            rows.push_back({"No configured sudo or administrative-group access detected"});

        utils::table::print_table(headers, rows);

        LOG_INFO(std::format("Checked configured privileges for {}.\n", username));
    }

    void privileges_manager::sudo(std::string_view username) const
    {
        check(username);

        static const std::vector<std::string> headers = {"Recorded sudo activity"};
        std::vector<std::vector<std::string>> rows;
        const std::vector<std::filesystem::path> log_paths = {"/var/log/auth.log", "/var/log/secure"};

        for(const auto& path : log_paths)
        {
            std::ifstream input(path);
            std::string line;

            while(std::getline(input, line))
            {
                const auto pos = line.find("sudo");

                if(pos != std::string::npos &&
                    (line.find("sudo: " + std::string(username) + " ", pos) != std::string::npos ||
                     line.find("USER=" + std::string(username), pos) != std::string::npos ||
                     line.find("user=" + std::string(username), pos) != std::string::npos))
                    rows.push_back({line});
            }
        }

        if(rows.empty())
            rows.push_back({"No matching activity found in readable auth.log or secure files"});

        utils::table::print_table(headers, rows);
    }

    void privileges_manager::changes(std::string_view since, std::string_view severity) const
    {
        size_t severity_level = 0;
        std::string normalized_severity(severity);
        std::transform(normalized_severity.begin(), normalized_severity.end(), normalized_severity.begin(), [](unsigned char c) { return std::toupper(c); });

        if(normalized_severity == "LOW") severity_level = 1;
        else if(normalized_severity == "MEDIUM") severity_level = 2;
        else if(normalized_severity == "HIGH") severity_level = 3;
        else if(normalized_severity == "CRITICAL") severity_level = 4;
        else throw loompa_exception(std::format("Unknown severity level: {}. Use LOW, MEDIUM, HIGH, or CRITICAL.\n", severity));

        std::string since_value(since);

        if(since_value.empty())
            throw loompa_exception("privileges changes requires --since TIME.\n");

        const std::time_t since_timestamp = utils::time::parse_time(since_value);

        std::istringstream input(utils::file_system::read_entire_file(changes_path));
        std::vector<std::vector<std::string>> rows;
        std::string line;

        while(std::getline(input, line))
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
        if(command != "list" && command != "check" && command != "sudo" && command != "changes")
            throw loompa_exception(std::format("Unknown privileges subcommand: {}\n", command));

        update_snapshot();

        if(command == "list")
            list();
        else if(command == "check" || command == "sudo")
        {
            if(argc == 0)
                throw loompa_exception(std::format("No username provided for privileges {}.\n", command));
            const std::string_view username = utils::string_view::shift_args(argc, argv);
            if(command == "check")
                check(username);
            else
                sudo(username);
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

            if(severity.empty())
                throw loompa_exception("privileges changes requires --severity LEVEL.\n");
            changes(since, severity);
        }
        
        else
            throw loompa_exception(std::format("Unknown privileges subcommand: {}\n", command));
    }
}
