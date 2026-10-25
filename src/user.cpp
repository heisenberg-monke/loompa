#include "user.hpp"
#include "app.hpp"
#include "utils.hpp"

namespace loompa
{
    std::string user_manager::field_string(const char* field, size_t size) const {
        return std::string(field, strnlen(field, size));
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
            rows.push_back({username, terminal, remote_host, utils::time::format_time(login_timestamp)});
        }

        endutxent();

        utils::table::print_table(headers, rows);
        
        LOG_INFO(std::format("Displayed {} active sessions.\n", rows.size()));
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
            usernames_by_uid.try_emplace(account.uid, username);
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

    std::string user_manager::username_for_uid(uid_t uid) const
    {
        const auto it = usernames_by_uid.find(uid);
        return it == usernames_by_uid.end() ? std::to_string(uid) : it->second;
    }

    void user_manager::parse_user_options(int argc, char** argv)
    {
        if(argc == 0)
            throw loompa_exception("No subcommand given.\n");

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

        else 
            throw loompa_exception(std::format("Unknown subcommand: {}\n", arg));
    }
}
