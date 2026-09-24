#include "user.hpp"
#include "group.hpp"

#include "utils.hpp"

int main()
{
    try {
        std::vector<loompa::user> users;
        std::vector<loompa::group> groups;
        std::unordered_set<std::string> priviledged_users;

        utils::read_system_command("getent passwd", users);
        utils::read_system_command("getent group", groups);

        for(const auto& u : users)
        {
            if(u.uid == 0)
                priviledged_users.insert(u.username);
        }

        for(const auto& g : groups)
        {
            if(g.name == "sudo" || g.name == "wheel")
            {
                for(const auto& member : g.members)
                    priviledged_users.insert(member);
            }
        }

        for(auto& u : users)
            u.privileged = priviledged_users.contains(u.username);

        loompa::user::print_users(users);
        loompa::group::print_groups(groups);
    }

    catch(const std::exception& e)
    {
        std::cerr << "[ERROR] " << e.what() << '\n';
        return 1;
    }
    
    return 0;
}