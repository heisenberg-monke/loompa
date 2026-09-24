#include "user.hpp"
#include "utils.hpp"

namespace loompa
{
    static inline const std::vector<std::string> USER_HEADERS = {
        "Username",
        "Home",
        "Shell",
        "UID",
        "GID",
        "PRIVILEDGED"
    };

    user::user(std::string_view view)
    {
        this->username  = utils::chop_by_delim(view, ':'); utils::chop_by_delim(view, ':');
        this->uid       = std::stoi(std::string(utils::chop_by_delim(view, ':')));
        this->gid       = std::stoi(std::string(utils::chop_by_delim(view, ':'))); utils::chop_by_delim(view, ':');
        this->home      = utils::chop_by_delim(view, ':');
        this->shell     = view;
    }

    std::vector<std::string> user::to_row() const
    {
        return {
            username,
            home,
            shell,
            std::to_string(uid),
            std::to_string(gid),
            privileged ? "YES" : "NO"
        };
    }

    void user::print_users(const std::vector<user>& users)
    {
        std::vector<std::vector<std::string>> content;
        
        content.reserve(users.size());

        for(const auto& u : users)
            content.emplace_back(u.to_row());

        utils::print_table(USER_HEADERS, content);
    }
}
