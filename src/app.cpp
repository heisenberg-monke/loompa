#include "app.hpp"
#include "user.hpp"

namespace loompa 
{
    void app::print_usage() const
    {
        LOG_OUT(
            "Usage: loompa [GLOBAL OPTION]... <COMMAND> [ARGS]\n"
            "\n"
            "Commands:\n"
            "  users list                         List users\n"
            "  users show <username>              Show user details\n"
            "  users groups <group>               List members of a group\n"
            "  users sessions                     Show active sessions\n"
            "  users history <username> [OPTIONS] Show login history\n"
            "  users failed-logins [OPTIONS]      Show failed login attempts\n"
            "  privileges list                   List elevated accounts, groups, and capabilities\n"
            "  privileges check <username>       Evaluate configured privilege access\n"
            "  privileges sudo <username>        Show sudo policy and recorded activity\n"
            "  privileges changes --since TIME --severity LEVEL\n"
            "                                     Severity: LOW, MEDIUM, HIGH, CRITICAL\n"
            "                                     Show recorded privilege changes\n"
            "\n"
            "History and failed-login options:\n"
            "  --since <DATE>                     Include entries since DATE\n"
            "  --until <DATE>                     Include entries until DATE\n"
            "  --limit <COUNT>                    Limit the number of entries\n"
            "\n"
            "DATE accepts GNU date expressions, such as '2026-10-25', 'yesterday',\n"
            "'24 hours ago', or compact durations such as '24h'.\n"
            "\n"
            "Global options:\n"
            "  -h, --help                         Show this help\n"
            "  -V, --version                      Show version\n"
            "  -v, --verbose                      Enable informational logging\n"
            "  -q, --quiet                        Disable informational logging\n");
    }

    void app::print_version() const
    {
        LOG_OUT("loompa 0.1.0\n");
    }

    void app::parse_commands(int argc, char** argv, const std::string_view* prev)
    {
        std::string_view arg = prev ? *prev : utils::string_view::shift_args(argc, argv);

        if(arg == "users")
            u_manager.parse_user_options(argc, argv);

        else if(arg == "privileges")
            p_manager.parse_options(argc, argv);

        else 
            throw loompa::loompa_exception(std::format("Unknown command: {}\n", arg));
    }

    void app::parse_global_options(int argc, char** argv, const std::string_view& arg)
    {
        if(arg == "-h" || arg == "--help")
            print_usage();

        else if(arg == "-V" || arg == "--version")
            print_version();

        else if(arg == "-v" || arg == "--verbose")
        {
            utils::logger::set_debug(true);
            parse_commands(argc, argv, nullptr);
        }

        else if(arg == "-q" || arg == "--quiet")
        {
            utils::logger::set_debug(false);
            parse_commands(argc, argv, nullptr);
        }

        else 
            throw loompa::loompa_exception(std::format("Unknown global option: {}", arg));
    }
}
