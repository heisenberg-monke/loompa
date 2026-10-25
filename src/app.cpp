#include "app.hpp"
#include "user.hpp"

namespace loompa 
{
    void app::print_usage() const
    {

    }

    void app::print_version() const
    {

    }

    void app::parse_commands(int argc, char** argv, const std::string_view* prev)
    {
        std::string_view arg = prev ? *prev : utils::string_view::shift_args(argc, argv);

        if(arg == "users")
            u_manager.parse_user_options(argc, argv);

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