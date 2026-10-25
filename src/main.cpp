#include "utils.hpp"
#include <cassert>
#include <iostream>
#include <string_view>

#include "app.hpp"

int main(int argc, char** argv)
{
    loompa::app app;

    try {
        utils::string_view::shift_args(argc, argv);

        if(argc == 0)
            throw loompa::loompa_exception("No command given.\n");

        std::string_view arg = utils::string_view::shift_args(argc, argv);

        if(arg[0] == '-')
            app.parse_global_options(argc, argv, arg);

        else
            app.parse_commands(argc, argv, &arg);

        return 0;
    }

    catch(const loompa::loompa_exception& e)
    {
        utils::logger::log(std::cerr, "ERROR", nullptr, e.what());
        app.print_usage();

        return 1;
    }

    catch(const std::runtime_error& e)
    {
        utils::logger::log(std::cerr, "ERROR", nullptr, e.what());
        app.print_usage();

        return 1;
    }
}
