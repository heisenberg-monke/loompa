#pragma once

#include "user.hpp"
#include "utils.hpp"

namespace loompa
{
    UTILS_CREATE_EXCEPTION(loompa);

    class app 
    {
        user_manager u_manager;

    public:
        void print_usage() const;
        void print_version() const;
        
        void parse_global_options(int argc, char** argv, const std::string_view& arg);
        void parse_commands(int argc, char** argv, const std::string_view* prev);
    };
}