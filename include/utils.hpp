#pragma once

#include <cassert>

#include <fstream>
#include <sstream>
#include <iostream>

#include <string>
#include <string_view>

#include <format>
#include <filesystem>
#include <source_location>

namespace utils
{
    namespace string_view
    {
        inline std::string_view chop_left(std::string_view& sv, size_t n = 1)
        {
            auto result = sv.substr(0, n);
            sv.remove_prefix(n);

            return result;
        }

        inline std::string_view chop_by_delim(std::string_view& sv, char delim)
        {
            const auto pos = sv.find(delim);

            if(pos == std::string_view::npos)
            {
                auto result = sv;

                sv = {};

                return result;
            }

            auto result = sv.substr(0, pos);
            
            sv.remove_prefix(pos + 1);

            return result;
        }

        template <typename Predicate>
        inline std::string_view chop_while(std::string_view& sv, Predicate p)
        {
            size_t i = 0;

            while(i < sv.size() && p(sv[i]))
                ++i;

            return chop_left(sv, i);
        }

        inline char* shift_args(int& argc, char**& argv)
        {
            assert(argc > 0);
            
            --argc;
            return *argv++;
        }

        inline constexpr std::string_view clean_function_name(std::string_view raw)
        {
            auto paren = raw.find('(');

            if(paren != std::string_view::npos)
                raw = raw.substr(0, paren);

            auto space = raw.rfind(' ');

            if(space != std::string_view::npos)
                raw = raw.substr(space + 1);

            return raw;
        }
    }

    namespace algorithms
    {
        template <typename T, typename U>
        inline size_t binary_search(const std::vector<T>& vec, U&& x)
        {
            const size_t n = vec.size();

            size_t low = 0;
            size_t high = n;

            while(low < high)
            {
                size_t mid = low + (high - low) / 2;

                if(vec[mid] == x)
                    return mid;

                if(vec[mid] < x)
                    low = mid + 1;

                else
                    high = mid;
            }

            return n;
        }
    }

    class logger
    {
        static inline bool DEBUG = false;
        static inline bool WARNINGS = false;

    public:
        static bool debug_enabled() {
            return DEBUG;
        }

        static bool warnings_enabled() {
            return WARNINGS;
        }

        static void set_debug(bool debug) {
            DEBUG = debug;
        }

        static void set_warnings(bool warnings) {
            WARNINGS = warnings;
        }

        static void log(std::ostream& out, const char* level, const char* func, const std::string& message)
        {
            if(level)
                out << '[' << level << "] ";

            if(func)
                out << func << ": ";

            out << message;
        }

        #define LOG_INFO(msg) if(utils::logger::debug_enabled()) utils::logger::log(std::cout, "INFO", __func__, msg)
        #define LOG_WARN(msg) if(utils::logger::warnings_enabled()) utils::logger::log(std::cerr, "WARN", __func__, msg)
        #define LOG_ERROR(msg) utils::logger::log(std::cerr, "ERROR", __func__, msg)
        #define LOG_OUT(msg) utils::logger::log(std::cout, nullptr, nullptr, msg)
    };

    #define UTILS_CREATE_EXCEPTION(name)                                                                                        \
        class name##_exception : public std::runtime_error                                                                      \
        {                                                                                                                       \
        public:                                                                                                                 \
            explicit name##_exception(const std::string& msg, std::source_location loc = std::source_location::current())       \
                : runtime_error(std::format("{}: {}", utils::string_view::clean_function_name(loc.function_name()), msg)) {}    \
        }
    
    namespace file_system
    {
        inline std::string read_entire_file(const std::filesystem::path& path)
        {
            auto path_str = path.string();
            std::ifstream file(path_str, std::ios::binary);

            if(!file)
                throw std::runtime_error(std::format("Failed to open file: {}: {}", path_str, strerror(errno)));

            std::ostringstream buffer;

            buffer << file.rdbuf();

            if(!file.good() && !file.eof())
                std::runtime_error(std::format("Failed to read file: {}: {}", path_str, strerror(errno)));

            LOG_INFO(std::format("Read {} successfully.\n", path_str));

            return buffer.str();
        }

        inline void write_entire_file(const std::filesystem::path& path, const std::string& content)
        {
            const auto path_str = path.string();
            const auto parent = path.parent_path();

            if(!parent.empty())
            {
                std::error_code ec;

                std::filesystem::create_directories(parent, ec);

                if(ec)
                    std::runtime_error(std::format("Failed to create directory: {}: {}", parent.string(), ec.message()));
            }

            std::ofstream file(path, std::ios::binary | std::ios::trunc);

            if(!file)
                throw std::runtime_error("Failed to open file: " + path_str + ": " + strerror(errno));

            file.write(content.data(), content.size());

            if(!file)
                throw std::runtime_error("Failed to write file: " + path_str + ": " + strerror(errno));

            file.close();

            if(!file)
                throw std::runtime_error("Failed to close file: " + path_str + ": " + strerror(errno));

            LOG_INFO("Created " + path_str + ".\n");
        }

        template <typename T>
        inline void read_system_command(const char* cmd, std::vector<T>& data)
        {
            FILE* pipe = popen(cmd, "r");

            if(!pipe)
                throw std::runtime_error(std::format("Failed to execute command: {}: {}", cmd, strerror(errno)));

            char buf[256];

            while(fgets(buf, sizeof(buf), pipe))
            {
                buf[strcspn(buf, "\n")] = '\0';
                data.emplace_back(buf);
            }
                

            pclose(pipe);
        }
    }
    
    namespace table 
    {
        inline void print_table(const std::vector<std::string>& headers, const std::vector<std::vector<std::string>>& content)
        {
            if(headers.empty())
                return;

            const size_t columns = headers.size();
            std::vector<size_t> widths(columns);

            for(size_t i = 0; i < columns; ++i)
                widths[i] = headers[i].size();

            for(const auto& row : content)
            {
                for(size_t i = 0; i < columns; ++i)
                    widths[i] = std::max(widths[i], row[i].size());
            }

            for(auto& width : widths)
                width += 2;

            auto border = [&]()
            {
                std::cout << '+';

                for(const auto& width : widths)
                    std::cout << std::string(width, '-') << '+';

                std::cout << '\n';
            };

            auto row = [&](const std::vector<std::string>& values)
            {
                std::cout << '|';

                for(size_t i = 0; i < columns; ++i)
                    std::cout << ' ' << std::left << std::setw(widths[i] - 1) << values[i] << '|';
                
                std::cout << '\n';
            };

            border();
            row(headers);
            border();

            for(const auto& values : content)
                row(values);

            border();
        }
    }
}