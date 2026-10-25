#pragma once

#include <cassert>
#include <cerrno>
#include <charconv>
#include <cctype>
#include <ctime>
#include <cstring>

#include <fstream>
#include <sstream>
#include <iostream>
#include <stdexcept>

#include <string>
#include <string_view>

#include <format>
#include <filesystem>
#include <source_location>
#include <fcntl.h>
#include <sys/wait.h>
#include <unistd.h>

namespace utils
{
    namespace time
    {
        inline std::string format_time(std::time_t timestamp)
        {
            std::tm value{};
            if(!localtime_r(&timestamp, &value))
                return "Unknown";
            std::ostringstream output;
            output << std::put_time(&value, "%Y-%m-%d %H:%M:%S");
            return output.str();
        }

        inline std::time_t parse_time(std::string_view value, bool end_of_day = false)
        {
            std::string expression(value);

            if(expression.size() > 1 && std::isdigit(static_cast<unsigned char>(expression[expression.size() - 2])))
            {
                const char unit = expression.back();
                const std::string_view amount(expression.data(), expression.size() - 1);
                std::string unit_name;

                switch(unit)
                {
                    case 's': unit_name = "second"; break;
                    case 'm': unit_name = "minute"; break;
                    case 'h': unit_name = "hour"; break;
                    case 'd': unit_name = "day"; break;
                    case 'w': unit_name = "week"; break;
                    default: break;
                }

                size_t amount_value{};
                const auto [amount_end, amount_error] = std::from_chars(amount.data(), amount.data() + amount.size(), amount_value);
                if(!unit_name.empty() && amount_error == std::errc{} && amount_end == amount.data() + amount.size())
                    expression = std::format("{} {}{} ago", amount_value, unit_name, amount_value == 1 ? "" : "s");
            }

            bool date_only = expression.size() == 10 && expression[4] == '-' && expression[7] == '-';
            for(size_t i = 0; date_only && i < expression.size(); ++i)
                if(i != 4 && i != 7 && !std::isdigit(static_cast<unsigned char>(expression[i])))
                    date_only = false;
            if(end_of_day && date_only)
                expression += " 23:59:59";

            int output_pipe[2];
            if(pipe(output_pipe) == -1)
                throw std::runtime_error(std::format("Failed to create time parser pipe: {}", std::strerror(errno)));

            const pid_t child = fork();
            if(child == -1)
            {
                close(output_pipe[0]);
                close(output_pipe[1]);
                throw std::runtime_error(std::format("Failed to start time parser: {}", std::strerror(errno)));
            }

            if(child == 0)
            {
                close(output_pipe[0]);
                if(dup2(output_pipe[1], STDOUT_FILENO) == -1)
                    _exit(127);
                close(output_pipe[1]);
                const int null_device = open("/dev/null", O_WRONLY);
                if(null_device != -1)
                {
                    dup2(null_device, STDERR_FILENO);
                    close(null_device);
                }
                const std::string date_argument = "--date=" + expression;
                execlp("date", "date", date_argument.c_str(), "+%s", static_cast<char*>(nullptr));
                _exit(127);
            }

            close(output_pipe[1]);
            char output[64]{};
            size_t output_size = 0;
            while(output_size < sizeof(output) - 1)
            {
                const ssize_t count = read(output_pipe[0], output + output_size, sizeof(output) - 1 - output_size);
                if(count > 0)
                    output_size += static_cast<size_t>(count);
                else if(count == -1 && errno == EINTR)
                    continue;
                else
                    break;
            }
            close(output_pipe[0]);

            int status{};
            while(waitpid(child, &status, 0) == -1)
                if(errno != EINTR)
                    throw std::runtime_error(std::format("Failed waiting for time parser: {}", std::strerror(errno)));

            if(output_size > 0 && output[output_size - 1] == '\n')
                --output_size;

            std::time_t timestamp{};
            const auto [end, error] = std::from_chars(output, output + output_size, timestamp);
            if(!WIFEXITED(status) || WEXITSTATUS(status) != 0 || error != std::errc{} || end != output + output_size)
                throw std::runtime_error(std::format("Invalid time: {}", value));

            return timestamp;
        }
    }

    namespace string_view
    {
        inline size_t parse_limit(std::string_view value)
        {
            size_t limit{};
            const auto [end, error] = std::from_chars(value.data(), value.data() + value.size(), limit);
            if(error != std::errc{} || end != value.data() + value.size())
                throw std::runtime_error(std::format("Invalid limit: {}", value));
            return limit;
        }

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

        inline std::vector<utmpx> read_login_records(const std::filesystem::path& path)
        {
            const std::string data = read_entire_file(path);
            if(data.size() % sizeof(utmpx) != 0)
                throw std::runtime_error(std::format("Login record file has an incomplete record: {}", path.string()));
            std::vector<utmpx> records(data.size() / sizeof(utmpx));
            for(size_t i = 0; i < records.size(); ++i)
                std::memcpy(&records[i], data.data() + i * sizeof(utmpx), sizeof(utmpx));
            return records;
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

            std::ostringstream rendered;
            auto border = [&]()
            {
                rendered << '+';

                for(const auto& width : widths)
                    rendered << std::string(width, '-') << '+';

                rendered << '\n';
            };

            auto row = [&](const std::vector<std::string>& values)
            {
                rendered << '|';

                for(size_t i = 0; i < columns; ++i)
                    rendered << ' ' << std::left << std::setw(widths[i] - 1) << values[i] << '|';
                
                rendered << '\n';
            };

            border();
            row(headers);
            border();

            for(const auto& values : content)
                row(values);

            border();

            const std::string output = rendered.str();
            size_t table_width = columns + 1;
            for(const auto width : widths)
                table_width += width;

            winsize terminal{};
            if(!isatty(STDOUT_FILENO) || ioctl(STDOUT_FILENO, TIOCGWINSZ, &terminal) == -1 ||
                terminal.ws_col == 0 || table_width <= terminal.ws_col)
            {
                std::cout << output;
                return;
            }

            FILE* buffer = std::tmpfile();
            if(!buffer)
            {
                std::cout << output;
                return;
            }

            std::fwrite(output.data(), 1, output.size(), buffer);
            std::fflush(buffer);
            std::rewind(buffer);

            std::vector<std::string> pager_arguments;
            if(const char* configured_pager = std::getenv("PAGER"); configured_pager && *configured_pager)
            {
                std::istringstream pager_words(configured_pager);
                std::string word;
                while(pager_words >> word)
                    pager_arguments.push_back(std::move(word));
            }
            else
                pager_arguments = {"less", "-S"};

            if(pager_arguments.empty())
            {
                std::fclose(buffer);
                std::cout << output;
                return;
            }

            const pid_t child = fork();
            if(child == 0)
            {
                if(dup2(fileno(buffer), STDIN_FILENO) == -1)
                    _exit(127);
                std::vector<char*> arguments;
                arguments.reserve(pager_arguments.size() + 1);
                for(auto& argument : pager_arguments)
                    arguments.push_back(argument.data());
                arguments.push_back(nullptr);
                execvp(arguments.front(), arguments.data());
                _exit(127);
            }

            std::fclose(buffer);
            if(child == -1)
            {
                std::cout << output;
                return;
            }

            int status{};
            pid_t waited;
            do
                waited = waitpid(child, &status, 0);
            while(waited == -1 && errno == EINTR);
            if(waited == -1 || !WIFEXITED(status) || WEXITSTATUS(status) != 0)
                std::cout << output;
        }
    }
}
