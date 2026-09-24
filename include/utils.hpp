#pragma once

namespace utils
{
    std::string_view chop_left(std::string_view& sv, size_t n);
    std::string_view chop_by_delim(std::string_view& sv, char delim);

    void print_table(const std::vector<std::string>& headers, const std::vector<std::vector<std::string>>& content);

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