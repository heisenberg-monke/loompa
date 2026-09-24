#include "utils.hpp"

namespace utils
{
    std::string_view chop_left(std::string_view& sv, size_t n)
    {
        auto result = sv.substr(0, n);
        sv.remove_prefix(n);

        return result;
    }

    std::string_view chop_by_delim(std::string_view& sv, char delim)
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

    void print_table(const std::vector<std::string>& headers, const std::vector<std::vector<std::string>>& content)
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