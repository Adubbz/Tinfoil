#include "util/graphics_util.hpp"
#include "ui/framework/view.hpp"

namespace tin::util
{
    void PrintTextCentred(std::string text)
    {
        auto* console = tin::ui::ViewManager::Instance().m_printConsole;
        unsigned int consoleWidth = console->consoleWidth;

        if (text.size() > consoleWidth)
            return;

        int totalPaddingSize = consoleWidth - text.size();
        int rightPadding = totalPaddingSize / 2;
        int leftPadding = totalPaddingSize - rightPadding;

        printf("%s%s%s\n", std::string(leftPadding, ' ').c_str(), text.c_str(), std::string(rightPadding, ' ').c_str());
    }
}