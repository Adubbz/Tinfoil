#pragma once

#include <switch/types.h>

#include <functional>
#include <memory>
#include <string>
#include <vector>
#include "ui/framework/console_view.hpp"
#include "nx/ipc/tin_ipc.h"

namespace tin::ui
{
    static const std::string DEFAULT_TITLE = "Tinfoil 0.3.0";
    struct IOptionValue
    {
        public:
            virtual const std::string& GetText() = 0;
    };

    struct TextOptionValue : public IOptionValue
    {
        std::string name;

        TextOptionValue(std::string name);

        const std::string& GetText() override;
    };

    struct TitleIdOptionValue : public IOptionValue
    {
        u64 titleId;
        std::string name;

        TitleIdOptionValue(u64 titleId);

        const std::string& GetText() override;
    };

    struct RightsIdOptionValue : public IOptionValue
    {
        RightsId rightsId;
        std::string name;

        RightsIdOptionValue(RightsId rightsId);

        const std::string& GetText() override;
    };

    enum class ConsoleEntrySelectType
    {
        NONE, SELECT, SELECT_INACTIVE, HEADING
    };

    struct ConsoleEntry
    {
        std::unique_ptr<IOptionValue> optionValue;
        ConsoleEntrySelectType selectType;
        std::function<void ()> onSelected;

        ConsoleEntry& operator=(const ConsoleEntry&) = delete;
        ConsoleEntry(const ConsoleEntry&) = delete;   

        ConsoleEntry(std::unique_ptr<IOptionValue> optionValue, ConsoleEntrySelectType selectType, std::function<void ()> onSelected);
    };
    class ConsoleOptionsView : public ConsoleView
    {
        private:
            static const int MAX_ENTRIES_PER_PAGE = 32;
        public:
            ConsoleOptionsView(std::string title=DEFAULT_TITLE, unsigned int unwindDistance = 1);

            virtual void OnPresented() override;
            virtual void ProcessInput(u64 keys) override;

            void AddEntry(std::unique_ptr<IOptionValue> value, ConsoleEntrySelectType selectType, std::function<void ()> onSelected);
            void AddEntry(std::string text, ConsoleEntrySelectType selectType, std::function<void ()> onSelected);

            ConsoleEntry* GetSelectedEntry();
            IOptionValue* GetSelectedOptionValue();

        protected:
            const std::string m_title;

            std::vector<std::unique_ptr<ConsoleEntry>> m_consoleEntries;
            unsigned int m_cursorPos = 0;
            unsigned int m_offset = 0;

            virtual const char* PaddingAfterCursor() const
            {
                return " ";
            }

            virtual void DisplayAll();

            void MoveCursor(signed char off);
            void DisplayCursor();
            void ClearCursor();
    };
}