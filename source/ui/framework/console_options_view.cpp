#include "ui/framework/console_options_view.hpp"

#include <cstring>
#include "util/graphics_util.hpp"
#include "util/title_util.hpp"
#include "error.hpp"
#include "translate.h"

#define OPTIONS_VIEW_PAGE_SIZE 42

namespace tin::ui
{
    // TextOptionValue

    TextOptionValue::TextOptionValue(std::string name) :
        name(name)
    {

    }

    const std::string& TextOptionValue::GetText()
    {
        return this->name;
    }

    // End TextOptionValue

    // TitleIdOptionValue

    TitleIdOptionValue::TitleIdOptionValue(u64 titleId) :
        titleId(titleId)
    {

    }

    const std::string& TitleIdOptionValue::GetText()
    {
        if (!name.size())
        {
            name = tin::util::GetBaseTitleName(titleId);

            if (!name.size())
            {
                name = translate(Translate::UNKNOWN);

                char titleIdStr[34] = { 0 };
                snprintf(titleIdStr, 34 - 1, "%016lx", titleId);
                name += " - " + std::string(titleIdStr);
            }
        }
        return name;
    }

    // End TitleIdOptionValue

    // RightsIdOptionValue

    RightsIdOptionValue::RightsIdOptionValue(RightsId rightsId) :
        rightsId(rightsId)
    {

    }

    const std::string& RightsIdOptionValue::GetText()
    {
        if (name.length() == 0)
        {
            u64 titleId = tin::util::GetRightsIdTid(this->rightsId);
            u64 keyGen = tin::util::GetRightsIdKeyGen(this->rightsId);
            name = tin::util::GetBaseTitleName(titleId);

            if (name.empty() || name == "Unknown")
            {
                try
                {
                    name = tin::util::GetBaseTitleName(titleId ^ 0x800);
                }
                catch (...) {}
            }

            char rightsIdStr[34] = { 0 };
            snprintf(rightsIdStr, 34 - 1, "%016lx%016lx", titleId, keyGen);
            name += " - " + std::string(rightsIdStr);
        }

        return name;
    }

    // End RightsIdOptionValue

    // ConsoleEntry

    ConsoleEntry::ConsoleEntry(std::unique_ptr<IOptionValue> optionValue, ConsoleEntrySelectType selectType, std::function<void ()> onSelected) :
        optionValue(std::move(optionValue)), selectType(selectType), onSelected(onSelected)
    {

    }

    // End ConsoleEntry

    ConsoleOptionsView::ConsoleOptionsView(std::string title, unsigned int unwindDistance) :
        ConsoleView(unwindDistance), m_title(title)
    {

    }

    void ConsoleOptionsView::OnPresented()
    {
        ConsoleView::OnPresented();

        for (unsigned char i = 0; i < m_consoleEntries.size(); i++)
        {
            ConsoleEntry* entry = m_consoleEntries.at(i).get();
            m_cursorPos = i;

            if (entry->selectType == ConsoleEntrySelectType::SELECT)
            {
                break;
            }
        }

        this->DisplayAll();
    }

    void ConsoleOptionsView::ProcessInput(u64 keys)
    {
        if (keys & KEY_DOWN)
            this->MoveCursor(1);
        else if (keys & KEY_UP)
            this->MoveCursor(-1);
        else if (keys & KEY_ZL)
            this->MoveCursor(-OPTIONS_VIEW_PAGE_SIZE);
        else if (keys & KEY_ZR)
            this->MoveCursor(OPTIONS_VIEW_PAGE_SIZE);
        else if (keys & KEY_A)
        {
            ConsoleEntry* consoleEntry = m_consoleEntries.at(m_cursorPos).get();

            if (consoleEntry->onSelected != NULL && consoleEntry->selectType == ConsoleEntrySelectType::SELECT)
                consoleEntry->onSelected();
        }
        else if (keys & KEY_B)
            m_viewManager->Unwind(m_unwindDistance);
    }

    void ConsoleOptionsView::AddEntry(std::unique_ptr<IOptionValue> optionValue, ConsoleEntrySelectType selectType, std::function<void ()> onSelected)
    {
        auto entry = std::make_unique<ConsoleEntry>(std::move(optionValue), selectType, onSelected);
        m_consoleEntries.push_back(std::move(entry));
    }

    void ConsoleOptionsView::AddEntry(std::string text, ConsoleEntrySelectType selectType, std::function<void ()> onSelected)
    {
        this->AddEntry(std::move(std::make_unique<TextOptionValue>(text)), selectType, onSelected);
    }

    ConsoleEntry* ConsoleOptionsView::GetSelectedEntry()
    {
        return m_consoleEntries.at(m_cursorPos).get();
    }

    IOptionValue* ConsoleOptionsView::GetSelectedOptionValue()
    {
        return this->GetSelectedEntry()->optionValue.get();
    }

    void ConsoleOptionsView::MoveCursor(signed char off)
    {
        if (off != -1 && off != 1 && off != OPTIONS_VIEW_PAGE_SIZE && off != -OPTIONS_VIEW_PAGE_SIZE)
            return;

        this->ClearCursor();

        for (unsigned char i = 0; i < m_consoleEntries.size(); i++)
        {
            signed char newCursorPos = (m_cursorPos + i * off + off);

            // Negative numbers should wrap back around to the end
            if (newCursorPos < 0)
                newCursorPos = m_consoleEntries.size() + newCursorPos;

            // Numbers greater than the number of entries should wrap around to the start
            newCursorPos %= m_consoleEntries.size();
            ConsoleEntry* entry = m_consoleEntries.at(newCursorPos).get();

            if (entry->selectType == ConsoleEntrySelectType::SELECT)
            {
                m_cursorPos = newCursorPos;
                break;
            }
        }

        if (m_cursorPos >= m_offset + OPTIONS_VIEW_PAGE_SIZE)
        {
            m_offset = m_cursorPos - OPTIONS_VIEW_PAGE_SIZE + 1;
        }

        if (m_cursorPos < m_offset)
        {
            m_offset = m_cursorPos;
        }

        this->DisplayAll();
    }

    void ConsoleOptionsView::DisplayAll()
    {
        auto console = ViewManager::Instance().m_printConsole;
        consoleClear();

        // Print the header
        console->flags |= CONSOLE_COLOR_BOLD;
        tin::util::PrintTextCentred(m_title);
        console->flags &= ~CONSOLE_COLOR_BOLD;

        if (m_consoleEntries.size())
        {
            if (m_offset >= m_consoleEntries.size())
            {
                m_offset = m_consoleEntries.size() - 1;
            }
            // Print the entries
            for (unsigned int i = 0; i < OPTIONS_VIEW_PAGE_SIZE && m_offset + i < m_consoleEntries.size(); i++)
            {
                auto& entry = m_consoleEntries[m_offset + i];
                char optionValueText[78] = { 0 };
                strncpy(optionValueText, entry->optionValue->GetText().c_str(), 78 - 1);

                switch (entry->selectType)
                {
                case ConsoleEntrySelectType::HEADING:
                    console->flags |= CONSOLE_COLOR_BOLD;
                    printf("%s\n", optionValueText);
                    console->flags &= ~CONSOLE_COLOR_BOLD;
                    break;

                case ConsoleEntrySelectType::SELECT_INACTIVE:
                    console->flags |= CONSOLE_COLOR_FAINT;
                    printf(" %s%s\n", PaddingAfterCursor(), optionValueText);
                    console->flags &= ~CONSOLE_COLOR_FAINT;
                    break;

                case ConsoleEntrySelectType::SELECT:
                    printf(" %s%s\n", PaddingAfterCursor(), optionValueText);
                    break;

                default:
                    printf("\n");
                }
            }
        }

        this->DisplayCursor();
    }

    void ConsoleOptionsView::DisplayCursor()
    {
        auto console = ViewManager::Instance().m_printConsole;
        console->cursorX = 0;
        console->cursorY = (m_cursorPos - m_offset) + 2;
        console->flags |= CONSOLE_COLOR_BOLD;
        printf("%s> ", CONSOLE_CYAN);
        console->flags &= ~CONSOLE_COLOR_BOLD;
        console->cursorX = 0;
        console->cursorY = (m_cursorPos - m_offset) + 3;
        printf("%s", CONSOLE_RESET);
    }

    void ConsoleOptionsView::ClearCursor()
    {
        auto console = ViewManager::Instance().m_printConsole;
        console->cursorX = 0;
        console->cursorY = (m_cursorPos - m_offset) + 2;
        printf("  ");
    }
}