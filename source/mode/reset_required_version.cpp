#include "mode/reset_required_version.hpp"

#include <exception>
#include <memory>
#include "nx/ipc/tin_ipc.h"
#include "ui/framework/console_view.hpp"
#include "ui/framework/console_options_view.hpp"
#include "ui/framework/view.hpp"
#include "error.hpp"
#include "translate.h"

namespace tin::ui
{
    ResetRequiredVersionMode::ResetRequiredVersionMode() :
        IMode(translate(Translate::RESET_REQUIRED_VERSION))
    {

    }

    void ResetRequiredVersionMode::OnSelected()
    {
        tin::ui::ViewManager& manager = tin::ui::ViewManager::Instance();
        auto view = std::make_unique<tin::ui::ConsoleOptionsView>();
        view->AddEntry(m_name, tin::ui::ConsoleEntrySelectType::HEADING, nullptr);
        view->AddEntry("", tin::ui::ConsoleEntrySelectType::NONE, nullptr);

        NsApplicationRecord records[32];
        s32 offset = 0, entriesRead;

        while (!nsListApplicationRecord(records, sizeof(records), offset, &entriesRead))
        {
            if (!entriesRead)
            {
                break;
            }

            for (s32 i = 0; i < entriesRead; i++)
            {
                view->AddEntry(std::make_unique<TitleIdOptionValue>(records[i].titleID), tin::ui::ConsoleEntrySelectType::SELECT, std::bind(&ResetRequiredVersionMode::OnTitleIdSelected, this));
            }

            offset += entriesRead;
            entriesRead = 0;
        }

        manager.PushView(std::move(view));
    }

    void ResetRequiredVersionMode::OnTitleIdSelected()
    {
        tin::ui::ViewManager& manager = tin::ui::ViewManager::Instance();
        ConsoleOptionsView* prevView;
        TitleIdOptionValue* optionValue;

        if (!(prevView = reinterpret_cast<ConsoleOptionsView*>(manager.GetCurrentView())))
        {
            throw std::runtime_error("View must be a ConsoleOptionsView!");
        }

        if (!(optionValue = reinterpret_cast<TitleIdOptionValue*>(prevView->GetSelectedOptionValue())))
        {
            throw std::runtime_error("Option value must be a TitleIdOptionValue");
        }

        // Push a blank view
        auto view = std::make_unique<tin::ui::ConsoleView>();
        manager.PushView(std::move(view));

        ASSERT_OK(nsPushLaunchVersion(0, optionValue->titleId), "Failed to reset required version");

        printf("%s\n\n%s\n", translate(Translate::TITLE_RESET_REQ_VER_SUCCESS), translate(Translate::PRESS_B_RETURN));
        prevView->GetSelectedEntry()->selectType = ConsoleEntrySelectType::SELECT_INACTIVE;
    }
}