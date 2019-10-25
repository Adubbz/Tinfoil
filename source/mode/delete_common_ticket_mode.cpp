#include "mode/delete_common_ticket_mode.hpp"

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
    DeleteCommonTicketMode::DeleteCommonTicketMode() :
        IMode(translate(Translate::TICKET_COMMON_DELETE))
    {

    }

    void DeleteCommonTicketMode::OnSelected()
    {
        tin::ui::ViewManager& manager = tin::ui::ViewManager::Instance();
        auto view = std::make_unique<tin::ui::ConsoleOptionsView>();
        view->AddEntry(m_name, tin::ui::ConsoleEntrySelectType::HEADING, nullptr);
        view->AddEntry("", tin::ui::ConsoleEntrySelectType::NONE, nullptr);

        u32 numInstalledTickets = 0;

        ASSERT_OK(esCountCommonTicket(&numInstalledTickets), "Failed to count common tickets");
        auto rightsIdBuf = std::make_unique<RightsId[]>(numInstalledTickets);
        u32 numRightsIdsWritten = 0;

        ASSERT_OK(esListCommonTicket(&numRightsIdsWritten, rightsIdBuf.get(), numInstalledTickets * sizeof(RightsId)), "Failed to list common tickets");

        if (numInstalledTickets != numRightsIdsWritten)
        {
            throw std::runtime_error("Mismatch between num installed tickets and num rights ids written");
        }

        for (unsigned int i = 0; i < numRightsIdsWritten; i++)
        {
            RightsId rightsId = rightsIdBuf[i];

            view->AddEntry(std::make_unique<RightsIdOptionValue>(rightsId), tin::ui::ConsoleEntrySelectType::SELECT, std::bind(&DeleteCommonTicketMode::OnRightsIdSelected, this));
        }

        manager.PushView(std::move(view));
    }

    void DeleteCommonTicketMode::OnRightsIdSelected()
    {
        tin::ui::ViewManager& manager = tin::ui::ViewManager::Instance();
        ConsoleOptionsView* prevView;
        RightsIdOptionValue* optionValue;

        if (!(prevView = reinterpret_cast<ConsoleOptionsView*>(manager.GetCurrentView())))
        {
            throw std::runtime_error("View must be a ConsoleOptionsView!");
        }

        if (!(optionValue = reinterpret_cast<RightsIdOptionValue*>(prevView->GetSelectedOptionValue())))
        {
            throw std::runtime_error("Option value must be a RightsIdOptionValue");
        }

        RightsId rightsId = optionValue->rightsId;

        // Push a blank view
        auto view = std::make_unique<tin::ui::ConsoleView>();
        manager.PushView(std::move(view));

        LOG_DEBUG("RightsId to delete: \n");
        printBytes(nxlinkout, rightsId.c, sizeof(RightsId), true);

        ASSERT_OK(esDeleteTicket(&rightsId, sizeof(RightsId)), "Failed to delete common ticket");

        printf("%s\n\n%s\n", translate(Translate::TICKET_COMMON_DELETE_SUCCESS), translate(Translate::PRESS_B_RETURN));
        prevView->GetSelectedEntry()->selectType = ConsoleEntrySelectType::SELECT_INACTIVE;
    }
}