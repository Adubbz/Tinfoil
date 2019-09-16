#ifdef __VERIFY_NSP__
#include "mode/verify_nsp_mode.hpp"

#include <switch.h>
#include "install/verify_nsp.hpp"
#include "ui/framework/console_options_view.hpp"
#include "util/file_util.hpp"

namespace tin::ui
{
    VerifyNSPMode::VerifyNSPMode() :
        IMode("Verify NSP")
    {

    }

    void VerifyNSPMode::OnSelected()
    {
        tin::ui::ViewManager& manager = tin::ui::ViewManager::Instance();
        auto view = std::make_unique<tin::ui::ConsoleOptionsView>();
        view->AddEntry("Select NSP", tin::ui::ConsoleEntrySelectType::HEADING, nullptr);
        view->AddEntry("", tin::ui::ConsoleEntrySelectType::NONE, nullptr);

        auto nspList = tin::util::GetNSPList();

        if (nspList.size() > 0)
        {
            for (unsigned int i = 0; i < nspList.size(); i++)
            {
                view->AddEntry(nspList[i], ConsoleEntrySelectType::SELECT, std::bind(&VerifyNSPMode::OnNSPSelected, this));
            }
        }

        manager.PushView(std::move(view));
    }

    void VerifyNSPMode::OnNSPSelected()
    {
        // Retrieve previous selection
        tin::ui::ViewManager& manager = tin::ui::ViewManager::Instance();
        ConsoleOptionsView* prevView;

        if (!(prevView = dynamic_cast<ConsoleOptionsView*>(manager.GetCurrentView())))
        {
            throw std::runtime_error("Previous view must be a ConsoleOptionsView!");
        }

        std::string path = "@Sdcard://tinfoil/nsp/" + prevView->GetSelectedOptionValue()->GetText();
        tin::install::NSPVerifier nspVerifier(path);

        // Push a blank view ready for installation
        auto view = std::make_unique<tin::ui::ConsoleView>(1);
        manager.PushView(std::move(view));

        nspVerifier.PerformVerification();
    }
}
#endif