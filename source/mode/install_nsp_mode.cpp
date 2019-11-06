#include "mode/install_nsp_mode.hpp"

#include <cstring>
#include <sstream>
#include "install/install_nsp.hpp"
#include "nx/fs.hpp"
#include "ui/framework/console_options_view.hpp"
#include "util/file_util.hpp"
#include "util/title_util.hpp"
#include "util/graphics_util.hpp"
#include "error.hpp"
#include "translate.h"

namespace tin::ui
{
    InstallNSPMode::InstallNSPMode() :
        IMode(translate(Translate::NSP_INSTALL))
    {

    }

    void InstallNSPMode::OnSelected()
    {
        tin::ui::ViewManager& manager = tin::ui::ViewManager::Instance();
        auto view = std::make_unique<tin::ui::ConsoleOptionsView>();
        view->AddEntry(translate(Translate::NSP_SELECT), tin::ui::ConsoleEntrySelectType::HEADING, nullptr);
        view->AddEntry("", tin::ui::ConsoleEntrySelectType::NONE, nullptr);

        auto nspList = tin::util::GetNSPList();

        if (nspList.size() > 0)
        {
            view->AddEntry(translate(Translate::NSP_INSTALL_ALL), ConsoleEntrySelectType::SELECT, std::bind(&InstallNSPMode::OnNSPSelected, this));

            for (unsigned int i = 0; i < nspList.size(); i++)
            {
                view->AddEntry(nspList[i], ConsoleEntrySelectType::SELECT, std::bind(&InstallNSPMode::OnNSPSelected, this));
            }
        }

        manager.PushView(std::move(view));
    }

    void InstallNSPMode::OnNSPSelected()
    {
        // Retrieve previous selection
        tin::ui::ViewManager& manager = tin::ui::ViewManager::Instance();
        ConsoleOptionsView* prevView;

        if (!(prevView = reinterpret_cast<ConsoleOptionsView*>(manager.GetCurrentView())))
        {
            throw std::runtime_error("Previous view must be a ConsoleOptionsView!");
        }

        m_name = prevView->GetSelectedOptionValue()->GetText();

        // Prepare the next view
        auto view = std::make_unique<tin::ui::ConsoleOptionsView>();
        view->AddEntry(translate(Translate::NSP_INSTALL_SELECT_DESTINATION), tin::ui::ConsoleEntrySelectType::HEADING, nullptr);
        view->AddEntry("", tin::ui::ConsoleEntrySelectType::NONE, nullptr);
        view->AddEntry(translate(Translate::SDCARD), tin::ui::ConsoleEntrySelectType::SELECT, std::bind(&InstallNSPMode::OnDestinationSelected, this));
        view->AddEntry(translate(Translate::NAND), tin::ui::ConsoleEntrySelectType::SELECT, std::bind(&InstallNSPMode::OnDestinationSelected, this));
        manager.PushView(std::move(view));
    }

    void InstallNSPMode::OnDestinationSelected()
    {
        // Retrieve previous selection
        tin::ui::ViewManager& manager = tin::ui::ViewManager::Instance();
        ConsoleOptionsView* prevView;

        if (!(prevView = reinterpret_cast<ConsoleOptionsView*>(manager.GetCurrentView())))
        {
            throw std::runtime_error("Previous view must be a ConsoleOptionsView!");
        }

        auto destStr = prevView->GetSelectedOptionValue()->GetText();
        m_destStorageId = FsStorageId_SdCard;

        if (destStr == translate(Translate::NAND))
        {
            m_destStorageId = FsStorageId_NandUser;
        }

        auto view = std::make_unique<tin::ui::ConsoleOptionsView>();
        view->AddEntry(translate(Translate::IGNORE_REQUIRED_FW_VERSION), tin::ui::ConsoleEntrySelectType::HEADING, nullptr);
        view->AddEntry("", tin::ui::ConsoleEntrySelectType::NONE, nullptr);
        view->AddEntry(translate(Translate::NO), tin::ui::ConsoleEntrySelectType::SELECT, std::bind(&InstallNSPMode::OnIgnoreReqFirmVersionSelected, this));
        view->AddEntry(translate(Translate::YES), tin::ui::ConsoleEntrySelectType::SELECT, std::bind(&InstallNSPMode::OnIgnoreReqFirmVersionSelected, this));
        manager.PushView(std::move(view));
    }

    void InstallNSPMode::OnIgnoreReqFirmVersionSelected()
    {
        // Retrieve previous selection
        tin::ui::ViewManager& manager = tin::ui::ViewManager::Instance();
        ConsoleOptionsView* prevView;

        if (!(prevView = reinterpret_cast<ConsoleOptionsView*>(manager.GetCurrentView())))
        {
            throw std::runtime_error("Previous view must be a ConsoleOptionsView!");
        }

        auto optStr = prevView->GetSelectedOptionValue()->GetText();
        m_ignoreReqFirmVersion = (optStr == translate(Translate::YES));
        std::vector<std::string> installList;

        if (m_name == translate(Translate::NSP_INSTALL_ALL))
        {
            installList = tin::util::GetNSPList();
        }
        else
        {
            installList.push_back(m_name);
        }

        // Push a blank view ready for installation
        auto view = std::make_unique<tin::ui::ConsoleView>(3);
        manager.PushView(std::move(view));

        for (unsigned int i = 0; i < installList.size(); i++)
        {
            std::string path = "@Sdcard://tinfoil/nsp/" + installList[i];

            try
            {
                nx::fs::IFileSystem fileSystem;
                fileSystem.OpenFileSystemWithId(path, FsFileSystemType_ApplicationPackage, 0);
                tin::install::nsp::SimpleFileSystem simpleFS(fileSystem, "/", path + "/");
                tin::install::nsp::NSPInstallTask task(simpleFS, m_destStorageId, m_ignoreReqFirmVersion);

                printf("%s\n", translate(Translate::NSP_INSTALL_PREPARING));
                task.Prepare();
                LOG_DEBUG("Pre Install Records: \n");
                task.DebugPrintInstallData();

                if (!task.VerifyContent())
                {
                    printf(CONSOLE_RED "\nTHIS NSP DOESN'T CONTAIN VALID NCA's!\n\nPress B to cancel the install, A to continue.\n");
                    consoleUpdate(NULL);
                    printf(CONSOLE_WHITE);
                    while(true)
                    {
                        hidScanInput();
                        u64 kDown = hidKeysDown(CONTROLLER_P1_AUTO);
                        if (kDown & KEY_B)
                            throw std::runtime_error("install abort!");
                        if (kDown & KEY_A)
                            break;
                    }
                }
                else
                {
                    printf(CONSOLE_GREEN "Valid Signature!\n");
                    consoleUpdate(NULL);
                }
                printf(CONSOLE_WHITE);

                std::stringstream ss;
                ss << translate(Translate::NSP_INSTALLING) << " " << tin::util::GetTitleName(task.GetTitleId(), task.GetContentMetaType()) << " (" << (i + 1) << "/" << installList.size() << ")";
                manager.m_printConsole->flags |= CONSOLE_COLOR_BOLD;
                tin::util::PrintTextCentred(ss.str());
                manager.m_printConsole->flags &= ~CONSOLE_COLOR_BOLD;

                task.Begin();
                LOG_DEBUG("Post Install Records: \n");
                task.DebugPrintInstallData();
            }
            catch (std::exception& e)
            {
                printf("%s\n", translate(Translate::NSP_INSTALL_FAILED));
                LOG_DEBUG("Failed to install NSP");
                LOG_DEBUG("%s", e.what());
                fprintf(stdout, "%s", e.what());
                break;
            }
        }

        printf("%s\n\n%s\n", translate(Translate::DONE), translate(Translate::PRESS_B_RETURN));
    }
}
