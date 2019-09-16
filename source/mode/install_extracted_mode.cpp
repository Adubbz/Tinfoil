#include "mode/install_extracted_mode.hpp"

#include <cstring>
#include "install/install_nsp.hpp"
#include "nx/fs.hpp"
#include "ui/framework/console_options_view.hpp"
#include "error.hpp"

namespace tin::ui
{
    InstallExtractedNSPMode::InstallExtractedNSPMode() :
        IMode("Install Extracted NSP")
    {

    }

    void InstallExtractedNSPMode::OnSelected()
    {
        tin::ui::ViewManager& manager = tin::ui::ViewManager::Instance();
        auto view = std::make_unique<tin::ui::ConsoleOptionsView>();
        view->AddEntry(m_name, tin::ui::ConsoleEntrySelectType::HEADING, nullptr);
        view->AddEntry("", tin::ui::ConsoleEntrySelectType::NONE, nullptr);

        nx::fs::IFileSystem fileSystem;
        fileSystem.OpenSdFileSystem();
        nx::fs::IDirectory dir = fileSystem.OpenDirectory("/tinfoil/extracted/", FS_DIROPEN_DIRECTORY);
        u64 entryCount = dir.GetEntryCount();

        if (entryCount > 0)
        {
            auto dirEntries = std::make_unique<FsDirectoryEntry[]>(entryCount);
            dir.Read(0, dirEntries.get(), entryCount);

            for (unsigned int i = 0; i < entryCount; i++)
            {
                FsDirectoryEntry dirEntry = dirEntries[i];

                if (dirEntry.type != ENTRYTYPE_DIR)
                    continue;

                view->AddEntry(dirEntry.name, ConsoleEntrySelectType::SELECT, std::bind(&InstallExtractedNSPMode::OnExtractedNSPSelected, this));
            }
        }

        manager.PushView(std::move(view));
    }

    void InstallExtractedNSPMode::OnExtractedNSPSelected()
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
        view->AddEntry("Select Destination", tin::ui::ConsoleEntrySelectType::HEADING, nullptr);
        view->AddEntry("", tin::ui::ConsoleEntrySelectType::NONE, nullptr);
        view->AddEntry("SD Card", tin::ui::ConsoleEntrySelectType::SELECT, std::bind(&InstallExtractedNSPMode::OnDestinationSelected, this));
        view->AddEntry("NAND", tin::ui::ConsoleEntrySelectType::SELECT, std::bind(&InstallExtractedNSPMode::OnDestinationSelected, this));
        manager.PushView(std::move(view));
    }

    void InstallExtractedNSPMode::OnDestinationSelected()
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

        if (destStr == "NAND")
        {
            m_destStorageId = FsStorageId_NandUser;
        }

        auto view = std::make_unique<tin::ui::ConsoleOptionsView>();
        view->AddEntry("Ignore Required Firmware Version", tin::ui::ConsoleEntrySelectType::HEADING, nullptr);
        view->AddEntry("", tin::ui::ConsoleEntrySelectType::NONE, nullptr);
        view->AddEntry("No", tin::ui::ConsoleEntrySelectType::SELECT, std::bind(&InstallExtractedNSPMode::OnIgnoreReqFirmVersionSelected, this));
        view->AddEntry("Yes", tin::ui::ConsoleEntrySelectType::SELECT, std::bind(&InstallExtractedNSPMode::OnIgnoreReqFirmVersionSelected, this));
        manager.PushView(std::move(view));
    }

    void InstallExtractedNSPMode::OnIgnoreReqFirmVersionSelected()
    {
        // Retrieve previous selection
        tin::ui::ViewManager& manager = tin::ui::ViewManager::Instance();
        ConsoleOptionsView* prevView;

        if (!(prevView = reinterpret_cast<ConsoleOptionsView*>(manager.GetCurrentView())))
        {
            throw std::runtime_error("Previous view must be a ConsoleOptionsView!");
        }

        auto optStr = prevView->GetSelectedOptionValue()->GetText();
        m_ignoreReqFirmVersion = false;

        if (optStr == "Yes")
        {
            m_ignoreReqFirmVersion = true;
        }

        std::string path = "/tinfoil/extracted/" + m_name + "/";
        std::string fullPath = "@Sdcard:/" + path;

        // Push a blank view ready for installation
        auto view = std::make_unique<tin::ui::ConsoleView>(3);
        manager.PushView(std::move(view));

        try
        {
            nx::fs::IFileSystem fileSystem;
            ASSERT_OK(fileSystem.OpenSdFileSystem(), "Failed to open SD file system");
            tin::install::nsp::SimpleFileSystem simpleFS(fileSystem, path, fullPath);
            tin::install::nsp::NSPInstallTask task(simpleFS, m_destStorageId, m_ignoreReqFirmVersion);

            task.Prepare();
            task.Begin();
        }
        catch (std::exception& e)
        {
            printf("Failed to install extracted NSP!\n");
            LOG_DEBUG("Failed to install extracted NSP");
            LOG_DEBUG("%s", e.what());
            fprintf(stdout, "%s", e.what());
        }
        
        printf("Done!\n\nPress (B) to return.\n");
    }
}