#include "mode/usb_install_mode.hpp"

#include <switch.h>

#include <exception>
#include <sstream>
#include <stdlib.h>
#include <malloc.h>
#include <threads.h>
#include <unistd.h>
#include "data/byte_buffer.hpp"
#include "install/install_nsp_remote.hpp"
#include "install/usb_nsp.hpp"
#include "ui/framework/console_view.hpp"
#include "ui/framework/console_checkbox_view.hpp"
#include "util/usb_util.hpp"
#include "debug.h"
#include "error.hpp"
#include "translate.h"
#include "options.h"

namespace tin::ui
{
    USBInstallMode::USBInstallMode() :
        IMode(translate(Translate::NSP_INSTALL_USB))
    {

    }

    USBInstallMode::~USBInstallMode()
    {
    }

    void USBInstallMode::OnUnwound()
    {

    }

    struct TUSHeader
    {
        u32 magic; // TUL0 (Tinfoil Usb List 0)
        u32 nspListSize;
        u64 padding;
    } PACKED;

    void USBInstallMode::OnSelected()
    {
        tin::ui::ViewManager& manager = tin::ui::ViewManager::Instance();
        auto view = std::make_unique<tin::ui::ConsoleView>();
        view->m_onUnwound = std::bind(&USBInstallMode::OnUnwound, this);
        manager.PushView(std::move(view));

        Result rc = 0;
        printf("%s\n", translate(Translate::NSP_INSTALL_USB_WAITING));
        consoleUpdate(NULL);

        while (true)
        {
            hidScanInput();

            if (hidKeysDown(CONTROLLER_P1_AUTO) & KEY_B)
                break;

            rc = usbDsWaitReady(1000000);

            if (R_SUCCEEDED(rc)) break;
            else if ((rc & 0x3FFFFF) != 0xEA01)
            {
                // Timeouts are okay, we just want to allow users to escape at this point
                THROW_FORMAT("Failed to wait for USB to be ready\n");
            }
        }

        printf("%s\n", translate(Translate::NSP_INSTALL_USB_READY));
        consoleUpdate(NULL);

        TUSHeader header;
        tin::util::USBRead(&header, sizeof(TUSHeader));

        if (header.magic != 0x304C5554)
            THROW_FORMAT("Incorrect TUL header magic!\n");

        LOG_DEBUG("Valid header magic.\n");
        LOG_DEBUG("NSP List Size: %u\n", header.nspListSize);

        auto nspListBuf = std::make_unique<char[]>(header.nspListSize+1);
        std::vector<std::string> nspNames;
        memset(nspListBuf.get(), 0, header.nspListSize+1);

        tin::util::USBRead(nspListBuf.get(), header.nspListSize);

        // Split the string up into individual nsp names
        std::stringstream nspNameStream(nspListBuf.get());
        std::string segment;
        std::string nspExt = ".nsp";
        std::string nszExt = ".nsz";

        while (std::getline(nspNameStream, segment, '\n'))
        {
            if (segment.compare(segment.size() - nspExt.size(), nspExt.size(), nspExt) == 0 || segment.compare(segment.size() - nszExt.size(), nszExt.size(), nszExt) == 0)
                nspNames.push_back(segment);
        }

        auto selectView = std::make_unique<tin::ui::ConsoleCheckboxView>(std::bind(&USBInstallMode::OnNSPSelected, this), DEFAULT_TITLE, 2);
        selectView->AddEntry(translate(Translate::NSP_SELECT), tin::ui::ConsoleEntrySelectType::HEADING, nullptr);
        selectView->AddEntry("", tin::ui::ConsoleEntrySelectType::NONE, nullptr);

        for (auto& nspName : nspNames)
        {
            LOG_DEBUG("NSP Name: %s\n", nspName.c_str());
            selectView->AddEntry(nspName, tin::ui::ConsoleEntrySelectType::SELECT, nullptr);
        }
        manager.PushView(std::move(selectView));
    }

    void USBInstallMode::OnNSPSelected()
    {
        tin::ui::ViewManager& manager = tin::ui::ViewManager::Instance();
        ConsoleCheckboxView* prevView;

        if (!(prevView = reinterpret_cast<ConsoleCheckboxView*>(manager.GetCurrentView())))
        {
            throw std::runtime_error("Previous view must be a ConsoleCheckboxView!");
        }

        auto values = prevView->GetSelectedOptionValues();
        m_nspNames.clear();

        for (auto& destStr : values)
        {
            m_nspNames.push_back(destStr->GetText());
        }

        auto view = std::make_unique<tin::ui::ConsoleOptionsView>(DEFAULT_TITLE);
        view->AddEntry(translate(Translate::NSP_INSTALL_SELECT_DESTINATION), tin::ui::ConsoleEntrySelectType::HEADING, nullptr);
        view->AddEntry("", tin::ui::ConsoleEntrySelectType::NONE, nullptr);
        view->AddEntry(translate(Translate::SDCARD), tin::ui::ConsoleEntrySelectType::SELECT, std::bind(&USBInstallMode::OnDestinationSelected, this));
        view->AddEntry(translate(Translate::NAND), tin::ui::ConsoleEntrySelectType::SELECT, std::bind(&USBInstallMode::OnDestinationSelected, this));
        manager.PushView(std::move(view));
    }

    void USBInstallMode::OnDestinationSelected()
    {
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

        auto view = std::make_unique<tin::ui::ConsoleView>(4);
        manager.PushView(std::move(view));

        for (auto& nspName : m_nspNames)
        {
            tin::install::nsp::USBNSP usbNSP(nspName);

            printf("%s %s\n", translate(Translate::NSP_INSTALL_FROM), nspName.c_str());
            tin::install::nsp::RemoteNSPInstall install(m_destStorageId, Options().GetIgnoreFirmwareVersion(), &usbNSP);

            printf("%s\n", translate(Translate::NSP_INSTALL_PREPARING));
            install.Prepare();
            LOG_DEBUG("Pre Install Records: \n");
            install.DebugPrintInstallData();
            install.Begin();
            LOG_DEBUG("Post Install Records: \n");
            install.DebugPrintInstallData();
            printf("\n");
        }

        tin::util::USBCmdManager::SendExitCmd();
        printf("\n Press (B) to return.");

        consoleUpdate(NULL);
    }
}