#include "mode/network_install_mode.hpp"

#include <cstring>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sstream>
#include <curl/curl.h>

#include <switch.h>
#include "nx/ipc/tin_ipc.h"
#include "ui/framework/console_view.hpp"
#include "ui/framework/console_checkbox_view.hpp"
#include "util/network_util.hpp"
#include "install/install_nsp_remote.hpp"
#include "install/http_nsp.hpp"
#include "debug.h"
#include "error.hpp"

namespace tin::ui
{
    const unsigned int MAX_URL_SIZE = 1024;
    const unsigned int MAX_URLS = 256;
    const int REMOTE_INSTALL_PORT = 2000;
    static int m_serverSocket = 0;
    static int m_clientSocket = 0;

    NetworkInstallMode::NetworkInstallMode() :
        IMode("Network Install NSP")
    {
    }

    NetworkInstallMode::~NetworkInstallMode()
    {
        if (m_serverSocket != 0)
        {
            close(m_serverSocket);
            m_serverSocket = 0;
        }
    }

    void NetworkInstallMode::InitializeServerSocket() try
    {
        // Create a socket
        m_serverSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
    
        if (m_serverSocket < -1)
        {
            THROW_FORMAT("Failed to create a server socket. Error code: %u\n", errno);
        }

        struct sockaddr_in server;
        server.sin_family = AF_INET;
        server.sin_port = htons(REMOTE_INSTALL_PORT);
        server.sin_addr.s_addr = htonl(INADDR_ANY);

        if (bind(m_serverSocket, (struct sockaddr*) &server, sizeof(server)) < 0)
        {
            THROW_FORMAT("Failed to bind server socket. Error code: %u\n", errno);
        }

        // Set as non-blocking
        fcntl(m_serverSocket, F_SETFL, fcntl(m_serverSocket, F_GETFL, 0) | O_NONBLOCK);

        if (listen(m_serverSocket, 5) < 0) 
        {
            THROW_FORMAT("Failed to listen on server socket. Error code: %u\n", errno);
        }
    }
    catch (std::exception& e)
    {
        printf("Failed to initialize server socket!\n");
        fprintf(stdout, "%s", e.what());

        if (m_serverSocket != 0)
        {
            close(m_serverSocket);
            m_serverSocket = 0;
        }
    }

    void NetworkInstallMode::OnUnwound()
    {
        LOG_DEBUG("unwinding view\n");
        if (m_clientSocket != 0)
        {
            close(m_clientSocket);
            m_clientSocket = 0;
        }

        curl_global_cleanup();
        #ifndef NXLINK_DEBUG
        socketExit();
        #endif
    }

    void NetworkInstallMode::OnSelected()
    {
        tin::ui::ViewManager& manager = tin::ui::ViewManager::Instance();
        auto view = std::make_unique<tin::ui::ConsoleView>();
        LOG_DEBUG("setting onUnwound...\n");
        view->m_onUnwound = std::bind(&NetworkInstallMode::OnUnwound, this);
        manager.PushView(std::move(view));

        try
        {
            #ifndef NXLINK_DEBUG
            ASSERT_OK(socketInitializeDefault(), "Failed to initialize socket");
            #endif
            ASSERT_OK(curl_global_init(CURL_GLOBAL_ALL), "Curl failed to initialized");

            // Initialize the server socket if it hasn't already been
            if (m_serverSocket == 0)
            {
                this->InitializeServerSocket();

                if (m_serverSocket <= 0)
                {
                    THROW_FORMAT("Server socket failed to initialize.\n");
                }
            }

            struct in_addr addr = {(in_addr_t) gethostid()};

            printf("Switch IP is %s\n", inet_ntoa(addr));
            printf("Waiting for connection...\n");
            printf("Press B to cancel\n");
            
            std::vector<std::string> urls;

            bool canceled = false;

            // Do this now because otherwise we won't get an opportunity whilst waiting
            // in the loop
            consoleUpdate(NULL);

            while (true)
            {
                // Break on input pressed
                hidScanInput();
                u64 kDown = hidKeysDown(CONTROLLER_P1_AUTO);

                consoleUpdate(NULL);

                if (kDown & KEY_B)
                {
                    canceled = true;
                    break;
                }

                struct sockaddr_in client;
                socklen_t clientLen = sizeof(client);

                m_clientSocket = accept(m_serverSocket, (struct sockaddr*)&client, &clientLen);

                if (m_clientSocket >= 0)
                {
                    printf("Accepted client connection\n");
                    u32 size = 0;
                    tin::network::WaitReceiveNetworkData(m_clientSocket, &size, sizeof(u32));
                    size = ntohl(size);

                    LOG_DEBUG("Received url buf size: 0x%x\n", size);

                    if (size > MAX_URL_SIZE * MAX_URLS)
                    {
                        THROW_FORMAT("URL size %x is too large!\n", size);
                    }

                    // Make sure the last string is null terminated
                    auto urlBuf = std::make_unique<char[]>(size+1);
                    memset(urlBuf.get(), 0, size+1);

                    tin::network::WaitReceiveNetworkData(m_clientSocket, urlBuf.get(), size);

                    // Split the string up into individual URLs
                    std::stringstream urlStream(urlBuf.get());
                    std::string segment;
                    std::string nspExt = ".nsp";

                    while (std::getline(urlStream, segment, '\n'))
                    {
                        if (segment.compare(segment.size() - nspExt.size(), nspExt.size(), nspExt) == 0)
                            urls.push_back(segment);
                    }

                    break;
                }
                else if (errno != EAGAIN)
                {
                    THROW_FORMAT("Failed to open client socket with code %u\n", errno);
                }
            }

            if (!canceled)
            {
                auto view = std::make_unique<tin::ui::ConsoleCheckboxView>(std::bind(&NetworkInstallMode::OnNSPSelected, this), DEFAULT_TITLE, 2);
                view->AddEntry("Select NSP to install", tin::ui::ConsoleEntrySelectType::HEADING, nullptr);
                view->AddEntry("", tin::ui::ConsoleEntrySelectType::NONE, nullptr);
                
                for (auto& url : urls)
                {
                    view->AddEntry(url, tin::ui::ConsoleEntrySelectType::SELECT, nullptr);
                }
                manager.PushView(std::move(view));
            }
            else
                manager.Unwind(1);
        }
        catch (std::runtime_error& e)
        {
            printf("Failed to perform remote install!\n");
            LOG_DEBUG("Failed to perform remote install");
            LOG_DEBUG("%s", e.what());
            fprintf(stdout, "%s", e.what());
        }
    }

    void NetworkInstallMode::OnNSPSelected()
    {
        tin::ui::ViewManager& manager = tin::ui::ViewManager::Instance();
        ConsoleCheckboxView* prevView;

        if (!(prevView = reinterpret_cast<ConsoleCheckboxView*>(manager.GetCurrentView())))
        {
            throw std::runtime_error("Previous view must be a ConsoleCheckboxView!");
        }

        auto values = prevView->GetSelectedOptionValues();

        for (auto& destStr : values)
        {
            m_urls.push_back(destStr->GetText());
        }

        auto view = std::make_unique<tin::ui::ConsoleOptionsView>(DEFAULT_TITLE);
        view->AddEntry("Select Destination", tin::ui::ConsoleEntrySelectType::HEADING, nullptr);
        view->AddEntry("", tin::ui::ConsoleEntrySelectType::NONE, nullptr);
        view->AddEntry("SD Card", tin::ui::ConsoleEntrySelectType::SELECT, std::bind(&NetworkInstallMode::OnDestinationSelected, this));
        view->AddEntry("NAND", tin::ui::ConsoleEntrySelectType::SELECT, std::bind(&NetworkInstallMode::OnDestinationSelected, this));
        manager.PushView(std::move(view));
    }

    void NetworkInstallMode::OnDestinationSelected()
    {
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

        auto view = std::make_unique<tin::ui::ConsoleView>(4);
        manager.PushView(std::move(view));
                    
        for (auto& url : m_urls)
        {
            tin::install::nsp::HTTPNSP httpNSP(url);

            printf("Installing from %s\n", url.c_str());
            tin::install::nsp::RemoteNSPInstall install(m_destStorageId, false, &httpNSP);

            printf("Preparing install...\n");
            install.Prepare();
            LOG_DEBUG("Pre Install Records: \n");
            install.DebugPrintInstallData();
            install.Begin();
            LOG_DEBUG("Post Install Records: \n");
            install.DebugPrintInstallData();
            printf("\n");
        }

        printf("Sending ack...\n");
        // Send 1 byte ack to close the server
        u8 ack = 0;
        tin::network::WaitSendNetworkData(m_clientSocket, &ack, sizeof(u8));
        printf("\n Press (B) to return.");

        consoleUpdate(NULL);
    }
}
