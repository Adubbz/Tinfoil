#include "install/verify_nsp.hpp"

#include <exception>
#include <string>
#include <tuple>

#include <switch.h>
#include "install/simple_filesystem.hpp"
#include "install/verify_nsp.hpp"
#include "nx/fs.hpp"
#include "nx/ncm.hpp"
#include "util/file_util.hpp"
#include "util/title_util.hpp"

#ifdef __VERIFY_NSP__
namespace tin::install
{
    NSPVerifier::NSPVerifier(std::string nspPath) :
        m_nspPath(nspPath)
    {

    }

    bool NSPVerifier::PerformVerification()
    {
        bool isComplete = true;
        nx::fs::IFileSystem nspFileSystem;

        try
        {
            nspFileSystem.OpenFileSystemWithId(m_nspPath, FsFileSystemType_ApplicationPackage, 0);
        }
        catch (std::exception& e)
        {
            this->PrintCritical("NSP is invalid and cannot be opened! Error: " + std::string(e.what()));
            printf("> NSP Path: %s\n", m_nspPath.c_str());
            return false;
        }
        this->PrintSuccess("PFS0 structure is valid");

        tin::install::nsp::SimpleFileSystem simpleFS(nspFileSystem, "/", m_nspPath + "/");

        std::string cnmtNCAPath;
        NcmContentInfo cnmtContentRecord;
        nx::ncm::ContentMeta contentMeta;

        try
        {
            std::tie(cnmtNCAPath, cnmtContentRecord) = tin::util::GetCNMTNCAInfo(m_nspPath);
        }
        catch (std::exception& e)
        {
            this->PrintCritical("Failed to find CNMT NCA. Error: " + std::string(e.what()));
            return false;
        }
        
        try
        {
            contentMeta = tin::util::GetContentMetaFromNCA(cnmtNCAPath);
        }
        catch (std::exception& e)
        {
            this->PrintCritical("Content meta could not be read. Error: " + std::string(e.what()));
            return false;
        }
        this->PrintSuccess("Successfully read content meta.");

        if (!simpleFS.HasFile(tin::util::GetNcaIdString(cnmtContentRecord.content_id) + ".cnmt.xml"))
            this->PrintWarning("CNMT XML is absent!");
        else
            this->PrintSuccess("CNMT XML is present.");

        auto contentMetaHeader = contentMeta.GetContentMetaHeader();
        u64 titleId = tin::util::GetBaseTitleId(contentMetaHeader.titleId, contentMetaHeader.type);

        for (NcmContentInfo contentRecord : contentMeta.GetContentRecords())
        {
            std::string ncaIdStr = tin::util::GetNcaIdString(contentRecord.content_id);
            std::string ncaName = ncaIdStr + ".nca";
            std::string xmlName = ncaIdStr + ".";

            if (simpleFS.HasFile(ncaName))
                this->PrintSuccess(ncaName + " is present.");
            else
            {
                this->PrintCritical(ncaName + " is missing!");
                return false;
            }

            // control, legalinfo

            switch (contentRecord.contentType)
            {
                case NcmContentType_Program:
                    xmlName += "programinfo.xml";
                    break;

                case NcmContentType_Data:
                    xmlName = "";
                    break;

                case NcmContentType_Control:
                    try
                    {
                        nx::fs::IFileSystem controlFileSystem;
                        controlFileSystem.OpenFileSystemWithId(m_nspPath + "/" + ncaName, FsFileSystemType_ContentControl, titleId);
                    }
                    catch (std::exception& e)
                    {
                        this->PrintCritical("Control NCA could not be read. Error: " + std::string(e.what()));
                        return false;
                    }
                    this->PrintSuccess("Control NCA is valid.");

                    xmlName += "nacp.xml";
                    break;

                case NcmContentType_HtmlDocument:
                    xmlName += "htmldocument.xml";
                    break;

                case NcmContentType_LegalInformation:
                    try
                    {
                        nx::fs::IFileSystem legalInfoFileSystem;
                        legalInfoFileSystem.OpenFileSystemWithId(m_nspPath + "/" + ncaName, FsFileSystemType_ContentManual, titleId);
                    }
                    catch (std::exception& e)
                    {
                        this->PrintCritical("Legal information NCA could not be read. Error: " + std::string(e.what()));
                        return false;
                    }
                    this->PrintSuccess("Legal information NCA is valid.");

                    xmlName += "legalinfo.xml";
                    break;

                // We ignore delta fragments (for now) since they aren't all included,
                // and we don't install them
                case NcmContentType_DeltaFragment:
                    continue;

                default:
                    this->PrintCritical("Unrecognized content type!");
                    return false;
            }

            if (xmlName == "")
                continue;

            if (simpleFS.HasFile(xmlName))
                this->PrintSuccess(xmlName + " is present.");
            else
            {
                this->PrintWarning(xmlName + " is missing!");
                isComplete = false;
            }
        }

        if (isComplete)
            this->PrintSuccess("NSP is valid.");
        else
            this->PrintWarning("NSP is installable, but incomplete.");

        return true;
    }

    void NSPVerifier::PrintCritical(std::string text)
    {
        printf("[%sCRITICAL%s] %s\n", CONSOLE_RED, CONSOLE_RESET, text.c_str());
    }

    void NSPVerifier::PrintWarning(std::string text)
    {
        printf("[%sWARNING%s] %s\n", CONSOLE_YELLOW, CONSOLE_RESET, text.c_str());
    }

    void NSPVerifier::PrintSuccess(std::string text)
    {
        printf("[%sOK%s] %s\n", CONSOLE_GREEN, CONSOLE_RESET, text.c_str());
    }
}
#endif