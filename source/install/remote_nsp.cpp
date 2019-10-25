#include "install/remote_nsp.hpp"

#include <threads.h>
#include "data/buffered_placeholder_writer.hpp"
#include "util/title_util.hpp"
#include "error.hpp"
#include "debug.h"

namespace tin::install::nsp
{
    RemoteNSP::RemoteNSP()
    {

    }

    // TODO: Do verification: PFS0 magic, sizes not zero
    void RemoteNSP::RetrieveHeader()
    {
        printf("Retrieving remote NSP header...\n");

        // Retrieve the base header
        m_headerBytes.resize(sizeof(PFS0BaseHeader), 0);
        this->BufferData(m_headerBytes.data(), 0x0, sizeof(PFS0BaseHeader));

        LOG_DEBUG("Base header: \n");
        printBytes(nxlinkout, m_headerBytes.data(), sizeof(PFS0BaseHeader), true);

        // Retrieve the full header
        size_t remainingHeaderSize = this->GetBaseHeader()->numFiles * sizeof(PFS0FileEntry) + this->GetBaseHeader()->stringTableSize;
        m_headerBytes.resize(sizeof(PFS0BaseHeader) + remainingHeaderSize, 0);
        this->BufferData(m_headerBytes.data() + sizeof(PFS0BaseHeader), sizeof(PFS0BaseHeader), remainingHeaderSize);

        LOG_DEBUG("Full header: \n");
        printBytes(nxlinkout, m_headerBytes.data(), m_headerBytes.size(), true);
    }

    const PFS0FileEntry* RemoteNSP::GetFileEntry(unsigned int index)
    {
        if (index >= this->GetBaseHeader()->numFiles)
            THROW_FORMAT("File entry index is out of bounds\n")

        size_t fileEntryOffset = sizeof(PFS0BaseHeader) + index * sizeof(PFS0FileEntry);

        if (m_headerBytes.size() < fileEntryOffset + sizeof(PFS0FileEntry))
            THROW_FORMAT("Header bytes is too small to get file entry!");

        return reinterpret_cast<PFS0FileEntry*>(m_headerBytes.data() + fileEntryOffset);
    }

    const PFS0FileEntry* RemoteNSP::GetFileEntryByExtension(std::string extension)
    {
        for (unsigned int i = 0; i < this->GetBaseHeader()->numFiles; i++)
        {
            const PFS0FileEntry* fileEntry = this->GetFileEntry(i);
            std::string name(this->GetFileEntryName(fileEntry));
            auto foundExtension = name.substr(name.find(".") + 1); 

            if (foundExtension == extension)
                return fileEntry;
        }

        return nullptr;
    }

    const PFS0FileEntry* RemoteNSP::GetFileEntryByName(std::string name)
    {
        for (unsigned int i = 0; i < this->GetBaseHeader()->numFiles; i++)
        {
            const PFS0FileEntry* fileEntry = this->GetFileEntry(i);
            std::string foundName(this->GetFileEntryName(fileEntry));

            if (foundName == name)
                return fileEntry;
        }

        return nullptr;
    }

    const PFS0FileEntry* RemoteNSP::GetFileEntryByNcaId(const NcmNcaId& ncaId)
    {
        const PFS0FileEntry* fileEntry = nullptr;
        std::string ncaIdStr = tin::util::GetNcaIdString(ncaId);

        if ((fileEntry = this->GetFileEntryByName(ncaIdStr + ".nca")) == nullptr)
        {
            if ((fileEntry = this->GetFileEntryByName(ncaIdStr + ".cnmt.nca")) == nullptr)
            {
                    if ((fileEntry = this->GetFileEntryByName(ncaIdStr + ".ncz")) == nullptr)
                    {
                         if ((fileEntry = this->GetFileEntryByName(ncaIdStr + ".cnmt.ncz")) == nullptr)
                         {
                              return nullptr;
                         }
                    }
            }
        }

        return fileEntry;
    }

    const char* RemoteNSP::GetFileEntryName(const PFS0FileEntry* fileEntry)
    {
        u64 stringTableStart = sizeof(PFS0BaseHeader) + this->GetBaseHeader()->numFiles * sizeof(PFS0FileEntry);
        return reinterpret_cast<const char*>(m_headerBytes.data() + stringTableStart + fileEntry->stringTableOffset);
    }

    const PFS0BaseHeader* RemoteNSP::GetBaseHeader()
    {
        if (m_headerBytes.empty())
            THROW_FORMAT("Cannot retrieve header as header bytes are empty. Have you retrieved it yet?\n");

        return reinterpret_cast<PFS0BaseHeader*>(m_headerBytes.data());
    }

    u64 RemoteNSP::GetDataOffset()
    {
        if (m_headerBytes.empty())
            THROW_FORMAT("Cannot get data offset as header is empty. Have you retrieved it yet?\n");

        return m_headerBytes.size();
    }
}