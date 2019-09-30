#include "install/simple_filesystem.hpp"

#include <exception>
#include <memory>
#include "nx/fs.hpp"
#include "error.hpp"

namespace tin::install::nsp
{
    SimpleFileSystem::SimpleFileSystem(nx::fs::IFileSystem& fileSystem, std::string rootPath, std::string absoluteRootPath) :
        m_fileSystem(&fileSystem) , m_rootPath(rootPath), m_absoluteRootPath(absoluteRootPath)
    {}

    SimpleFileSystem::~SimpleFileSystem() {}

    nx::fs::IFile SimpleFileSystem::OpenFile(std::string path)
    {
        return m_fileSystem->OpenFile(m_rootPath + path);
    }

    bool SimpleFileSystem::HasFile(std::string path)
    {
        try
        {
            LOG_DEBUG(("Attempting to find file at " + m_rootPath + path + "\n").c_str());
            m_fileSystem->OpenFile(m_rootPath + path);
            return true;
        }
        catch (std::exception& e) {}
        return false;
    }

    std::string SimpleFileSystem::GetFileNameFromExtension(std::string path, std::string extension)
    {
        nx::fs::IDirectory dir = m_fileSystem->OpenDirectory(m_rootPath + path, FsDirOpenMode_ReadFiles | FsDirOpenMode_ReadDirs);

        u64 entryCount = dir.GetEntryCount();
        auto dirEntries = std::make_unique<FsDirectoryEntry[]>(entryCount);

        dir.Read(0, dirEntries.get(), entryCount);

        for (unsigned int i = 0; i < entryCount; i++)
        {
            FsDirectoryEntry dirEntry = dirEntries[i];
            std::string dirEntryName = dirEntry.name;

            if (dirEntry.type == FsDirEntryType_Dir)
            {
                auto subdirPath = path + dirEntryName + "/";
                auto subdirFound = this->GetFileNameFromExtension(subdirPath, extension);

                if (subdirFound != "")
                    return subdirFound;
                continue;
            }
            else if (dirEntry.type == FsDirEntryType_File)
            {
                auto foundExtension = dirEntryName.substr(dirEntryName.find(".") + 1); 

                if (foundExtension == extension)
                    return dirEntryName;
            }
        }

        return "";
    }
}