#include <switch.h>
#include "options.h"
#include "rapidjson/document.h"

OptionsContext* g_options = NULL;

const OptionsContext& Options()
{
    if (!g_options) {
        g_options = new OptionsContext();
    }

    return *g_options;
}

OptionsContext::OptionsContext() : m_ignoreFirmwareVersion(true), m_language(Language::Type::en)
{
    if (!Load()) {
        printf("error loading options.json\n");
    }
}

OptionsContext::~OptionsContext()
{
}

bool OptionsContext::Load()
{
    FILE* f = fopen("sdmc:/switch/options.json", "r");

    if (!f)
    {
        return false;
    }

    if (fseek(f, 0, SEEK_END) < 0)
    {
        fclose(f);
        throw std::runtime_error("error seeking end of options file");
        return false;
    }

    auto sz = ftell(f);

    if (sz < 1)
    {
        fclose(f);
        return false;
    }

    if (fseek(f, 0, SEEK_SET) < 0)
    {
        fclose(f);
        throw std::runtime_error("error seeking beginning of options file");
        return false;
    }

    char* buffer = (char*)malloc(sz + 1);
    if (!buffer) {
        fclose(f);
        throw std::runtime_error("out of memory");
        return false;
    }

    memset(buffer, 0, sz);
    auto bytesRead = fread(buffer, 1, sz, f);

    if (bytesRead < 1)
    {
        free(buffer);
        fclose(f);
        throw std::runtime_error("efailed to read options file");
        return false;
    }

    buffer[sz] = '\0';
    rapidjson::Document document;
    document.Parse(buffer);

    if (document.IsObject())
    {
        if (document.HasMember("language") && document["language"].IsString())
        {
            m_language = std::string(document["language"].GetString());
        }

        if (document.HasMember("ignore_firmware_version") && document["ignore_firmware_version"].IsInt())
        {
            m_ignoreFirmwareVersion = document["ignore_firmware_version"].GetInt();
        }
    }
    else
    {
        throw std::runtime_error("invalid options.json format");
    }

    free(buffer);
    fclose(f);
    return true;
}

bool OptionsContext::Save()
{
    return false;
}