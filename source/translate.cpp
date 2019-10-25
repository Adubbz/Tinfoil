#include <switch.h>
#include "translate.h"
#include "options.h"
#include <cstring>

Language g_languageId;

void setCurrentLanguage(const Language& languageId)
{
    if ((u8)languageId == (u8)Language::Type::None)
    {
        g_languageId = Options().GetLanguage();
    }
    else
    {
        g_languageId = languageId;
    }
}


#include "translate_data.h"


const char* translate(const Translate& key)
{
    const char* t = g_translations[(u32)g_languageId][(u32)key];

    if (!t)
    {
        return "";
    }

    return t;
}