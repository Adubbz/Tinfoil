#pragma once

#ifdef __VERIFY_NSP__
#include <string>

namespace tin::install
{
    enum class VerificationErrorType
    {
        CRITICAL, WARNING
    };

    enum class VerificationLevel
    {
        ERROR_ALL, ERROR_CRITICAL_WARN, ERROR_CRITICAL_IGNORE_WARN, WARN_ALL
    };

    class NSPVerifier
    {
        private:
            std::string m_nspPath;

        public:
            NSPVerifier(std::string nspPath);

            bool PerformVerification();

            void PrintCritical(std::string text);
            void PrintWarning(std::string text);
            void PrintSuccess(std::string text);
    };
}
#endif