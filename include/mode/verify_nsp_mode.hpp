#pragma once

#ifdef __VERIFY_NSP__
#include <string>
#include <switch.h>
#include "mode/mode.hpp"

namespace tin::ui
{
    class VerifyNSPMode : public IMode
    {
        public:
            VerifyNSPMode();

            void OnSelected() override;
            void OnNSPSelected();
    };
}
#endif