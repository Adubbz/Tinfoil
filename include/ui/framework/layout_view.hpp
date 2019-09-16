#pragma once

#include "ui/framework/view.hpp"

#include <memory>
#include <vector>

namespace tin::ui
{
    class LayoutView : public View
    {
        protected:

            unsigned int m_unwindDistance = 1;

            virtual void OnPresented() override;
            virtual void ProcessInput(u64 keys) override;
            virtual void Update() override;

        public:
            LayoutView(unsigned int unwindDistance = 1);
    };
}