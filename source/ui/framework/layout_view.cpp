#include "ui/framework/layout_view.hpp"

#include <switch.h>
#include "error.hpp"

namespace tin::ui
{
    LayoutView::LayoutView(unsigned int unwindDistance) :
        m_unwindDistance(unwindDistance)
    {

    }

    void LayoutView::OnPresented()
    {
        consoleClear();
    }

    void LayoutView::ProcessInput(u64 keys)
    {
        if (keys & KEY_B)
            m_viewManager->Unwind(m_unwindDistance);
    }

    void LayoutView::Update()
    {        
        for (auto& layer : m_layers)
        {
            layer->UpdateLayer();
            layer->DrawLayer();
        }
    }

    void LayoutView::AddLayer(std::unique_ptr<Layer> layer)
    {
        m_layers.push_back(std::move(layer));
    }
}