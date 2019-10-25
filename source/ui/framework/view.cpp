#include "ui/framework/view.hpp"

extern bool g_shouldExit;

namespace tin::ui
{
    ViewManager::ViewManager() {}

    ViewManager& ViewManager::Instance()
    {
        static ViewManager instance;
        return instance;
    }

    void ViewManager::PushView(std::unique_ptr<View> view)
    {
        if (m_views.size() > 0)
        {
            view->m_prevView = this->GetCurrentView();
        }

        view->m_viewManager = this;
        view->OnPresented();
        m_views.push(std::move(view));
    }

    void ViewManager::Unwind(unsigned int count)
    {
        if (m_views.size() > 1 && count > 0)
        {
            for (unsigned int i = 0; i < count; i++)
            {
                View* view = m_views.top().get();
                if (view->m_onUnwound != nullptr)
                    view->m_onUnwound();
                m_views.pop();
            }

            this->GetCurrentView()->OnPresented();
        }
        else
        {
            g_shouldExit = true;
        }
    }

    void ViewManager::ProcessInput(u64 keys)
    {
        this->GetCurrentView()->ProcessInput(keys);
    }

    void ViewManager::Update()
    {
        this->GetCurrentView()->Update();
    }

    View* ViewManager::GetCurrentView()
    {
        return m_views.top().get();
    }
}