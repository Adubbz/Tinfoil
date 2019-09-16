#include "ui/framework/list_element.hpp"

#include "error.hpp"

namespace tin::ui
{
    RowElement::RowElement(u32 width) :
        BoxElement(width, ROW_HEIGHT)
    {
        SubElementLayout rowSubElementLayout;
        rowSubElementLayout.arrangementType = SubElementArrangementType::BOTTOM_TO_TOP;
        this->SetColour(Colour(0, 0, 0, 0));
        this->SetSubElementLayout(rowSubElementLayout);

        auto underlineElement = std::make_unique<BoxElement>(m_dimensions.width, 3);
        m_underlineElement = underlineElement.get();
        underlineElement->SetColour(0x556C91);
        this->AddSubElement(std::move(underlineElement));

        auto contentElement = std::make_unique<BoxElement>(m_dimensions.width, m_dimensions.height - 3);
        SubElementLayout contentSubElementLayout;
        contentSubElementLayout.arrangementType = SubElementArrangementType::LEFT_TO_RIGHT;
        contentElement->SetColour(Colour(0, 0, 0, 0));
        contentElement->SetSubElementLayout(contentSubElementLayout);

        auto textElement = std::make_unique<TextElement>(m_dimensions.width * 0.8, m_dimensions.height);
        m_textElement = textElement.get();
        textElement->SetScale(5);
        textElement->SetColour(0xC3D0DF);
        textElement->SetInsets(0, 30);

        contentElement->AddSubElement(std::move(textElement));
        this->AddSubElement(std::move(contentElement));
    }

    void RowElement::SetSelected(bool value)
    {
        if (value)
        {
            m_isSelected = true;
            this->SetColour(0x2B324E);
            m_textElement->SetColour(0xFFFFFF);
        }
        else
        {
            m_isSelected = false;
            this->SetColour(Colour(0, 0, 0, 0));
            m_textElement->SetColour(0xC3D0DF);
        }
    }

    ListElement::ListElement(u32 width, u32 height) :
        BoxElement(width, height)
    {
        this->SetColour(Colour(0, 0, 0, 0));

        SubElementLayout subElementLayout;
        subElementLayout.arrangementType = SubElementArrangementType::TOP_TO_BOTTOM;
        this->SetSubElementLayout(subElementLayout);

        m_touchHandler.m_onTouchesStarted = [&](unsigned int posX, unsigned int posY)
        {
            m_startScrollOffset = m_scrollOffset;
        };

        m_touchHandler.m_onTouchesMoving = [&](unsigned int startX, unsigned int startY, signed int distX, unsigned int distY)
        {
            m_scrollOffset = m_startScrollOffset - distY;

            // Subtract 3 to cut off the final underline
            int maxScroll = RowElement::ROW_HEIGHT * m_subElements.size() - m_dimensions.height - 3;

            // Don't allow scrolling if there is not enough elements
            if (maxScroll < 0)
                maxScroll = 0;

            if (m_scrollOffset < 0)
                m_scrollOffset = 0;

            if (m_scrollOffset > maxScroll)
                m_scrollOffset = maxScroll;
        };

        m_touchHandler.m_onTapped = [&](unsigned int posX, unsigned int posY)
        {
            unsigned int row = (posY - m_touchHandler.GetTouchAreaPos().y + m_scrollOffset) / RowElement::ROW_HEIGHT;
            RowElement* rowElement = reinterpret_cast<RowElement*>(m_subElements.at(row).get());
            rowElement->SetSelected(!rowElement->m_isSelected);
        };
    }

    void ListElement::Draw(Canvas canvas, Position position)
    {
        // No need to draw sub elements if we don't have any
        if (m_subElements.empty())
            return;

        Position scrollPos = position;
        scrollPos.y = position.y - m_scrollOffset;
            
        unsigned int startOffset = 0;

        for (auto& subElement : m_subElements)
        {
            unsigned int startX = scrollPos.x;
            unsigned int startY = scrollPos.y + startOffset;

            Position subElementPos(startX, startY);
            // NOTE: The canvas is still whilst the list itself moves
            Canvas subElementCanvas = canvas.Intersect(position, this->GetDimensions()).Intersect(subElementPos, subElement->GetDimensions());
            
            subElement->Draw(subElementCanvas, subElementPos);
            startOffset += subElement->GetDimensions().height + m_subElementLayout.gapSize;
        }
    }

    void ListElement::Update(Position position)
    {
        m_touchHandler.SetTouchArea(position, m_dimensions);
        m_touchHandler.Update();
    }

    void ListElement::AddRow(const char* text)
    {
        auto rowElement = std::make_unique<RowElement>(m_dimensions.width);
        rowElement->m_textElement->SetText(text);
        this->AddSubElement(std::move(rowElement));
    }
}