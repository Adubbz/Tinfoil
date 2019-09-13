#include "ui/framework/canvas.hpp"

#include "error.hpp"

namespace tin::ui
{
    Canvas::Canvas() :
       m_restrictionPosition(0, 0), m_restrictionDimensions(1280, 720)
    {

    }

    Canvas::Canvas(Position restrictionPosition, Dimensions restrictionDimensions) :
        m_restrictionPosition(restrictionPosition), m_restrictionDimensions(restrictionDimensions)
    {
        
    }

    void Canvas::DrawPixel(u32 x, u32 y, Colour colour, bool restricted)
    {
        if (x >= 1280 || y >= 720)
            return;

        if (restricted && (x < m_restrictionPosition.x || x >= (m_restrictionPosition.x + m_restrictionDimensions.width) || y < m_restrictionPosition.y || y >= ((m_restrictionPosition.y + m_restrictionDimensions.height))))
            return;

        /*u32 off = (y * g_framebufWidth + x) * 4;
        *((u32*)&g_framebuf[off]) = colour.r | (colour.g << 8) | (colour.b << 16) | (0xff << 24);*/
    }

    void Canvas::DrawPixelBlend(u32 x, u32 y, Colour colour, bool restricted)
    {
        if (x >= 1280 || y >= 720)
            return;

        /*u32 off = (y * g_framebufWidth + x) * 4;

        u8 r = BlendColour(g_framebuf[off], colour.r, colour.a); off++;
        u8 g = BlendColour(g_framebuf[off], colour.g, colour.a); off++;
        u8 b = BlendColour(g_framebuf[off], colour.b, colour.a); off++;

        this->DrawPixel(x, y, Colour(r, g, b, 0xFF), restricted);*/
    }

    Canvas Canvas::Intersect(Position pos, Dimensions dimensions)
    {
        u32 rStartX = m_restrictionPosition.x;
        u32 rStartY = m_restrictionPosition.y;
        u32 rEndX = rStartX + m_restrictionDimensions.width;
        u32 rEndY = rStartY + m_restrictionDimensions.height;

        u32 newStartX = pos.x;
        u32 newStartY = pos.y;
        u32 newEndX = pos.x + dimensions.width;
        u32 newEndY = pos.y + dimensions.height;

        if (newStartX < rStartX) newStartX = rStartX;
        else if (newStartX > rEndX) return Canvas(Position(0, 0), Dimensions(0, 0));

        if (newStartY < rStartY) newStartY = rStartY;
        else if (newStartY > rEndY) return Canvas(Position(0, 0), Dimensions(0, 0));

        if (newEndX > rEndX) newEndX = rEndX;
        else if (newEndX < rStartX) return Canvas(Position(0, 0), Dimensions(0, 0));

        if (newEndY > rEndY) newEndY = rEndY;
        else if (newEndY < rStartY) return Canvas(Position(0, 0), Dimensions(0, 0));

        return Canvas(Position(newStartX, newStartY), Dimensions(newEndX - newStartX, newEndY - newStartY));
    }
}