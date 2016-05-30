using System;
using System.Drawing;
using System.Drawing.Drawing2D;
using PdfSharp.Drawing;

namespace XDrawing.TestLab.Tester
{
  /// <summary>
  /// Demonstrates the use of XGraphics.DrawString.
  /// </summary>
  public class TestText01 : TesterBase
  {
    public TestText01()
    {
    }

    public override void RenderPage(XGraphics gfx)
    {
      base.RenderPage(gfx);

      string text = "TgfÄÖÜWi9";
      if (this.properties.Font1.Text != "")
        text = this.properties.Font1.Text;
      float x = 100, y = 300;
      string familyName = properties.Font1.FamilyName;
      XFontStyle style = this.properties.Font1.Style;
      float emSize = this.properties.Font1.Size;

      //familyName = "Verdana";
      //style = XFontStyle.Regular;
      //emSize = 20;
      //text = "X";

      XFont font = CreateFont(familyName, emSize, style);
      //font = this.properties.Font1.Font;
      XSize size = gfx.MeasureString(text, font);

      double lineSpace = font.GetHeight(gfx);
      int cellSpace = font.FontFamily.GetLineSpacing(style);
      int cellAscent = font.FontFamily.GetCellAscent(style);
      int cellDescent = font.FontFamily.GetCellDescent(style);
      int cellLeading = cellSpace - cellAscent - cellDescent;

      double ascent = lineSpace * cellAscent / cellSpace;
      gfx.DrawRectangle(XBrushes.Bisque, x, y - ascent, size.Width, ascent);

      double descent = lineSpace * cellDescent / cellSpace;
      gfx.DrawRectangle(XBrushes.LightGreen, x, y, size.Width, descent);

      double leading = lineSpace * cellLeading / cellSpace;
      gfx.DrawRectangle(XBrushes.Yellow, x, y + descent, size.Width, leading);

      //gfx.DrawRectangle(this.properties.Brush1.Brush, x, y - size.Height, size.Width, size.Height);
      //gfx.DrawLine(this.properties.Pen2.Pen, x, y, x + size.Width, y);
      //gfx.DrawString("Hello", this.properties.Font1.Font, this.properties.Font1.Brush, 200, 200);

#if true_
      XPdfFontOptions pdfOptions = new XPdfFontOptions(false, true);
      font = new XFont("Tahoma", 8, XFontStyle.Regular, pdfOptions);
      text = "Hallo";
      text = chinese;
#endif
      gfx.DrawString(text, font, this.properties.Font1.Brush, x, y);

#if true
      XFont font2 = CreateFont(familyName, emSize, XFontStyle.Italic);
      gfx.DrawString(text, font2, this.properties.Font1.Brush, x, y+50);
#endif
      //gfx.DrawLine(XPens.Red, x, y + 10, x + 13.7, y + 10);
      //gfx.DrawString(text, font, this.properties.Font1.Brush, x, y + 20);
    }

    public override string Description
    {
      get { return "DrawString"; }
    }
  }
}
