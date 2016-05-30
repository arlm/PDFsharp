using System;
using System.Drawing;
using System.Drawing.Drawing2D;
using PdfSharp.Drawing;

namespace XDrawing.TestLab.Tester
{
  /// <summary>
  /// Demonstrates the use of XGraphics.DrawString.
  /// </summary>
  public class Acro8Bug : TesterBase
  {
    public Acro8Bug()
    {
    }

    public override void RenderPage(XGraphics gfx)
    {
      //base.RenderPage(gfx);

      XFont font1 = new XFont("Arial", 9);
      XFont font2 = new XFont("Arial", 9, XFontStyle.Italic);
      XFont font3 = new XFont("Arial", 9, XFontStyle.Bold);
      XSolidBrush brush = new XSolidBrush(XColors.Black);

      gfx.DrawString("Page 5", font1, brush, 100, 100);
      gfx.DrawString("Water Sports You've Done continued", font2, brush, 100, 200);
      gfx.DrawString("Rowing", font1, brush, 100, 250);
      gfx.DrawString("Snorkeling", font1, brush, 100, 300);
      gfx.DrawString("WINTER SPORTS, SKIING, SKIING IN THE US", font3, XBrushes.Red, 100, 320);

      gfx.DrawLine(XPens.Red, 100, 100, 200, 200);

      gfx.DrawString("Resorts You've Skied in Vermont", font3, brush, 100, 400);
      gfx.DrawString("Haystack", font1, brush, 100, 420);

//      string text = "TgfÄÖÜWi9";
//      if (this.properties.Font1.Text != "")
//        text = this.properties.Font1.Text;
//      float x = 100, y = 300;
//      string familyName = properties.Font1.FamilyName;
//      XFontStyle style = this.properties.Font1.Style;
//      float emSize = this.properties.Font1.Size;
//      XFont font = CreateFont(familyName, emSize, style);
//      font = this.properties.Font1.Font;
//      XSize size = gfx.MeasureString(text, font);

//      double lineSpace = font.GetHeight(gfx);
//      int cellSpace   = font.FontFamily.GetLineSpacing(style);
//      int cellAscent  = font.FontFamily.GetCellAscent(style);
//      int cellDescent = font.FontFamily.GetCellDescent(style);
//      int cellLeading = cellSpace - cellAscent - cellDescent;

//      double ascent  = lineSpace * cellAscent / cellSpace;
//      gfx.DrawRectangle(XBrushes.Bisque, x, y - ascent, size.Width, ascent);

//      double descent = lineSpace * cellDescent / cellSpace;
//      gfx.DrawRectangle(XBrushes.LightGreen, x, y, size.Width, descent);

//      double leading = lineSpace * cellLeading / cellSpace;
//      gfx.DrawRectangle(XBrushes.Yellow, x, y + descent, size.Width, leading);

//      //gfx.DrawRectangle(this.properties.Brush1.Brush, x, y - size.Height, size.Width, size.Height);
//      //gfx.DrawLine(this.properties.Pen2.Pen, x, y, x + size.Width, y);
//      //gfx.DrawString("Hello", this.properties.Font1.Font, this.properties.Font1.Brush, 200, 200);

//#if true_
//      XPdfFontOptions pdfOptions = new XPdfFontOptions(false, true);
//      font = new XFont("Tahoma", 8, XFontStyle.Regular, pdfOptions);
//      text = "Hallo";
//      text = chinese;
//#endif
//      gfx.DrawString(text, font, this.properties.Font1.Brush, x, y);
//      gfx.DrawLine(XPens.Red, 0, 0, 100, 100);
//      gfx.DrawString(text, font, this.properties.Font1.Brush, x, y + 20);
    }

    public override string Description
    {
      get {return "DrawString";}
    }
  }
}
