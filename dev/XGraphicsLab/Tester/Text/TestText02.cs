using System;
using System.Drawing;
using System.Drawing.Drawing2D;
using PdfSharp.Pdf;
using PdfSharp.Drawing;

namespace XDrawing.TestLab.Tester
{
  /// <summary>
  /// Demonstrates the use of XGraphics.DrawString.
  /// </summary>
  public class TestText02 : TesterBase
  {
    public TestText02()
    {
    }

    public override void RenderPage(XGraphics gfx)
    {
      base.RenderPage(gfx);

      string facename = "Times";
      XFont fontR = new XFont(facename, 40);
      XFont fontB = new XFont(facename, 40, XFontStyle.Bold);
      XFont fontI = new XFont(facename, 40, XFontStyle.Italic);
      XFont fontBI = new XFont(facename, 40, XFontStyle.Bold | XFontStyle.Italic);
      //gfx.DrawString("Hello", this.properties.Font1.Font, this.properties.Font1.Brush, 200, 200);
      double x = 80;
      XPen pen = XPens.SlateBlue;
      gfx.DrawLine(pen, x, 100, x, 600);
      gfx.DrawLine(pen, x - 50, 200, 400, 200);
      gfx.DrawLine(pen, x - 50, 300, 400, 300);
      gfx.DrawLine(pen, x - 50, 400, 400, 400);
      gfx.DrawLine(pen, x - 50, 500, 400, 500);

      double lineSpace = fontR.GetHeight(gfx);
      int cellSpace = fontR.FontFamily.GetLineSpacing(fontR.Style);
      int cellAscent = fontR.FontFamily.GetCellAscent(fontR.Style);
      int cellDescent = fontR.FontFamily.GetCellDescent(fontR.Style);
      double cyAscent = lineSpace * cellAscent / cellSpace;

      XFontMetrics metrics = fontR.Metrics;

      XSize size;
      gfx.DrawString("Times 40", fontR, this.properties.Font1.Brush, x, 200);
      size = gfx.MeasureString("Times 40", fontR);
      gfx.DrawLine(this.properties.Pen3.Pen, x, 200, x + size.Width, 200);

      gfx.DrawString("Times bold 40", fontB, this.properties.Font1.Brush, x, 300);
      size = gfx.MeasureString("Times bold 40", fontB);
      //gfx.DrawLine(this.properties.Pen3.Pen, x, 300, x + size.Width, 300);

      gfx.DrawString("Times italic 40", fontI, this.properties.Font1.Brush, x, 400);
      size = gfx.MeasureString("Times italic 40", fontI);
      //gfx.DrawLine(this.properties.Pen3.Pen, x, 400, x + size.Width, 400);

      gfx.DrawString("Times bold italic 40", fontBI, this.properties.Font1.Brush, x, 500);
      size = gfx.MeasureString("Times bold italic 40", fontBI);
      //gfx.DrawLine(this.properties.Pen3.Pen, x, 500, x + size.Width, 500);

#if true___
      // Check Malayalam
      XPdfFontOptions options = new XPdfFontOptions(PdfFontEncoding.Unicode, PdfFontEmbedding.Always);
      XFont Kartika = new XFont("Kartika", 20, XFontStyle.Regular, options);
      XFont AnjaliOldLipi = new XFont("AnjaliOldLipi", 20, XFontStyle.Regular, options);
      gfx.DrawString("മകനെ ഇത് ഇന്ത്യയുടെ ഭൂപടം", Kartika, this.properties.Font1.Brush, x, 600);
      gfx.DrawString("മകനെ ഇത് ഇന്ത്യയുടെ ഭൂപടം", AnjaliOldLipi, this.properties.Font1.Brush, x, 650);
#endif
    }

    public override string Description
    {
      get { return "DrawString"; }
    }
  }
}
