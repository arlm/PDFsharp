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
  public class Embedding : TesterBase
  {
    public Embedding()
    {
    }

    public override void RenderPage(XGraphics gfx)
    {
      base.RenderPage(gfx);

      string text = "TgfÄÖÜWi9";
      if (this.properties.Font1.Text != "")
        text = this.properties.Font1.Text;
      string familyName1 = properties.Font1.FamilyName;
      string familyName2 = properties.Font2.FamilyName;
      //XFontStyle style = this.properties.Font1.Style;
      float emSize1 = this.properties.Font1.Size;
      float emSize2 = this.properties.Font2.Size;
      XPdfFontOptions options1 = new XPdfFontOptions(
        this.properties.Font1.Unicode ? PdfFontEncoding.Unicode : PdfFontEncoding.WinAnsi,
        this.properties.Font1.Embed ? PdfFontEmbedding.Always : PdfFontEmbedding.None);
      XFont font1R = CreateFont(familyName1, emSize1, XFontStyle.Regular, options1);
      XFont font1B = CreateFont(familyName1, emSize1, XFontStyle.Bold, options1);
      XFont font1I = CreateFont(familyName1, emSize1, XFontStyle.Italic, options1);
      XFont font1BI = CreateFont(familyName1, emSize1, XFontStyle.BoldItalic, options1);
      XFont font1U = CreateFont(familyName1, emSize1, XFontStyle.Underline, options1);
      XFont font1S = CreateFont(familyName1, emSize1, XFontStyle.Strikeout, options1);

      XPdfFontOptions options2 = new XPdfFontOptions(
        this.properties.Font2.Unicode ? PdfFontEncoding.Unicode : PdfFontEncoding.WinAnsi,
        this.properties.Font2.Embed ? PdfFontEmbedding.Always : PdfFontEmbedding.None);
      XFont font2R = CreateFont(familyName2, emSize2, XFontStyle.Regular, options2);
      XFont font2B = CreateFont(familyName2, emSize2, XFontStyle.Bold, options2);
      XFont font2I = CreateFont(familyName2, emSize2, XFontStyle.Italic, options2);
      XFont font2BI = CreateFont(familyName2, emSize2, XFontStyle.BoldItalic, options2);
      XFont font2U = CreateFont(familyName2, emSize2, XFontStyle.Underline, options2);
      XFont font2S = CreateFont(familyName2, emSize2, XFontStyle.Strikeout, options2);
      //XSize size = gfx.MeasureString(text, font);

      //double lineSpace = font.GetHeight(gfx);
      //int cellSpace   = font.FontFamily.GetLineSpacing(style);
      //int cellAscent  = font.FontFamily.GetCellAscent(style);
      //int cellDescent = font.FontFamily.GetCellDescent(style);
      //int cellLeading = cellSpace - cellAscent - cellDescent;

      double x = 100, y = 50, d = 50;
      gfx.DrawString(text, font1R, this.properties.Font1.Brush, new XPoint(x, y += d));
      gfx.DrawString(text, font1B, this.properties.Font1.Brush, new XPoint(x, y += d));
      gfx.DrawString(text, font1I, this.properties.Font1.Brush, new XPoint(x, y += d));
      gfx.DrawString(text, font1BI, this.properties.Font1.Brush, new XPoint(x, y += d));
      gfx.DrawString(text, font1U, this.properties.Font1.Brush, new XPoint(x, y += d));
      gfx.DrawString(text, font1S, this.properties.Font1.Brush, new XPoint(x, y += d));

      y += 50;
      gfx.DrawString(text, font2R, this.properties.Font2.Brush, new XPoint(x, y += d));
      gfx.DrawString(text, font2B, this.properties.Font2.Brush, new XPoint(x, y += d));
      gfx.DrawString(text, font2I, this.properties.Font2.Brush, new XPoint(x, y += d));
      gfx.DrawString(text, font2BI, this.properties.Font2.Brush, new XPoint(x, y += d));
      gfx.DrawString(text, font2U, this.properties.Font2.Brush, new XPoint(x, y += d));
      gfx.DrawString(text, font2S, this.properties.Font2.Brush, new XPoint(x, y += d));

      //double ascent  = lineSpace * cellAscent / cellSpace;
      //gfx.DrawRectangle(XBrushes.Bisque, x, y - ascent, size.Width, ascent);

      //double descent = lineSpace * cellDescent / cellSpace;
      //gfx.DrawRectangle(XBrushes.LightGreen, x, y, size.Width, descent);

      //double leading = lineSpace * cellLeading / cellSpace;
      //gfx.DrawRectangle(XBrushes.Yellow, x, y + descent, size.Width, leading);

      //gfx.DrawRectangle(this.properties.Brush1.Brush, x, y - size.Height, size.Width, size.Height);
      //gfx.DrawLine(this.properties.Pen2.Pen, x, y, x + size.Width, y);
      //gfx.DrawString("Hello", this.properties.Font1.Font, this.properties.Font1.Brush, 200, 200);

#if true_
      XPdfFontOptions pdfOptions = new XPdfFontOptions(false, true);
      font = new XFont("Tahoma", 8, XFontStyle.Regular, pdfOptions);
      text = "Hallo";
      text = chinese;
#endif
      //gfx.DrawString(text, font, this.properties.Font1.Brush, x, y);
    }

    public override string Description
    {
      get {return "DrawString";}
    }
  }
}
