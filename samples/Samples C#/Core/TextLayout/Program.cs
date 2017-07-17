using System;
using System.Diagnostics;
using PdfSharp.Pdf;
using PdfSharp.Drawing;
using PdfSharp.Drawing.Layout;

namespace TextLayout
{
    /// <summary>
    /// This sample shows how to layout text with the TextFormatter class.
    /// TextFormatter is new since PDFsharp 0.9 and was provided because it was one of the "most wanted"
    /// features. But it is better and easier to use MigraDoc to format paragraphs...
    /// </summary>
    class Program
    {
        [STAThread]
        static void Main()
        {
            const string filename = "TextLayout_tempfile.pdf";

            const string text =
                "Facin exeraessisit la consenim iureet dignibh eu facilluptat vercil dunt autpat. " +
                "Ecte magna faccum dolor sequisc iliquat, quat, quipiss equipit accummy niate magna " +
                "facil iure eraesequis am velit, quat atis dolore dolent luptat nulla adio odipissectet " +
                "lan venis do essequatio conulla facillandrem zzriusci bla ad minim inis nim velit eugait " +
                "aut aut lor at ilit ut nulla ate te eugait alit augiamet ad magnim iurem il eu feuissi.\n" +
                "Guer sequis duis eu feugait luptat lum adiamet, si tate dolore mod eu facidunt adignisl in " +
                "henim dolorem nulla faccum vel inis dolutpatum iusto od min ex euis adio exer sed del " +
                "dolor ing enit veniamcon vullutat praestrud molenis ciduisim doloborem ipit nulla consequisi.\n" +
                "Nos adit pratetu eriurem delestie del ut lumsandreet nis exerilisit wis nos alit venit praestrud " +
                "dolor sum volore facidui blaor erillaortis ad ea augue corem dunt nis  iustinciduis euisi.\n" +
                "Ut ulputate volore min ut nulpute dolobor sequism olorperilit autatie modit wisl illuptat dolore " +
                "min ut in ute doloboreet ip ex et am dunt at.";

            var document = new PdfDocument();

            var page = document.AddPage();
            var gfx = XGraphics.FromPdfPage(page);
            var font = new XFont("Times New Roman", 10, XFontStyle.Bold);
            var tf = new XTextFormatter(gfx);

            var rect = new XRect(40, 100, 250, 232);
            gfx.DrawRectangle(XBrushes.SeaShell, rect);
            //tf.Alignment = ParagraphAlignment.Left;
            tf.DrawString(text, font, XBrushes.Black, rect, XStringFormats.TopLeft);

            rect = new XRect(310, 100, 250, 232);
            gfx.DrawRectangle(XBrushes.SeaShell, rect);
            tf.Alignment = XParagraphAlignment.Right;
            tf.DrawString(text, font, XBrushes.Black, rect, XStringFormats.TopLeft);

            rect = new XRect(40, 400, 250, 232);
            gfx.DrawRectangle(XBrushes.SeaShell, rect);
            tf.Alignment = XParagraphAlignment.Center;
            tf.DrawString(text, font, XBrushes.Black, rect, XStringFormats.TopLeft);

            rect = new XRect(310, 400, 250, 232);
            gfx.DrawRectangle(XBrushes.SeaShell, rect);
            tf.Alignment = XParagraphAlignment.Justify;
            tf.DrawString(text, font, XBrushes.Black, rect, XStringFormats.TopLeft);

            // Save the document...
            document.Save(filename);
            // ...and start a viewer.
            Process.Start(filename);
        }
    }
}