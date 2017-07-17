﻿using System.Diagnostics;
using PdfSharp.Drawing;
using PdfSharp.Pdf;

namespace HelloWorld
{
    /// <summary>
    /// This sample is the obligatory Hello World program.
    /// </summary>
    class Program
    {
        static void Main()
        {
            // Create a new PDF document.
            var document = new PdfDocument();
            document.Info.Title = "Created with PDFsharp";

            // Create an empty page in this document.
            var page = document.AddPage();

            // Get an XGraphics object for drawing on this page.
            var gfx = XGraphics.FromPdfPage(page);

            // Draw two lines with a red default pen.
            var width = page.Width;
            var height = page.Height;
            gfx.DrawLine(XPens.Red, 0, 0, width, height);
            gfx.DrawLine(XPens.Red, width, 0, 0, height);

            // Draw a circle with a red pen which is 1.5 point thick.
            var r = width / 5;
            gfx.DrawEllipse(new XPen(XColors.Red, 1.5), XBrushes.White, new XRect(width / 2 - r, height / 2 - r, 2 * r, 2 * r));

            // Create a font.
            var font = new XFont("Times New Roman", 20, XFontStyle.BoldItalic);

            // Draw the text.
            gfx.DrawString("Hello, PDFsharp!", font, XBrushes.Black,
                new XRect(0, 0, page.Width, page.Height), XStringFormats.Center);

            // Save the document...
            const string filename = "HelloWorld_tempfile.pdf";
            document.Save(filename);
            // ...and start a viewer.
            Process.Start(filename);
        }
    }
}
