﻿using System.Diagnostics;
using System.IO;
using PdfSharp;
using PdfSharp.Drawing;
using PdfSharp.Pdf;

// By courtesy of Peter Berndts 

namespace Booklet
{
    /// <summary>
    /// This sample shows how to produce a booklet by placing
    /// two pages of an existing document on
    /// one landscape orientated page of a new document.
    /// </summary>
    class Program
    {
        static void Main()
        {
            // Get a fresh copy of the sample PDF file
            var filename = "Portable Document Format.pdf";
            var file = Path.Combine(Directory.GetCurrentDirectory(), filename);
            File.Copy(Path.Combine("../../../../assets/PDFs/", filename), file, true);

            // Remove ReadOnly attribute from the copy.
            File.SetAttributes(file, File.GetAttributes(file) & ~FileAttributes.ReadOnly);

            // Create the output document
            var outputDocument = new PdfDocument();

            // Show single pages.
            // (Note: one page contains two pages from the source document.
            //  If the number of pages of the source document can not be
            //  divided by 4, the first pages of the output document will
            //  each contain only one page from the source document.)
            outputDocument.PageLayout = PdfPageLayout.SinglePage;

            // Open the external document as XPdfForm object.
            var form = XPdfForm.FromFile(filename);
            // Determine width and height.
            double extWidth = form.PixelWidth;
            double extHeight = form.PixelHeight;

            var inputPages = form.PageCount;
            var sheets = inputPages / 4;
            if (sheets * 4 < inputPages)
                sheets += 1;
            var allpages = 4 * sheets;
            var vacats = allpages - inputPages;


            for (var idx = 1; idx <= sheets; idx += 1)
            {
                // Front page of a sheet:
                // Add a new page to the output document.
                var page = outputDocument.AddPage();
                page.Orientation = PageOrientation.Landscape;
                page.Width = 2 * extWidth;
                page.Height = extHeight;
                double width = page.Width;
                double height = page.Height;

                var gfx = XGraphics.FromPdfPage(page);

                // Skip if left side has to remain blank.
                XRect box;
                if (vacats > 0)
                    vacats -= 1;
                else
                {
                    // Set page number (which is one-based) for left side.
                    form.PageNumber = allpages + 2 * (1 - idx);
                    box = new XRect(0, 0, width / 2, height);
                    // Draw the page identified by the page number like an image.
                    gfx.DrawImage(form, box);
                }

                // Set the page number (which is one-based) for the right side.
                form.PageNumber = 2 * idx - 1;
                box = new XRect(width / 2, 0, width / 2, height);
                // Draw the page identified by the page number like an image.
                gfx.DrawImage(form, box);

                // Back page of a sheet.
                page = outputDocument.AddPage();
                page.Orientation = PageOrientation.Landscape;
                page.Width = 2 * extWidth;
                page.Height = extHeight;

                gfx = XGraphics.FromPdfPage(page);

                // Set the page number (which is one-based) for the left side.
                form.PageNumber = 2 * idx;
                box = new XRect(0, 0, width / 2, height);
                // Draw the page identified by the page number like an image.
                gfx.DrawImage(form, box);

                // Skip if the right side has to remain blank.
                if (vacats > 0)
                    vacats -= 1;
                else
                {
                    // Set the page number (which is one-based) for the right side.
                    form.PageNumber = allpages + 1 - 2 * idx;
                    box = new XRect(width / 2, 0, width / 2, height);
                    // Draw the page identified by the page number like an image.
                    gfx.DrawImage(form, box);
                }
            }

            // Save the document...
            filename = "Booklet_tempfile.pdf";
            outputDocument.Save(filename);
            // ...and start a viewer.
            Process.Start(filename);
        }
    }
}
