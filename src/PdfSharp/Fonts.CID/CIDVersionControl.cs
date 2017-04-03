#region PDFsharp - A .NET library for processing PDF
//
// Authors:
//   Stefan Lange
//
// Copyright (c) 2005-2016 empira Software GmbH, Cologne Area (Germany)
//
// http://www.pdfsharp.com
// http://sourceforge.net/projects/pdfsharp
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
// THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER 
// DEALINGS IN THE SOFTWARE.
#endregion

using PdfSharp.Pdf;

namespace PdfSharp.Fonts.CID
{
    public sealed class CIDVersionControl : PdfDictionary
    {
        /// <summary>
        /// Initializes a new page. The page must be added to a document before it can be used.
        /// Depending of the IsMetric property of the current region the page size is set to
        /// A4 or Letter respectively. If this size is not appropriate it should be changed before
        /// any drawing operations are performed on the page.
        /// </summary>
        public CIDVersionControl()
        {
            Elements.SetName(Keys.Registry, "Adobe");
            Elements.SetName(Keys.Ordering, "Japan1");
            Elements.SetName(Keys.Supplement, "0");
        }

        internal CIDVersionControl(PdfDictionary dict)
           : base(dict)
        {
        }

        /// <summary>
        /// Gets or sets the bleed box.
        /// </summary>
        public string Ordering
        {
            get { return Elements.GetString(Keys.Ordering, true); }
            set { Elements.SetString(Keys.Ordering, value); }
        }

        /// <summary>
        /// Gets or sets the bleed box.
        /// </summary>
        public string Registry
        {
            get { return Elements.GetString(Keys.Registry, true); }
            set { Elements.SetString(Keys.Registry, value); }
        }

        /// <summary>
        /// Gets or sets the bleed box.
        /// </summary>
        public int Supplement
        {
            get { return Elements.GetInteger(Keys.Supplement, true); }
            set { Elements.SetInteger(Keys.Supplement, value); }
        }

        /// <summary>
        /// Predefined keys common to CID Version Control information.
        /// </summary>
        internal class Keys : KeysBase
        {
            /// <summary>
            /// (Required; non-inheritable) A rectangle, expressed in default user space units, defining the
            /// boundaries of the physical medium on which the page is intended to be displayed or printed.
            /// </summary>
            [KeyInfo(KeyType.String | KeyType.Required)]
            public const string Ordering = "/Ordering";

            /// <summary>
            /// (Required; non-inheritable) Contains the version control information
            /// </summary>
            [KeyInfo(KeyType.String | KeyType.Required)]
            public const string Registry = "/Registry";

            /// <summary>
            /// (Required; non-inheritable)  A rectangle, expressed in default user space units, defining the
            /// visible region of default user space. When the page is displayed or printed, its contents
            /// are to be clipped (cropped) to this rectangle and then imposed on the output medium in some
            /// implementation defined manner. Default value: the value of MediaBox.
            /// </summary>
            [KeyInfo(KeyType.Integer | KeyType.Required)]
            public const string Supplement = "/Supplement";
        }
    }
}