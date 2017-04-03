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
    public sealed class CMapDictionary : PdfDictionary
    {
        /// <summary>
        /// Initializes a new page. The page must be added to a document before it can be used.
        /// Depending of the IsMetric property of the current region the page size is set to
        /// A4 or Letter respectively. If this size is not appropriate it should be changed before
        /// any drawing operations are performed on the page.
        /// </summary>
        public CMapDictionary()
        {
        }

        internal CMapDictionary(PdfDictionary dict)
           : base(dict)
        {
        }

        /// <summary>
        /// Predefined keys common to CMap definitions.
        /// </summary>
        internal class Keys : KeysBase
        {
            /// <summary>
            /// (Required; non-inheritable) Contains the CID version control information
            /// </summary>
            [KeyInfo(KeyType.Dictionary | KeyType.Required)]
            public const string CIDSystemInfo = "/CIDSystemInfo";

            /// <summary>
            /// (Required; non-inheritable) The CMap instance name.
            /// </summary>
            [KeyInfo(KeyType.Name | KeyType.Required)]
            public const string CMapName = "/CMapName";

            /// <summary>
            /// (Required; non-inheritable) Defines changes to the internal organization
            /// of CMap files or the semantics of CMap operators
            /// </summary>
            [KeyInfo(KeyType.Integer | KeyType.Required)]
            public const string CMapType = "/CMapType";

            /// <summary>
            /// (Optional; non-inheritable) Defines the version number of this CMap file
            /// </summary>
            [KeyInfo(KeyType.Integer | KeyType.Optional)]
            public const string CMapVersion = "/CMapVersion";

            /// <summary>
            /// (Optional; non-inheritable) Defines the offset of unique ID numbers for the characters described on this CMap file
            /// </summary>
            [KeyInfo(KeyType.Integer | KeyType.Optional)]
            public const string UniqueIDOffset = "/UIDOffset";

            /// <summary>
            /// (Optional; non-inheritable) Identifies a font by the entire sequence of numbers in the array
            /// </summary>
            [KeyInfo(KeyType.Array | KeyType.Optional)]
            public const string ExtendedUniqueID = "/XUID";

            /// <summary>
            /// (Optional; non-inheritable) Controls wheter the CID-keyed font writes horizontally or vertically.
            /// An entry of 0 defines horizontal writing from letf to right; an entry of 1 defines vertical writing
            /// from top to bottom. Default value: 0
            /// </summary>
            [KeyInfo(KeyType.Integer | KeyType.Optional)]
            public const string WritingMode = "/WMode";
        }
    }
}
