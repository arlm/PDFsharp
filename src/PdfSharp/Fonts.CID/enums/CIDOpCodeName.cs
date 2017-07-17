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

namespace PdfSharp.Fonts.CID
{
#pragma warning disable 1591

    /// <summary>
    /// The names of the op-codes.
    /// </summary>
    public enum CIDOpCodeName
    {
        Dictionary,  // Name followed by dictionary.

        // I know that this is not useable in VB or other languages with no case sensitivity.
        def, begincmap, endbfchar, endcmap, begin, begincodespacerange, endcodespacerange, beginbfchar, pop, end,
        findresource, dict, beginbfrange, endbfrange, CMapName, currentdict, defineresource, begincidrange,
        endcidrange, beginnotdefrange, endnotdefrange, usecmap, usefont, begincidchar, endcidchar,
        beginnotdefchar, endnotdefchar, CIDSystemInfo, dup, cvn
    }
}
