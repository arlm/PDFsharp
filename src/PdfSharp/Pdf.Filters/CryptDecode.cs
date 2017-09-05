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

using System;
using System.IO;
using PdfSharp.Internal;
using PdfSharp.Pdf.Security;
using System.Diagnostics;

namespace PdfSharp.Pdf.Filters
{
    /// <summary>
    /// Implements the FlateDecode filter by wrapping SharpZipLib.
    /// </summary>
    public class CryptDecode : Filter
    {
        // Reference: 3.3.3  LZWDecode and FlateDecode Filters / Page 71

        /// <summary>
        /// Encodes the specified data.
        /// </summary>
        public override byte[] Encode(byte[] data)
        {
            return Encode(data, new PdfCryptoFilter((PdfDictionary)null));
        }

        /// <summary>
        /// Encodes the specified data.
        /// </summary>
        public byte[] Encode(byte[] data, PdfCryptoFilter encryptionDic)
        {
            PdfSecurityHandler handler = new PdfIdentitySecurityHandler(encryptionDic._document);

            return handler.EncryptBytes(data);
        }

        /// <summary>
        /// Decodes the specified data.
        /// </summary>
        public override byte[] Decode(byte[] data, FilterParms parms = null)
        {
            if (data == null)
                throw new ArgumentNullException(nameof(data));

            string type = parms?.Elements.GetName("/Type");
            string name = parms?.Elements.GetName("/Name");
            PdfSecurityHandler handler;

            if (parms == null || type != "/CryptFilterDecodeParms" || name == "/Identity")
            {
                handler = new PdfIdentitySecurityHandler(parms?._document);
            }
            else if (name == "/AESV2")
            {
                handler = new PdfAESV2SecurityHandler(parms?._document);
            }
            else if (name == "/AESV3")
            {
                handler = new PdfAESV3SecurityHandler(parms?._document);
            }
            else
            {
                Debug.WriteLine("Crypt Filter not implemented: " + parms);
                throw new NotImplementedException("Unknown crypt filter: " + parms);
            }

            return handler.DecryptBytes(data);
        }
    }
}
