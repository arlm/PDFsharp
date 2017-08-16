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

using PdfSharp.Pdf.IO;
using PdfSharp.Pdf.Advanced;
using System;

#pragma warning disable 0169
#pragma warning disable 0649

namespace PdfSharp.Pdf.Security
{
    /// <summary>
    /// Represents the standard PDF security handler.
    /// </summary>
    public sealed class PdfIdentitySecurityHandler : PdfSecurityHandler
    {
        internal PdfIdentitySecurityHandler(PdfDocument document)
            : base(document)
        { }

        /// <summary>
        /// Sets the user password of the document. Setting a password automatically sets the
        /// PdfDocumentSecurityLevel to PdfDocumentSecurityLevel.Encrypted128Bit if its current
        /// value is PdfDocumentSecurityLevel.None.
        /// </summary>
        public override string UserPassword
        {
            internal get
            {
                return _userPassword;
            }

            set
            {
                _document._securitySettings.DocumentSecurityLevel = PdfDocumentSecurityLevel.None;
                _userPassword = value;
            }
        }
        private string _userPassword;

        /// <summary>
        /// Sets the owner password of the document. Setting a password automatically sets the
        /// PdfDocumentSecurityLevel to PdfDocumentSecurityLevel.Encrypted128Bit if its current
        /// value is PdfDocumentSecurityLevel.None.
        /// </summary>
        public override string OwnerPassword
        {
            internal get
            {
                return _userPassword;
            }

            set
            {
                _document._securitySettings.DocumentSecurityLevel = PdfDocumentSecurityLevel.None;
                _ownerPassword = value;
            }
        }
        private string _ownerPassword;

        /// <summary>
        /// Gets or sets the user access permission represented as an integer in the P key.
        /// </summary>
        internal override PdfUserAccessPermission Permission
        {
            get
            {
                return PdfUserAccessPermission.PermitAll;
            }
            set { }
        }

        /// <summary>
        /// Encrypts the whole document.
        /// </summary>
        public override void EncryptDocument()
        {
        }

        /// <summary>
        /// Decrypts the whole document.
        /// </summary>
        public override void DecryptDocument(PdfReference xrefEncrypt)
        {
        }

        /// <summary>
        /// Encrypts an array.
        /// </summary>
        public override byte[] EncryptBytes(byte[] bytes)
        {
            return bytes;
        }

        /// <summary>
        /// Decrypts an array.
        /// </summary>
        public override byte[] DecryptBytes(byte[] bytes)
        {
            return bytes;
        }

        internal override void WriteObject(PdfWriter writer)
        {
            // Don't encrypt myself.
            PdfSecurityHandler securityHandler = writer.SecurityHandler;
            writer.SecurityHandler = null;
            base.WriteObject(writer);
            writer.SecurityHandler = securityHandler;
        }

        public override void PrepareEncryption()
        {
        }

        internal override void SetHashKey(PdfObjectID id)
        {
        }

        public override PasswordValidity ValidatePassword(string inputPassword)
        {
            return PasswordValidity.UserPassword;
        }
    }
}
