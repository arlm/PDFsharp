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
using System.Collections.Generic;
using System.Diagnostics;
using PdfSharp.Pdf.IO;
using PdfSharp.Pdf.Advanced;
using PdfSharp.Pdf.Internal;
using System.Text;
#if !NETFX_CORE && !UWP
using System.Security.Cryptography;
#endif

#pragma warning disable 0169
#pragma warning disable 0649

namespace PdfSharp.Pdf.Security
{
    /// <summary>
    /// Represents the AESV2 PDF security handler.
    /// </summary>
    public sealed class PdfAESV2SecurityHandler : PdfSecurityHandler
    {
        internal PdfAESV2SecurityHandler(PdfDocument document)
            : base(document)
        { }

        internal PdfAESV2SecurityHandler(PdfDictionary dict)
            : base(dict)
        { }

        public bool EncryptMetadata
        {
            internal get
            {
                return _encryptMetadata;
            }

            set
            {
                _encryptMetadata = value;
            }
        }
        private bool _encryptMetadata;

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
                if (_document._securitySettings.DocumentSecurityLevel == PdfDocumentSecurityLevel.None)
                    _document._securitySettings.DocumentSecurityLevel = PdfDocumentSecurityLevel.AES_V2;
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
                if (_document._securitySettings.DocumentSecurityLevel == PdfDocumentSecurityLevel.None)
                    _document._securitySettings.DocumentSecurityLevel = PdfDocumentSecurityLevel.AES_V2;
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
                PdfUserAccessPermission permission = (PdfUserAccessPermission)Elements.GetInteger(Keys.P);
                if (permission == 0)
                    permission = PdfUserAccessPermission.PermitAll;
                return permission;
            }
            set { Elements.SetInteger(Keys.P, (int)value); }
        }

        /// <summary>
        /// Encrypts the whole document.
        /// </summary>
        public override void EncryptDocument()
        {
            foreach (PdfReference iref in _document._irefTable.AllReferences)
            {
                if (!ReferenceEquals(iref.Value, this))
                    EncryptObject(iref.Value);
            }
        }

        /// <summary>
        /// Decrypts the whole document.
        /// </summary>
        public override void DecryptDocument(PdfReference xrefEncrypt)
        {
            foreach (PdfReference iref in _document._irefTable.AllReferences)
            {
                if (!ReferenceEquals(iref.Value, this))
                {
                    DecryptObject(iref.Value, xrefEncrypt);
                }
            }
        }

        /// <summary>
        /// Encrypts an indirect object.
        /// </summary>
        internal void EncryptObject(PdfObject value)
        {
            Debug.Assert(value.Reference != null);

            SetHashKey(value.ObjectID);
#if DEBUG
            if (value.ObjectID.ObjectNumber == 10)
                GetType();
#endif

            PdfDictionary dict;
            PdfArray array;
            PdfStringObject str;
            if ((dict = value as PdfDictionary) != null)
                EncryptDictionary(dict);
            else if ((array = value as PdfArray) != null)
                EncryptArray(array);
            else if ((str = value as PdfStringObject) != null)
            {
                if (str.Length != 0)
                {
                    byte[] bytes = str.EncryptionValue;
                    PrepareAESKey();
                    EncryptAES(bytes);
                    str.EncryptionValue = bytes;
                }
            }
        }

        /// <summary>
        /// Decrypts an indirect object.
        /// </summary>
        internal void DecryptObject(PdfObject value, PdfReference xrefEncrypt)
        {
            Debug.Assert(value.Reference != null);

            SetHashKey(value.ObjectID);
#if DEBUG
            Debug.WriteLine($">>> Decrypt object: {value.ObjectID} with {_keySize}-bit key");
            DumpBytes("key", _key);

            if (value.ObjectID.ObjectNumber == 10)
                GetType();
#endif

            try
            {
                PdfDictionary dict;
                PdfArray array;
                PdfStringObject str;
                if ((dict = value as PdfDictionary) != null)
                {
                    if (dict.ObjectID != xrefEncrypt?.ObjectID)
                    {
                        DecryptDictionary(dict);
                    }
#if DEBUG
                    else
                    {
                        if (dict.ObjectID == xrefEncrypt?.ObjectID)
                            Debug.WriteLine($">>> Skipping /Encrypt dictionary: {value.ObjectID} ...");
                        else
                            Debug.WriteLine($">>> Skipping Catalog (trailer) dictionary: {value.ObjectID} ...");
                    }
#endif
                }
                else if ((array = value as PdfArray) != null)
                {
                    DecryptArray(array);
                }
                else if ((str = value as PdfStringObject) != null)
                {
                    if (str.Length != 0)
                    {
                        byte[] bytes = str.EncryptionValue;
                        PrepareAESKey();
                        PrepareAESIV(bytes, 0, 16);
                        byte[] temp = new byte[bytes.Length];

                        int length = DecryptAES(bytes, 16, bytes.Length - 16, temp);

                        Array.Resize(ref temp, length);

                        str.EncryptionValue = temp;
                    }
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($">>> Decrypt object error for {value.ObjectID}: {ex.Message}");
                Debug.WriteLine(ex.StackTrace);
            }
        }

        /// <summary>
        /// Encrypts a dictionary.
        /// </summary>
        void EncryptDictionary(PdfDictionary dict)
        {
            PdfName[] names = dict.Elements.KeyNames;
            foreach (KeyValuePair<string, PdfItem> item in dict.Elements)
            {
                PdfString value1;
                PdfDictionary value2;
                PdfArray value3;
                if ((value1 = item.Value as PdfString) != null)
                    EncryptString(value1);
                else if ((value2 = item.Value as PdfDictionary) != null)
                    EncryptDictionary(value2);
                else if ((value3 = item.Value as PdfArray) != null)
                    EncryptArray(value3);
            }
            if (dict.Stream != null)
            {
                byte[] bytes = dict.Stream.Value;
                if (bytes.Length != 0)
                {
                    PrepareAESKey();
                    EncryptAES(bytes);
                    dict.Stream.Value = bytes;
                }
            }
        }

        /// <summary>
        /// Decrypts a dictionary.
        /// </summary>
        void DecryptDictionary(PdfDictionary dict)
        {
            PdfName[] names = dict.Elements.KeyNames;
            foreach (KeyValuePair<string, PdfItem> item in dict.Elements)
            {
                PdfString value1;
                PdfDictionary value2;
                PdfArray value3;
                if ((value1 = item.Value as PdfString) != null)
                {
                    DecryptString(value1);
                }
                else if ((value2 = item.Value as PdfDictionary) != null)
                {
                    DecryptDictionary(value2);
                }
                else if ((value3 = item.Value as PdfArray) != null)
                {
                    if (dict.ObjectID == _document._trailer.ObjectID && item.Key == PdfTrailer.Keys.ID)
                    {
                        continue;
                    }

                    DecryptArray(value3);
                }
            }
            if (dict.Stream != null && dict.ObjectID != _document?._trailer?.ObjectID)
            {
                PdfObjectStream objStream = dict as PdfObjectStream;

                if (!(objStream?._decrypted ?? false))
                {
                    byte[] bytes = dict.Stream.Value;
                    if (bytes.Length != 0)
                    {
                        PrepareAESKey();
                        PrepareAESIV(bytes, 0, 16);
                        byte[] temp = new byte[bytes.Length];

                        int length = DecryptAES(bytes, 16, bytes.Length - 16, temp);

                        Array.Resize(ref temp, length);

                        dict.Stream.Value = temp;
                    }

                    if (objStream != null)
                    {
                        objStream._decrypted = true;
                    }
                }
            }
        }

        /// <summary>
        /// Encrypts an array.
        /// </summary>
        void EncryptArray(PdfArray array)
        {
            int count = array.Elements.Count;
            for (int idx = 0; idx < count; idx++)
            {
                PdfItem item = array.Elements[idx];
                PdfString value1;
                PdfDictionary value2;
                PdfArray value3;
                if ((value1 = item as PdfString) != null)
                    EncryptString(value1);
                else if ((value2 = item as PdfDictionary) != null)
                    EncryptDictionary(value2);
                else if ((value3 = item as PdfArray) != null)
                    EncryptArray(value3);
            }
        }

        /// <summary>
        /// Decrypts an array.
        /// </summary>
        void DecryptArray(PdfArray array)
        {
            int count = array.Elements.Count;
            for (int idx = 0; idx < count; idx++)
            {
                PdfItem item = array.Elements[idx];
                PdfString value1;
                PdfDictionary value2;
                PdfArray value3;
                if ((value1 = item as PdfString) != null)
                    DecryptString(value1);
                else if ((value2 = item as PdfDictionary) != null)
                    DecryptDictionary(value2);
                else if ((value3 = item as PdfArray) != null)
                    DecryptArray(value3);
            }
        }

        /// <summary>
        /// Encrypts a string.
        /// </summary>
        void EncryptString(PdfString value)
        {
            if (value.Length != 0)
            {
                byte[] bytes = value.EncryptionValue;
                PrepareAESKey();
                EncryptAES(bytes);
                value.EncryptionValue = bytes;
            }
        }

        /// <summary>
        /// Decrypts a string.
        /// </summary>
        void DecryptString(PdfString value)
        {
            if (value.Length != 0)
            {
                try
                {
                    byte[] bytes = value.EncryptionValue;
                    PrepareAESKey();
                    PrepareAESIV(bytes, 0, 16);
                    byte[] temp = new byte[bytes.Length];

                    int length = DecryptAES(bytes, 16, bytes.Length - 16, temp);

                    Array.Resize(ref temp, length);

                    value.EncryptionValue = temp;
                }
                catch (CryptographicException ex)
                {
#if DEBUG
                    Debug.WriteLine($">>> Decrypt string error, trying without padding: {ex.Message}");
                    DumpBytes("key", _key);
                    DumpBytes("data", value.EncryptionValue);
#endif
                }
            }
        }

        /// <summary>
        /// Encrypts an array.
        /// </summary>
        public override byte[] EncryptBytes(byte[] bytes)
        {
            if (bytes != null && bytes.Length != 0)
            {
                PrepareAESKey();
                EncryptAES(bytes);
            }
            return bytes;
        }

        /// <summary>
        /// Decrypts an array.
        /// </summary>
        public override byte[] DecryptBytes(byte[] bytes)
        {
            if (bytes != null && bytes.Length != 0)
            {
                PrepareAESKey();
                PrepareAESIV(bytes, 0, 16);
                byte[] temp = new byte[bytes.Length];

                int length = DecryptAES(bytes, 16, bytes.Length - 16, temp);

                Array.Resize(ref temp, length);

                return temp;
            }

            return bytes;
        }

        #region Encryption Algorithms

        /// <summary>
        /// Tests the encryption dictionary to see if this handler supports the
        /// algorithm specified in its data
        /// </summary>
        /// <param name="dict">The encryption dictionary</param>
        /// <returns>True if this class can handle this algorithm, false otherwise</returns>
        public static bool CanHandle(PdfDictionary dict)
        {
            string filter = dict.Elements.GetName(PdfSecurityHandler.Keys.Filter);
            int v = dict.Elements.GetInteger(PdfSecurityHandler.Keys.V);
            int r = dict.Elements.GetInteger(Keys.R);
            int keyLength = dict.Elements.GetInteger(PdfSecurityHandler.Keys.Length);

            if (filter != Filter || v != 4 || r != 4 || keyLength != 128)
                return false;

            PdfDictionary cf = dict.Elements.GetDictionary(PdfSecurityHandler.Keys.CF);

            if (!cf.Elements.ContainsKey(PdfCryptoFilter.StdCF))
                return false;

            PdfDictionary stdCF = cf.Elements.GetDictionary(PdfCryptoFilter.StdCF);
            string cfm = stdCF.Elements.GetName(PdfCryptoFilter.Keys.CFM);

            if (cfm != PdfCryptoFilter.AESV2)
                return false;

            return true;
        }

        /// <summary>
        /// Checks the password.
        /// </summary>
        /// <param name="inputPassword">Password or null if no password is provided.</param>
        public override PasswordValidity ValidatePassword(string inputPassword)
        {
            // We can handle AES V2 encryption.
            if (!CanHandle(this))
                throw new PdfReaderException(PSSR.UnknownEncryption);

            byte[] documentID = PdfEncoders.RawEncoding.GetBytes(Owner.Internals.FirstDocumentID);
            byte[] oValue = PdfEncoders.RawEncoding.GetBytes(Elements.GetString(Keys.O));
            byte[] uValue = PdfEncoders.RawEncoding.GetBytes(Elements.GetString(Keys.U));
            int pValue = Elements.GetInteger(Keys.P);
            int rValue = Elements.GetInteger(Keys.R);
            _encryptMetadata = true;

            if (Elements.ContainsKey(PdfCryptoFilter.Keys.EncryptMetadata))
            {
                _encryptMetadata = Elements.GetBoolean(PdfCryptoFilter.Keys.EncryptMetadata);
            }

            if (inputPassword == null)
            {
                inputPassword = string.Empty;
            }

            // Try owner password first.
            InitWithOwnerPassword(documentID, inputPassword, inputPassword, oValue, pValue, _encryptMetadata);

            PasswordValidity result = CheckOwnerPassword(documentID, pValue, _ownerKey, oValue, uValue, _encryptMetadata);
            _document.SecuritySettings._hasOwnerPermissions = result == PasswordValidity.OwnerPassword;

            if (result == PasswordValidity.OwnerPassword)
            {
                return result;
            }

            // Now try user password.
            InitWithUserPassword(documentID, inputPassword, oValue, pValue, _encryptMetadata);

            return CheckUserPassword(_userKey, uValue);
        }

        internal PasswordValidity CheckUserPassword(byte[] userKey, byte[] uValue)
        {
            if (EqualsKey(userKey, uValue, 16))
            {
                return PasswordValidity.UserPassword;
            }

            return PasswordValidity.Invalid;
        }

        internal PasswordValidity CheckOwnerPassword(byte[] documentId, int permissions, byte[] ownerKey, byte[] oValue, byte[] uValue, bool encryptMetadata)
        {
            byte[] paddedPassword = new byte[32];
            Array.Copy(oValue, 0, paddedPassword, 0, 32);

            byte[] mkey = new byte[16];

            // Encrypt the key
            for (int i = 19; i >= 0; i--)
            {
                for (int j = 0; j < 16; ++j)
                {
                    mkey[j] = (byte)(ownerKey[j] ^ i);
                }

#if DEBUG
                Debug.WriteLine(string.Format("CHECK O PASS {0}", i));
                DumpBytes("key", mkey);
                DumpBytes("data", paddedPassword);
#endif

                PrepareRC4Key(mkey, length: 16);
                EncryptRC4(paddedPassword);

#if DEBUG
                DumpBytes("output", paddedPassword);
#endif
            }

            _encryptionKey = CreateEncryptionKey(documentId, paddedPassword, oValue, permissions, encryptMetadata);
            _userKey = SetupUserKey(documentId, _encryptionKey);

            if (CheckUserPassword(_userKey, uValue) == PasswordValidity.UserPassword)
            {
                return PasswordValidity.OwnerPassword;
            }

            return PasswordValidity.Invalid;
        }

        [Conditional("DEBUG")]
        internal static void DumpBytes(string tag, byte[] bytes)
        {
            string dump = tag + ": ";

            for (int idx = 0; idx < bytes.Length; idx++)
            {
                dump += string.Format("{0:X2}", bytes[idx]);
            }

            Debug.WriteLine(dump);
        }

        /// <summary>
        /// Pads a password to a 32 byte array.
        /// </summary>
        internal static byte[] PadPassword(string password)
        {
            byte[] padded = new byte[32];

            if (string.IsNullOrEmpty(password))
            {
                Array.Copy(PasswordPadding, 0, padded, 0, 32);
            }
            else
            {
                int length = Math.Min(password.Length, 32);

                string win1252String = ConvertUnicodeToWin1252(password);
                byte[] passwordBytes = PdfEncoders.DocEncoding.GetBytes(win1252String);

                Array.Copy(passwordBytes, 0, padded, 0, length);

                if (length < 32)
                {
                    Array.Copy(PasswordPadding, 0, padded, length, 32 - length);
                }
            }

            return padded;
        }

        static string ConvertUnicodeToWin1252(string source)
        {
            var unicode = new UnicodeEncoding();
            var win1252 = Encoding.GetEncoding(1252);

            byte[] input = unicode.GetBytes(source);
            byte[] output = Encoding.Convert(unicode, win1252, input);

            return win1252.GetString(output);
        }

        static readonly byte[] PasswordPadding = // 32 bytes password padding defined by Adobe
            {
              0x28, 0xBF, 0x4E, 0x5E, 0x4E, 0x75, 0x8A, 0x41, 0x64, 0x00, 0x4E, 0x56, 0xFF, 0xFA, 0x01, 0x08,
              0x2E, 0x2E, 0x00, 0xB6, 0xD0, 0x68, 0x3E, 0x80, 0x2F, 0x0C, 0xA9, 0xFE, 0x64, 0x53, 0x69, 0x7A
            };

        /// <summary>
        /// Generates the user key based on the padded user password.
        /// </summary>
        internal void InitWithUserPassword(byte[] documentID, string userPassword, byte[] oValue, int permissions, bool encryptMetadata)
        {
            _encryptionKey = CreateEncryptionKey(documentID, userPassword, oValue, permissions, encryptMetadata);
            _userKey = SetupUserKey(documentID, _encryptionKey);
        }

        /// <summary>
        /// Generates the user key based on the padded owner password.
        /// </summary>
        internal void InitWithOwnerPassword(byte[] documentID, string userPassword, string ownerPassword, byte[] oValue, int permissions, bool encryptMetadata)
        {
            if (string.IsNullOrEmpty(ownerPassword))
            {
                ownerPassword = userPassword;
            }

            _encryptionKey = CreateEncryptionKey(documentID, userPassword, oValue, permissions, encryptMetadata);

            _ownerKey = SetupOwnerKey(ownerPassword);
            byte[] calculatedOValue = CreateOwnerKey(_ownerKey, userPassword);

            byte[] userKey = SetupUserKey(documentID, _encryptionKey);
            Array.Copy(userKey, 0, _userKey, 0, 32);
        }

        /// <summary>
        /// Computes the padded user password from the padded owner password.
        /// </summary>
        internal byte[] SetupOwnerKey(string ownerPassword)
        {
            var ownerPadding = PadPassword(ownerPassword);

            byte[] ownerKey = new byte[16];

            //#if !SILVERLIGHT

            _md5.Initialize();
            byte[] digest = _md5.ComputeHash(ownerPadding);

            // Hash the pad 50 times
            for (int idx = 0; idx < 50; idx++)
            {
                _md5.Initialize();
                digest = _md5.ComputeHash(digest, 0, 16);
            }

            Array.Copy(digest, 0, ownerKey, 0, 16);

            //#endif

            return ownerKey;
        }

        /// <summary>
        /// Computes the padded user password from the padded owner password.
        /// </summary>
        internal byte[] CreateOwnerKey(byte[] ownerKey, string userPassword)
        {
            var userPadding = PadPassword(userPassword);

            byte[] oValue = new byte[32];
            Array.Copy(userPadding, 0, oValue, 0, 32);

            //#if !SILVERLIGHT

            byte[] mkey = new byte[16];

            // Encrypt the key
            for (int i = 0; i < 20; i++)
            {
                for (int j = 0; j < 16; ++j)
                {
                    mkey[j] = (byte)(ownerKey[j] ^ i);
                }

#if DEBUG
                Debug.WriteLine(string.Format("CREATE O PASS {0}", i));
                DumpBytes("key", mkey);
                DumpBytes("data", oValue);
#endif

                PrepareRC4Key(mkey, length: 16);
                EncryptRC4(oValue);

#if DEBUG
                DumpBytes("output", oValue);
#endif
            }

            //#endif

            return oValue;
        }

        /// <summary>
        /// Computes the encryption key.
        /// </summary>
        internal byte[] CreateEncryptionKey(byte[] documentID, string password, byte[] oValue, int permissions, bool encryptMetadata)
        {
            var paddedPassword = PadPassword(password);

            return CreateEncryptionKey(documentID, paddedPassword, oValue, permissions, encryptMetadata);
        }

        /// <summary>
        /// Computes the encryption key.
        /// </summary>
        internal byte[] CreateEncryptionKey(byte[] documentID, byte[] paddedPassword, byte[] oValue, int permissions, bool encryptMetadata)
        {
            //#if !SILVERLIGHT
            byte[] encryptionKey = new byte[16];

#if !NETFX_CORE
            _md5.Initialize();

            _md5.TransformBlock(paddedPassword, 0, paddedPassword.Length, paddedPassword, 0);
            _md5.TransformBlock(oValue, 0, oValue.Length, oValue, 0);

            // Split permission into 4 bytes
            byte[] permission = new byte[4];
            permission[0] = (byte)permissions;
            permission[1] = (byte)(permissions >> 8);
            permission[2] = (byte)(permissions >> 16);
            permission[3] = (byte)(permissions >> 24);

            _md5.TransformBlock(permission, 0, 4, permission, 0);

            if (!encryptMetadata)
            {
                _md5.TransformBlock(documentID, 0, documentID.Length, documentID, 0);

                byte[] values = { 0xFF, 0xFF, 0xFF, 0xFF };
                _md5.TransformFinalBlock(values, 0, values.Length);
            }
            else
            {
                _md5.TransformFinalBlock(documentID, 0, documentID.Length);
            }

            byte[] digest = _md5.Hash;

            for (int idx = 0; idx < 50; idx++)
            {
                _md5.Initialize();
                digest = _md5.ComputeHash(digest, 0, 16);
            }

            Array.Copy(digest, 0, encryptionKey, 0, encryptionKey.Length);
            return encryptionKey;
            //#endif
#endif
        }

        /// <summary>
        /// Computes the user key.
        /// </summary>
        internal byte[] SetupUserKey(byte[] documentID, byte[] encryptionKey)
        {
#if !NETFX_CORE
            //#if !SILVERLIGHT
            var userPadding = PadPassword(string.Empty);

            byte[] userKey = new byte[32];

            _md5.Initialize();

            _md5.TransformBlock(userPadding, 0, userPadding.Length, userPadding, 0);
            _md5.TransformFinalBlock(documentID, 0, documentID.Length);
            byte[] digest = _md5.Hash;

            Array.Copy(_md5.Hash, 0, userKey, 0, 16);

            PrepareRC4Key(encryptionKey, length: 16);
            EncryptRC4(userKey, 0, 16);

            //Encrypt the key
            for (int i = 1; i < 20; i++)
            {
                for (int j = 0; j < 16; j++)
                {
                    digest[j] = (byte)(encryptionKey[j] ^ i);
                }

#if DEBUG
                Debug.WriteLine(string.Format("CREATE U PASS {0}", i));
                DumpBytes("key", digest);
                DumpBytes("data", userKey);
#endif

                PrepareRC4Key(digest, length: 16);
                EncryptRC4(userKey, 0, 16);

#if DEBUG
                DumpBytes("output", userKey);
#endif
            }

            return userKey;
            //#endif
#endif
        }

        /// <summary>
        /// Prepare the encryption key.
        /// </summary>
        internal void PrepareRC4Key()
        {
            PrepareRC4Key(_key, length: _keySize);
        }

        /// <summary>
        /// Prepare the encryption key.
        /// </summary>
        internal void PrepareRC4Key(byte[] key, int offset = 0, int length = 0)
        {
            if (length == 0)
                return;

            int idx1 = 0;
            int idx2 = 0;

            for (int idx = 0; idx < 256; idx++)
                _state[idx] = (byte)idx;

            byte tmp;

            for (int idx = 0; idx < 256; idx++)
            {
                idx2 = (key[idx1 + offset] + _state[idx] + idx2) & 255;
                tmp = _state[idx];
                _state[idx] = _state[idx2];
                _state[idx2] = tmp;
                idx1 = (idx1 + 1) % length;
            }
        }

        /// <summary>
        /// Prepare the encryption key.
        /// </summary>
        internal void PrepareAESKey()
        {
            PrepareAESKey(_key, 0, _key.Length);
        }

        /// <summary>
        /// Prepare the encryption key.
        /// </summary>
        internal void PrepareAESKey(byte[] key, int offset = 0, int length = 0)
        {
            if (length == 0)
            {
                length = key.Length;
            }

            _aes.Clear();
            _aes.BlockSize = 128;
            _aes.KeySize = 128;
            _aes.Mode = CipherMode.CBC;
            _aes.Padding = PaddingMode.PKCS7;

            byte[] temp = new byte[length];
            Array.Copy(key, offset, temp, 0, length);
            _aes.Key = temp;
        }

        /// <summary>
        /// Prepare the encryption key.
        /// </summary>
        internal void PrepareAESIV(byte[] iv)
        {
            PrepareAESIV(iv, 0, iv?.Length ?? 0);
        }

        /// <summary>
        /// Prepare the encryption key.
        /// </summary>
        internal void PrepareAESIV(byte[] iv, int offset = 0, int length = 0)
        {
            if (iv == null)
            {
                _aes.IV = new byte[16];
            }
            else
            {
                if (length == 0)
                {
                    length = iv.Length;
                }

                byte[] temp = new byte[length];
                Array.Copy(iv, offset, temp, 0, length);
                _aes.IV = temp;
            }
        }

        /// <summary>
        /// Encrypts the data.
        /// </summary>
        // ReSharper disable InconsistentNaming
        internal void EncryptRC4(byte[] data)
        // ReSharper restore InconsistentNaming
        {
            EncryptRC4(data, 0, data.Length, data);
        }

        /// <summary>
        /// Encrypts the data.
        /// </summary>
        // ReSharper disable InconsistentNaming
        internal void EncryptRC4(byte[] data, int offset, int length)
        // ReSharper restore InconsistentNaming
        {
            EncryptRC4(data, offset, length, data);
        }

        /// <summary>
        /// Encrypts the data.
        /// </summary>
        internal void EncryptRC4(byte[] inputData, byte[] outputData)
        {
            EncryptRC4(inputData, 0, inputData.Length, outputData);
        }

        /// <summary>
        /// Encrypts the data.
        /// </summary>
        internal void EncryptRC4(byte[] inputData, int offset, int length, byte[] outputData)
        {
            length += offset;
            int x = 0, y = 0;
            byte b;

            for (int idx = offset; idx < length; idx++)
            {
                x = (x + 1) & 255;
                y = (_state[x] + y) & 255;
                b = _state[x];
                _state[x] = _state[y];
                _state[y] = b;
                outputData[idx] = (byte)(inputData[idx] ^ _state[(_state[x] + _state[y]) & 255]);
            }
        }

        /// <summary>
        /// Decrypts the data.
        /// </summary>
        // ReSharper disable InconsistentNaming
        internal int DecryptAES(byte[] data)
        // ReSharper restore InconsistentNaming
        {
            return DecryptAES(data, 0, data.Length, data);
        }

        /// <summary>
        /// Decrypts the data.
        /// </summary>
        // ReSharper disable InconsistentNaming
        internal int DecryptAES(byte[] data, int offset, int length)
        // ReSharper restore InconsistentNaming
        {
            return DecryptAES(data, offset, length, data);
        }

        /// <summary>
        /// Decrypts the data.
        /// </summary>
        internal int DecryptAES(byte[] inputData, byte[] outputData)
        {
            return DecryptAES(inputData, 0, inputData.Length, outputData);
        }

        /// <summary>
        /// Decrypts the data.
        /// </summary>
        internal int DecryptAES(byte[] inputData, int offset, int length, byte[] outputData)
        {
            using (var decryptor = _aes.CreateDecryptor())
            {
                var data = decryptor.TransformFinalBlock(inputData, offset, length);
                int responseLength = Math.Min(data.Length, length);

                Array.Clear(outputData, 0, length);
                Array.Copy(data, outputData, responseLength);

                return responseLength;
            }
        }

        /// <summary>
        /// Encrypts the data.
        /// </summary>
        // ReSharper disable InconsistentNaming
        internal int EncryptAES(byte[] data)
        // ReSharper restore InconsistentNaming
        {
            return EncryptAES(data, 0, data.Length, data);
        }

        /// <summary>
        /// Encrypts the data.
        /// </summary>
        // ReSharper disable InconsistentNaming
        internal int EncryptAES(byte[] data, int offset, int length)
        // ReSharper restore InconsistentNaming
        {
            return EncryptAES(data, offset, length, data);
        }

        /// <summary>
        /// Encrypts the data.
        /// </summary>
        internal int EncryptAES(byte[] inputData, byte[] outputData)
        {
            return EncryptAES(inputData, 0, inputData.Length, outputData);
        }

        /// <summary>
        /// Encrypts the data.
        /// </summary>
        internal int EncryptAES(byte[] inputData, int offset, int length, byte[] outputData)
        {
            using (var encryptor = _aes.CreateEncryptor())
            {
                var data = encryptor.TransformFinalBlock(inputData, offset, length);
                int responseLength = Math.Max(data.Length, length);

                Array.Copy(data, outputData, Math.Max(data.Length, length));
                return responseLength;
            }
        }

        /// <summary>
        /// Checks whether the calculated key correct.
        /// </summary>
        internal bool EqualsKey(byte[] key, byte[] value, int length)
        {
            for (int idx = 0; idx < length; idx++)
            {
                if (key[idx] != value[idx])
                    return false;
            }
            return true;
        }

        /// <summary>
        /// Set the hash key for the specified object.
        /// </summary>
        internal override void SetHashKey(PdfObjectID id)
        {
#if !NETFX_CORE
            //#if !SILVERLIGHT
            byte[] objectId = new byte[5];
            _md5.Initialize();

            // Split the object number and generation
            objectId[0] = (byte)id.ObjectNumber;
            objectId[1] = (byte)(id.ObjectNumber >> 8);
            objectId[2] = (byte)(id.ObjectNumber >> 16);
            objectId[3] = (byte)id.GenerationNumber;
            objectId[4] = (byte)(id.GenerationNumber >> 8);

            _md5.TransformBlock(_encryptionKey, 0, _encryptionKey.Length, _encryptionKey, 0);
            _md5.TransformBlock(objectId, 0, objectId.Length, objectId, 0);
            _md5.TransformFinalBlock(KeySalt, 0, KeySalt.Length);
            _key = _md5.Hash;

            _md5.Initialize();

            _keySize = _encryptionKey.Length + 5;

            if (_keySize > 16)
            {
                _keySize = 16;
            }
            //#endif
#endif
        }

        static readonly byte[] KeySalt = // 4 bytes salt for backward compatibility, not intended to provide additional security.
            {
              0x73, 0x41, 0x6C, 0x54
            };

        /// <summary>
        /// Prepares the security handler for encrypting the document.
        /// </summary>
        public override void PrepareEncryption()
        {
            //#if !SILVERLIGHT
            Debug.Assert(_document._securitySettings.DocumentSecurityLevel != PdfDocumentSecurityLevel.None);
            int permissions = (int)Permission;

            PdfInteger vValue = new PdfInteger(4);
            PdfInteger length = new PdfInteger(128);
            PdfInteger rValue = new PdfInteger(4);

            if (string.IsNullOrEmpty(_userPassword))
                _userPassword = string.Empty;

            // Use user password twice if no owner password provided.
            if (string.IsNullOrEmpty(_ownerPassword))
            {
                _ownerPassword = _userPassword;
            }

            // Correct permission bits
            permissions |= unchecked((int)0xfffff0c0);
            permissions &= unchecked((int)0xfffffffc);

            PdfInteger pValue = new PdfInteger(permissions);

            Debug.Assert(_ownerPassword.Length > 0, "Empty owner password.");

            _md5.Initialize();
            _ownerKey = SetupOwnerKey(_ownerPassword);
            _ownerKey = CreateOwnerKey(_ownerKey, _userPassword);
            byte[] documentID = PdfEncoders.RawEncoding.GetBytes(_document.Internals.FirstDocumentID);

            bool isV4 = vValue.Value >= 4;
            InitWithUserPassword(documentID, _userPassword, _ownerKey, permissions, true);

            PdfString oValue = new PdfString(PdfEncoders.RawEncoding.GetString(_ownerKey, 0, _ownerKey.Length));
            PdfString uValue = new PdfString(PdfEncoders.RawEncoding.GetString(_userKey, 0, _userKey.Length));

            Elements[PdfSecurityHandler.Keys.Filter] = new PdfName("/Standard");
            Elements[PdfSecurityHandler.Keys.V] = vValue;
            Elements[PdfSecurityHandler.Keys.Length] = length;
            Elements[Keys.R] = rValue;
            Elements[Keys.O] = oValue;
            Elements[Keys.U] = uValue;
            Elements[Keys.P] = pValue;
            //#endif
        }

        /// <summary>
        /// The global encryption key.
        /// </summary>
        internal byte[] _encryptionKey;

#if !SILVERLIGHT && !UWP
        /// <summary>
        /// The message digest algorithm MD5.
        /// </summary>
        readonly MD5 _md5 = new MD5CryptoServiceProvider();
#if DEBUG_
        readonly MD5Managed _md5M = new MD5Managed();
#endif
#else
        readonly MD5Managed _md5 = new MD5Managed();
#endif
#if NETFX_CORE
        // readonly MD5Managed _md5 = new MD5Managed();
#endif
        /// <summary>
        /// Bytes used for RC4 encryption.
        /// </summary>
        readonly byte[] _state = new byte[256];

        readonly Rijndael _aes = new RijndaelManaged();

        /// <summary>
        /// The encryption key for the owner.
        /// </summary>
        byte[] _ownerKey = new byte[32];

        /// <summary>
        /// The encryption key for the user.
        /// </summary>
        byte[] _userKey = new byte[32];

        /// <summary>
        /// The encryption key for a particular object/generation.
        /// </summary>
        internal byte[] _key;

        /// <summary>
        /// The encryption key length for a particular object/generation.
        /// </summary>
        int _keySize;

        #endregion

        internal override void WriteObject(PdfWriter writer)
        {
            // Don't encrypt myself.
            PdfSecurityHandler securityHandler = writer.SecurityHandler;
            writer.SecurityHandler = null;
            base.WriteObject(writer);
            writer.SecurityHandler = securityHandler;
        }

        #region Keys
        /// <summary>
        /// Predefined keys of this dictionary.
        /// </summary>
        internal sealed new class Keys : PdfSecurityHandler.Keys
        {
            /// <summary>
            /// (Required) A number specifying which revision of the standard security handler
            /// should be used to interpret this dictionary:
            /// • 2 if the document is encrypted with a V value less than 2 and does not have any of
            ///   the access permissions set (by means of the P entry, below) that are designated 
            ///   "Revision 3 or greater".
            /// • 3 if the document is encrypted with a V value of 2 or 3, or has any "Revision 3 or 
            ///   greater" access permissions set.
            /// • 4 if the document is encrypted with a V value of 4
            /// </summary>
            [KeyInfo(KeyType.Integer | KeyType.Required)]
            public const string R = "/R";

            /// <summary>
            /// (Required) A 32-byte string, based on both the owner and user passwords, that is
            /// used in computing the encryption key and in determining whether a valid owner
            /// password was entered.
            /// </summary>
            [KeyInfo(KeyType.String | KeyType.Required)]
            public const string O = "/O";

            /// <summary>
            /// (Required) A 32-byte string, based on the user password, that is used in determining
            /// whether to prompt the user for a password and, if so, whether a valid user or owner 
            /// password was entered.
            /// </summary>
            [KeyInfo(KeyType.String | KeyType.Required)]
            public const string U = "/U";

            /// <summary>
            /// (Required) A set of flags specifying which operations are permitted when the document
            /// is opened with user access.
            /// </summary>
            [KeyInfo(KeyType.Integer | KeyType.Required)]
            public const string P = "/P";

            /// <summary>
            /// (Optional; meaningful only when the value of V is 4; PDF 1.5) Indicates whether
            /// the document-level metadata stream is to be encrypted. Applications should respect this value.
            /// Default value: true.
            /// </summary>
            [KeyInfo(KeyType.Boolean | KeyType.Optional)]
            public const string EncryptMetadata = "/EncryptMetadata";

            /// <summary>
            /// Gets the KeysMeta for these keys.
            /// </summary>
            public static DictionaryMeta Meta
            {
                get { return _meta ?? (_meta = CreateMeta(typeof(Keys))); }
            }
            static DictionaryMeta _meta;
        }

        /// <summary>
        /// Gets the KeysMeta of this dictionary type.
        /// </summary>
        internal override DictionaryMeta Meta
        {
            get { return Keys.Meta; }
        }
        #endregion
    }
}
