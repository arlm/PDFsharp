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
    /// Represents the AESV3 PDF security handler.
    /// </summary>
    public sealed class PdfAESV3SecurityHandler : PdfSecurityHandler
    {
        internal PdfAESV3SecurityHandler(PdfDocument document)
            : base(document)
        { }

        internal PdfAESV3SecurityHandler(PdfDictionary dict)
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
                    _document._securitySettings.DocumentSecurityLevel = PdfDocumentSecurityLevel.AES_V3;
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
                    _document._securitySettings.DocumentSecurityLevel = PdfDocumentSecurityLevel.AES_V3;
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

            if (filter != Filter || v != 5 || !(r >= 5 && v <= 6) || keyLength != 256)
                return false;

            PdfDictionary cf = dict.Elements.GetDictionary(PdfSecurityHandler.Keys.CF);

            if (!cf.Elements.ContainsKey(PdfCryptoFilter.StdCF))
                return false;

            PdfDictionary stdCF = cf.Elements.GetDictionary(PdfCryptoFilter.StdCF);
            string cfm = stdCF.Elements.GetName(PdfCryptoFilter.Keys.CFM);

            if (cfm != PdfCryptoFilter.AESV3)
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
            byte[] oeValue = PdfEncoders.RawEncoding.GetBytes(Elements.GetString(Keys.OE));
            byte[] ueValue = PdfEncoders.RawEncoding.GetBytes(Elements.GetString(Keys.UE));
            byte[] permsValue = PdfEncoders.RawEncoding.GetBytes(Elements.GetString(Keys.Perms));
            int pValue = Elements.GetInteger(Keys.P);
            int rValue = Elements.GetInteger(Keys.R);
            int vValue = Elements.GetInteger(PdfSecurityHandler.Keys.V);
            bool isV4 = vValue >= 4;
            _encryptMetadata = true;

            byte[] ownerData = new byte[32];
            Array.Copy(oValue, 0, ownerData, 0, 32);

            byte[] ownerValidationSalt = new byte[8];
            Array.Copy(oValue, 32, ownerValidationSalt, 0, 8);

            byte[] ownerKeySalt = new byte[8];
            Array.Copy(oValue, 40, ownerKeySalt, 0, 8);

            byte[] userData = new byte[32];
            Array.Copy(oValue, 0, userData, 0, 32);

            byte[] userValidationSalt = new byte[8];
            Array.Copy(uValue, 32, userValidationSalt, 0, 8);

            byte[] userKeySalt = new byte[8];
            Array.Copy(uValue, 40, userKeySalt, 0, 8);

            if (Elements.ContainsKey(PdfCryptoFilter.Keys.EncryptMetadata))
            {
                _encryptMetadata = Elements.GetBoolean(PdfCryptoFilter.Keys.EncryptMetadata);
            }

            if (inputPassword == null)
            {
                inputPassword = string.Empty;
            }

            // Try owner password first.
            InitWithOwnerPassword(inputPassword, inputPassword, uValue, rValue, _encryptMetadata, ownerKeySalt, oeValue, userKeySalt, ueValue);

            PasswordValidity result = CheckOwnerPassword(inputPassword, ownerValidationSalt, uValue, oValue, rValue);
            _document.SecuritySettings._hasOwnerPermissions = result == PasswordValidity.OwnerPassword;

            if (result == PasswordValidity.OwnerPassword)
            {
                if (CheckPerms(pValue, permsValue, _encryptionKey, _encryptMetadata))
                {
                    return result;
                }
            }

            // Now try user password.
            InitWithUserPassword(inputPassword, rValue, _encryptMetadata, userKeySalt, ueValue);

            result = CheckUserPassword(inputPassword, userValidationSalt, uValue, rValue);

            if (result == PasswordValidity.UserPassword)
            {
                if (CheckPerms(pValue, permsValue, _encryptionKey, _encryptMetadata))
                {
                    return result;
                }
            }

            return PasswordValidity.Invalid;
        }

        internal PasswordValidity CheckUserPassword(string password, byte[] userValidationSalt, byte[] uValue, int rValue)
        {
            byte[] passwordBytes = PadPassword(password);

            byte[] result;
            _sha256.Initialize();

            if (rValue == 5)
            {
                _sha256.TransformBlock(passwordBytes, 0, passwordBytes.Length, passwordBytes, 0);
                _sha256.TransformFinalBlock(userValidationSalt, 0, userValidationSalt.Length);

                result = _sha256.Hash;
            }
            else
            {
                _sha256.TransformBlock(passwordBytes, 0, passwordBytes.Length, passwordBytes, 0);
                _sha256.TransformFinalBlock(userValidationSalt, 0, userValidationSalt.Length);

                result = ComputePDF20Hash(passwordBytes, _sha256.Hash, null);
            }

            if (EqualsKey(uValue, result, 32))
            {
                return PasswordValidity.UserPassword;
            }

            return PasswordValidity.Invalid;
        }

        internal PasswordValidity CheckOwnerPassword(string password, byte[] ownerValidationSalt, byte[] uValue, byte[] oValue, int rValue)
        {
            byte[] passwordBytes = PadPassword(password);
            byte[] result;

            _sha256.Initialize();

            if (rValue == 5)
            {
                _sha256.TransformBlock(passwordBytes, 0, passwordBytes.Length, passwordBytes, 0);
                _sha256.TransformBlock(ownerValidationSalt, 0, ownerValidationSalt.Length, ownerValidationSalt, 0);
                _sha256.TransformFinalBlock(uValue, 0, 48);

                result = _sha256.Hash;
            }
            else
            {
                _sha256.TransformBlock(passwordBytes, 0, passwordBytes.Length, passwordBytes, 0);
                _sha256.TransformBlock(ownerValidationSalt, 0, ownerValidationSalt.Length, ownerValidationSalt, 0);
                _sha256.TransformFinalBlock(uValue, 0, 48);

                result = ComputePDF20Hash(passwordBytes, _sha256.Hash, uValue);
            }

            if (EqualsKey(oValue, result, 32))
            {
                return PasswordValidity.OwnerPassword;
            }

            return PasswordValidity.Invalid;
        }

        internal bool CheckPerms(int permissions, byte[] permsValue, byte[] encryptionKey, bool encryptMetadata)
        {
            byte[] permission = new byte[16];

            PrepareAESKey(encryptionKey);
            PrepareAESIV(null);
            _aes.Padding = PaddingMode.None;

            DecryptAES(permsValue, permission);

            if (permission[9] != 97 /* 'a */ ||
                permission[10] != 100 /* 'd' */ ||
                permission[11] != 98 /* 'b' */)
            {
                return false;
            }

            byte encryptMetadataByte = (byte)(encryptMetadata ? 0x54 /* 'T' */ : 0x46 /* 'F' */);

            if (permission[8] != encryptMetadataByte)
            {
                return false;
            }

            int p = permission[0] & 0xFF |
                    permission[1] << 8 |
                    permission[2] << 16 |
                    permission[3] << 24;

            if (p != permissions)
            {
                return false;
            }

            return true;
        }

        private byte[] ComputePDF20Hash(byte[] passwordBytes, byte[] input, byte[] uValue)
        {
            byte[] result;
            byte[] k = new byte[32];
            Array.Copy(input, k, 32);

            SHA384 sha384 = new SHA384Managed();
            SHA512 sha512 = new SHA512Managed();

            _sha256.Initialize();
            sha384.Initialize();
            sha512.Initialize();

            byte[] e = null;
            int round = 0;

            while (round < 64 || e[e.Length - 1] > (round - 32))
            {
                int arrayLength = passwordBytes.Length + k.Length + (uValue == null ? 0 : 48);
                byte[] k1 = new byte[arrayLength * 64];

                for (int index = 0, pos = 0; index < 64; index++)
                {
                    Array.Copy(passwordBytes, 0, k1, pos, passwordBytes.Length);
                    pos += passwordBytes.Length;

                    Array.Copy(k, 0, k1, pos, k.Length);
                    pos += k.Length;

                    if (uValue != null && uValue.Length >= 48)
                    {
                        Array.Copy(uValue, 0, k1, pos, 48);
                        pos += 48;
                    }
                }

                PrepareAESKey(k, 0, 16, keySize: 128);
                PrepareAESIV(k, 16, 16);
                _aes.Padding = PaddingMode.None;

                e = new byte[k1.Length];
                EncryptAES(k1, e);

                int remainder = 0;

                for (int index = 0; index < 16; index++)
                {
                    remainder += e[index];
                }

                remainder %= 3;

                if (remainder == 0)
                {
                    k = _sha256.ComputeHash(e, 0, e.Length);
                }
                else if (remainder == 1)
                {
                    k = sha384.ComputeHash(e, 0, e.Length);
                }
                else if (remainder == 2)
                {
                    k = sha512.ComputeHash(e, 0, e.Length);
                }

                round++;
            }

            result = new byte[32];
            Array.Copy(k, 0, result, 0, 32);
            return result;
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
            string saslPrepString = StringPrep.SaslPrep(password);
            string utf8String = ConvertUnicodeToUTF8(saslPrepString);
            byte[] passwordBytes = PdfEncoders.RawEncoding.GetBytes(utf8String);

            int length = Math.Min(127, passwordBytes.Length);
            byte[] paddedPassword = new byte[length];
            Array.Copy(passwordBytes, paddedPassword, length);

            return paddedPassword;
        }

        static string ConvertUnicodeToUTF8(string source)
        {
            var unicode = new UnicodeEncoding();

            byte[] input = unicode.GetBytes(source);
            byte[] output = Encoding.Convert(unicode, Encoding.UTF8, input);

            return Encoding.UTF8.GetString(output);
        }

        /// <summary>
        /// Generates the user key based on the padded user password.
        /// </summary>
        internal void InitWithUserPassword(string userPassword, int rValue, bool encryptMetadata, byte[] userKeysalt, byte[] userEncryption)
        {
            _encryptionKey = SetupUserKey(userPassword, userKeysalt, userEncryption, rValue);
            _userKey = _encryptionKey;
        }

        /// <summary>
        /// Generates the user key based on the padded owner password.
        /// </summary>
        internal void InitWithOwnerPassword(string userPassword, string ownerPassword, byte[] uValue, int rValue, bool encryptMetadata, byte[] ownerKeysalt, byte[] ownerEncryption, byte[] userKeysalt, byte[] userEncryption)
        {
            if (string.IsNullOrEmpty(ownerPassword))
            {
                ownerPassword = userPassword;
            }

            _encryptionKey = SetupOwnerKey(ownerPassword, ownerKeysalt, uValue, ownerEncryption, rValue);
            _ownerKey = _encryptionKey;
            _userKey = SetupUserKey(userPassword, userKeysalt, userEncryption, rValue);
        }

        /// <summary>
        /// Computes the padded user password from the padded owner password.
        /// </summary>
        internal byte[] SetupOwnerKey(string password, byte[] ownerKeySalt, byte[] uValue, byte[] ownerEncryption, int rValue)
        {
#if !NETFX_CORE
            //#if !SILVERLIGHT
            byte[] key;
            byte[] passwordBytes = PadPassword(password);

            _sha256.Initialize();
            _sha256.TransformBlock(passwordBytes, 0, password.Length, passwordBytes, 0);
            _sha256.TransformBlock(ownerKeySalt, 0, ownerKeySalt.Length, ownerKeySalt, 0);
            _sha256.TransformFinalBlock(uValue, 0, uValue.Length);

            if (rValue == 5)
            {
                key = _sha256.Hash;
            }
            else
            {
                key = ComputePDF20Hash(passwordBytes, _sha256.Hash, uValue);
            }

            byte[] userKey = new byte[ownerEncryption.Length];

            PrepareAESKey(key);
            PrepareAESIV(null);
            _aes.Padding = PaddingMode.None;
            DecryptAES(ownerEncryption, userKey);

            return userKey;
            //#endif
#endif
        }

        /// <summary>
        /// Computes the user key.
        /// </summary>
        internal byte[] SetupUserKey(string password, byte[] userKeySalt, byte[] userEncryption, int rValue)
        {
#if !NETFX_CORE
            //#if !SILVERLIGHT
            byte[] key;
            byte[] passwordBytes = PadPassword(password);

            _sha256.Initialize();
            _sha256.TransformBlock(passwordBytes, 0, password.Length, passwordBytes, 0);
            _sha256.TransformFinalBlock(userKeySalt, 0, userKeySalt.Length);

            if (rValue == 5)
            {
                key = _sha256.Hash;
            }
            else
            {
                key = ComputePDF20Hash(passwordBytes, _sha256.Hash, null);
            }

            byte[] userKey = new byte[userEncryption.Length];

            PrepareAESKey(key);
            PrepareAESIV(null);
            _aes.Padding = PaddingMode.None;
            DecryptAES(userEncryption, userKey);

            return userKey;
            //#endif
#endif
        }

        internal byte[] SetupPerms(int permissions, bool encryptMetadata, byte[] encryptionKey, byte[] randomData = null)
        {
            byte[] permission = new byte[16];
            permission[0] = (byte)(permissions);
            permission[1] = (byte)(permissions >> 8);
            permission[2] = (byte)(permissions >> 16);
            permission[3] = (byte)(permissions >> 24);
            permission[4] = 0xFF;
            permission[5] = 0xFF;
            permission[6] = 0xFF;
            permission[7] = 0xFF;
            permission[8] = (byte)(encryptMetadata ? 0x54 /* 'T' */ : 0x46 /* 'F' */);
            permission[9] = 97;     // 'a
            permission[10] = 100;   // 'd'
            permission[11] = 98;    // 'b'

            if (randomData == null)
            {
                randomData = new byte[4];

                RNGCryptoServiceProvider rngCsp = new RNGCryptoServiceProvider();
                rngCsp.GetBytes(randomData);
            }

            Array.Copy(randomData, 0, permission, 12, 4);

            PrepareAESKey(encryptionKey);
            PrepareAESIV(null);
            _aes.Padding = PaddingMode.None;

            EncryptAES(permission);

            return permission;
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
        internal void PrepareAESKey(byte[] key, int offset = 0, int length = 0, int keySize = 256)
        {
            if (length == 0)
            {
                length = key.Length;
            }

            _aes.Clear();
            _aes.BlockSize = 128;
            _aes.KeySize = keySize;
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
            _key = _encryptionKey;
            _keySize = _encryptionKey.Length;
        }

        /// <summary>
        /// Prepares the security handler for encrypting the document.
        /// </summary>
        public override void PrepareEncryption()
        {
            //#if !SILVERLIGHT
            Debug.Assert(_document._securitySettings.DocumentSecurityLevel != PdfDocumentSecurityLevel.None);
            int permissions = (int)Permission;

            PdfInteger vValue;
            PdfInteger length;
            PdfInteger rValue;

            vValue = new PdfInteger(5);
            length = new PdfInteger(256);
            rValue = new PdfInteger(5);

            if (string.IsNullOrEmpty(_userPassword))
                _userPassword = string.Empty;

            // Use user password twice if no owner password provided.
            if (string.IsNullOrEmpty(_ownerPassword))
            {
                _ownerPassword = _userPassword;
            }

            // Correct permission bits
            permissions |= unchecked((int)(0xfffff0c0));
            permissions &= unchecked((int)0xfffffffc);

            PdfInteger pValue = new PdfInteger(permissions);

            Debug.Assert(_ownerPassword.Length > 0, "Empty owner password.");
            byte[] userPad = PadPassword(_userPassword);
            byte[] ownerPad = PadPassword(_ownerPassword);

            _md5.Initialize();
            _ownerKey = SetupOwnerKey(_ownerPassword, new byte[] { }, new byte[] { }, new byte[] { }, vValue.Value);

            byte[] documentID = PdfEncoders.RawEncoding.GetBytes(_document.Internals.FirstDocumentID);

            bool isV4 = vValue.Value >= 4;
            rValue = new PdfInteger(5);
            InitWithUserPassword(_userPassword, vValue.Value, true, new byte[] { }, new byte[] { });

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
        readonly SHA256 _sha256 = new System.Security.Cryptography.SHA256Managed();

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
            /// (Required) A 32-byte string, based on both the owner and user passwords, that is
            /// used in computing the encryption key and in determining whether a valid owner
            /// password was entered.
            /// </summary>
            [KeyInfo(KeyType.String | KeyType.Required)]
            public const string OE = "/OE";

            /// <summary>
            /// (Required) A 32-byte string, based on the user password, that is used in determining
            /// whether to prompt the user for a password and, if so, whether a valid user or owner 
            /// password was entered.
            /// </summary>
            [KeyInfo(KeyType.String | KeyType.Required)]
            public const string UE = "/UE";

            /// <summary>
            /// (Required) A set of flags specifying which operations are permitted when the document
            /// is opened with user access.
            /// </summary>
            [KeyInfo(KeyType.Integer | KeyType.Required)]
            public const string P = "/P";

            /// <summary>
            /// (Required) A set of flags specifying which operations are permitted when the document
            /// is opened with user access.
            /// </summary>
            [KeyInfo(KeyType.String | KeyType.Required)]
            public const string Perms = "/Perms";

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
