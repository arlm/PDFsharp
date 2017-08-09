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
                    _document._securitySettings.DocumentSecurityLevel = PdfDocumentSecurityLevel.Encrypted128Bit;
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
                    _document._securitySettings.DocumentSecurityLevel = PdfDocumentSecurityLevel.Encrypted128Bit;
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
        public override void DecryptDocument()
        {
            foreach (PdfReference iref in _document._irefTable.AllReferences)
            {
                if (!ReferenceEquals(iref.Value, this))
                    DecryptObject(iref.Value);
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
        internal void DecryptObject(PdfObject value)
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
                DecryptDictionary(dict);
            else if ((array = value as PdfArray) != null)
                DecryptArray(array);
            else if ((str = value as PdfStringObject) != null)
            {
                if (str.Length != 0)
                {
                    byte[] bytes = str.EncryptionValue;
                    PrepareAESKey();
                    PrepareAESIV(bytes, 0, 16);
                    int length = DecryptAES(bytes, 16, bytes.Length - 16);

                    byte[] temp = new byte[length];
                    Array.Copy(bytes, temp, length);

                    str.EncryptionValue = temp;
                }
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
                    DecryptString(value1);
                else if ((value2 = item.Value as PdfDictionary) != null)
                    DecryptDictionary(value2);
                else if ((value3 = item.Value as PdfArray) != null)
                    DecryptArray(value3);
            }
            if (dict.Stream != null)
            {
                byte[] bytes = dict.Stream.Value;
                if (bytes.Length != 0)
                {
                    PrepareAESKey();
                    PrepareAESIV(bytes, 0, 16);
                    int length = DecryptAES(bytes, 16, bytes.Length - 16);

                    byte[] temp = new byte[length];
                    Array.Copy(bytes, temp, length);

                    dict.Stream.Value = temp;
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
                byte[] bytes = value.EncryptionValue;
                PrepareAESKey();
                PrepareAESIV(bytes, 0, 16);
                int length = DecryptAES(bytes, 16, bytes.Length - 16);

                byte[] temp = new byte[length];
                Array.Copy(bytes, temp, length);

                value.EncryptionValue = temp;
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
                int length = DecryptAES(bytes, 16, bytes.Length - 16);

                byte[] temp = new byte[length];
                Array.Copy(bytes, temp, length);

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
            InitWithOwnerPassword(documentID, inputPassword, inputPassword, ownerData, uValue, pValue, isV4, rValue, _encryptMetadata, ownerKeySalt, oeValue, userKeySalt, ueValue);

            PasswordValidity result = CheckOwnerPassword(inputPassword, ownerValidationSalt, uValue, oValue, rValue);
            _document.SecuritySettings._hasOwnerPermissions = result == PasswordValidity.OwnerPassword;

            if (result == PasswordValidity.OwnerPassword)
            {
                return result;
            }

            // Now try user password.
            //password = PdfEncoders.RawEncoding.GetBytes(inputPassword);
            InitWithUserPassword(documentID, inputPassword, ownerData, pValue, isV4, rValue, _encryptMetadata, userKeySalt, ueValue);

            return CheckUserPassword(inputPassword, userValidationSalt, uValue, rValue);
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

                result = ComputePDF20Hash(passwordBytes, _sha256.Hash, new byte[] { });
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
                _sha256.TransformFinalBlock(uValue, 0, uValue.Length);

                result = _sha256.Hash;
            }
            else
            {
                _sha256.TransformBlock(passwordBytes, 0, passwordBytes.Length, passwordBytes, 0);
                _sha256.TransformBlock(ownerValidationSalt, 0, ownerValidationSalt.Length, ownerValidationSalt, 0);
                _sha256.TransformFinalBlock(uValue, 0, uValue.Length);

                result = ComputePDF20Hash(passwordBytes, _sha256.Hash, uValue);
            }

            if (EqualsKey(oValue, result, 32))
            {
                return PasswordValidity.OwnerPassword;
            }

            return PasswordValidity.Invalid;
        }

        private byte[] ComputePDF20Hash(byte[] passwordBytes, byte[] input, byte[] userBytes)
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
            int i = 0;

            while (i < 64 || e[e.Length - 1] > (i - 32))
            {
                int arrayLength = passwordBytes.Length + k.Length + userBytes.Length;
                byte[] k1 = new byte[arrayLength * 64];
                byte[] array = new byte[arrayLength];

                Array.Copy(passwordBytes, 0, array, 0, passwordBytes.Length);
                Array.Copy(k, 0, array, passwordBytes.Length, k.Length);
                Array.Copy(userBytes, 0, array, passwordBytes.Length + k.Length, userBytes.Length);

                for (int index = 0, pos = 0; index < 64; index++, pos += arrayLength)
                {
                    Array.Copy(array, 0, k1, pos, array.Length);
                }

                byte[] iv = new byte[16];
                byte[] key = new byte[16];

                Array.Copy(k, 0, key, 0, 16);
                Array.Copy(k, 16, iv, 0, 16);

                PrepareAESKey(key, keySize: 128);
                PrepareAESIV(iv);
                _aes.Padding = PaddingMode.None;

                e = new byte[k1.Length];
                EncryptAES(k1, e);

                int remainder = 0;

                for (int index = 0; index < 16; index++)
                {
                    remainder *= (256 % 3);
                    remainder %= 3;
                    remainder += ((e[index] >> 0) % 3);
                    remainder %= 3;
                }

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

                i++;
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
        internal void InitWithUserPassword(byte[] documentID, string userPassword, byte[] oValue, int permissions, bool isV4, int rValue, bool encryptMetadata, byte[] userKeysalt, byte[] userEncryption)
        {
            _encryptionKey = SetupUserKey(userPassword, userKeysalt, userEncryption, rValue);
            _userKey = _encryptionKey;
        }

        /// <summary>
        /// Generates the user key based on the padded owner password.
        /// </summary>
        internal void InitWithOwnerPassword(byte[] documentID, string userPassword, string ownerPassword, byte[] oValue, byte[] uValue, int permissions, bool isV4, int rValue, bool encryptMetadata, byte[] ownerKeysalt, byte[] ownerEncryption, byte[] userKeysalt, byte[] userEncryption)
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
                key = ComputePDF20Hash(passwordBytes, _sha256.Hash, new byte[] { });
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
                _keySize = 16;
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
            InitWithUserPassword(documentID, _userPassword, _ownerKey, permissions, isV4, vValue.Value, true, new byte[] { }, new byte[] { });

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
