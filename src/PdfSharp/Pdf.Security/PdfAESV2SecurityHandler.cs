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
                if ((int)permission == 0)
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
                    PrepareKey();
                    EncryptAES(bytes);
                    str.EncryptionValue = bytes;
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
                    PrepareKey();
                    EncryptAES(bytes);
                    dict.Stream.Value = bytes;
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
        /// Encrypts a string.
        /// </summary>
        void EncryptString(PdfString value)
        {
            if (value.Length != 0)
            {
                byte[] bytes = value.EncryptionValue;
                PrepareKey();
                EncryptAES(bytes);
                value.EncryptionValue = bytes;
            }
        }

        /// <summary>
        /// Encrypts an array.
        /// </summary>
        public override byte[] EncryptBytes(byte[] bytes)
        {
            if (bytes != null && bytes.Length != 0)
            {
                PrepareKey();
                EncryptAES(bytes);
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

            if (filter != Standard || v != 4)
                return false;

            if (filter == Standard && v == 4)
            {
                PdfDictionary cf = dict.Elements.GetDictionary(PdfSecurityHandler.Keys.CF);

                if (!cf.Elements.ContainsKey(PdfCryptoFilter.StdCF))
                    return false;

                PdfDictionary stdCF = cf.Elements.GetDictionary(PdfCryptoFilter.StdCF);
                string cfm = stdCF.Elements.GetName(PdfCryptoFilter.Keys.CFM);

                if (cfm != PdfCryptoFilter.AESV2)
                    return false;
            }

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
            bool isV4 = Elements.GetInteger(Keys.V) >= 4;
            bool encryptMetadata = isV4;

            if (Elements.ContainsKey(PdfCryptoFilter.Keys.EncryptMetadata))
                encryptMetadata = Elements.GetBoolean(PdfCryptoFilter.Keys.EncryptMetadata);

            if (inputPassword == null)
                inputPassword = "";

            bool strongEncryption = rValue == 3 || rValue == 4;
            int keyLength = strongEncryption ? 16 : 32;

            // Try owner password first.
            //byte[] password = PdfEncoders.RawEncoding.GetBytes(inputPassword);
            InitWithOwnerPassword(documentID, inputPassword, oValue, pValue, strongEncryption, isV4, encryptMetadata);

            if (EqualsKey(uValue, keyLength))
            {
                _document.SecuritySettings._hasOwnerPermissions = true;
                return PasswordValidity.OwnerPassword;
            }

            _document.SecuritySettings._hasOwnerPermissions = false;

            // Now try user password.
            //password = PdfEncoders.RawEncoding.GetBytes(inputPassword);
            InitWithUserPassword(documentID, inputPassword, oValue, pValue, strongEncryption, isV4, encryptMetadata);

            if (EqualsKey(uValue, keyLength))
                return PasswordValidity.UserPassword;

            return PasswordValidity.Invalid;
        }

        [Conditional("DEBUG")]
        static void DumpBytes(string tag, byte[] bytes)
        {
            string dump = tag + ": ";
            for (int idx = 0; idx < bytes.Length; idx++)
                dump += String.Format("{0:X2}", bytes[idx]);
            Debug.WriteLine(dump);
        }

        /// <summary>
        /// Pads a password to a 32 byte array.
        /// </summary>
        static byte[] PadPassword(string password)
        {
            byte[] padded = new byte[32];
            if (password == null)
                Array.Copy(PasswordPadding, 0, padded, 0, 32);
            else
            {
                int length = password.Length;
                Array.Copy(PdfEncoders.RawEncoding.GetBytes(password), 0, padded, 0, Math.Min(length, 32));
                if (length < 32)
                    Array.Copy(PasswordPadding, 0, padded, length, 32 - length);
            }
            return padded;
        }
        static readonly byte[] PasswordPadding = // 32 bytes password padding defined by Adobe
            {
              0x28, 0xBF, 0x4E, 0x5E, 0x4E, 0x75, 0x8A, 0x41, 0x64, 0x00, 0x4E, 0x56, 0xFF, 0xFA, 0x01, 0x08,
              0x2E, 0x2E, 0x00, 0xB6, 0xD0, 0x68, 0x3E, 0x80, 0x2F, 0x0C, 0xA9, 0xFE, 0x64, 0x53, 0x69, 0x7A
            };

        /// <summary>
        /// Generates the user key based on the padded user password.
        /// </summary>
        void InitWithUserPassword(byte[] documentID, string userPassword, byte[] ownerKey, int permissions, bool strongEncryption, bool isV4, bool encryptMetadata)
        {
            InitEncryptionKey(documentID, PadPassword(userPassword), ownerKey, permissions, strongEncryption, isV4, encryptMetadata);
            SetupUserKey(documentID);
        }

        /// <summary>
        /// Generates the user key based on the padded owner password.
        /// </summary>
        void InitWithOwnerPassword(byte[] documentID, string ownerPassword, byte[] ownerKey, int permissions, bool strongEncryption, bool isV4, bool encryptMetadata)
        {
            byte[] userPad = ComputeOwnerKey(ownerKey, PadPassword(ownerPassword), strongEncryption);
            InitEncryptionKey(documentID, userPad, ownerKey, permissions, strongEncryption, isV4, encryptMetadata);
            SetupUserKey(documentID);
        }

        /// <summary>
        /// Computes the padded user password from the padded owner password.
        /// </summary>
        byte[] ComputeOwnerKey(byte[] userPad, byte[] ownerPad, bool strongEncryption)
        {
            byte[] ownerKey = new byte[32];
            //#if !SILVERLIGHT
            byte[] digest = _md5.ComputeHash(ownerPad);
            if (strongEncryption)
            {
                byte[] mkey = new byte[16];
                // Hash the pad 50 times
                for (int idx = 0; idx < 50; idx++)
                    digest = _md5.ComputeHash(digest);
                Array.Copy(userPad, 0, ownerKey, 0, 32);
                // Encrypt the key
                for (int i = 0; i < 20; i++)
                {
                    for (int j = 0; j < mkey.Length; ++j)
                        mkey[j] = (byte)(digest[j] ^ i);
                    PrepareAESKey(mkey);
                    EncryptAES(ownerKey);
                }
            }
            else
            {
                PrepareAESKey(digest, 0, 16);
                EncryptAES(userPad, ownerKey);
            }
            //#endif
            return ownerKey;
        }

        /// <summary>
        /// Computes the encryption key.
        /// </summary>
        void InitEncryptionKey(byte[] documentID, byte[] userPad, byte[] ownerKey, int permissions, bool strongEncryption, bool isV4, bool encryptMetadata)
        {
            //#if !SILVERLIGHT
            _ownerKey = ownerKey;
            _encryptionKey = new byte[strongEncryption ? 16 : 5];

#if !NETFX_CORE
            _md5.Initialize();
            _md5.TransformBlock(userPad, 0, userPad.Length, userPad, 0);
            _md5.TransformBlock(ownerKey, 0, ownerKey.Length, ownerKey, 0);

            // Split permission into 4 bytes
            byte[] permission = new byte[4];
            permission[0] = (byte)permissions;
            permission[1] = (byte)(permissions >> 8);
            permission[2] = (byte)(permissions >> 16);
            permission[3] = (byte)(permissions >> 24);
            _md5.TransformBlock(permission, 0, 4, permission, 0);
            _md5.TransformBlock(documentID, 0, documentID.Length, documentID, 0);

            if (isV4 && !encryptMetadata)
            {
                byte[] values = { 0xFF, 0xFF, 0xFF, 0xFF };
                _md5.TransformBlock(values, 0, 4, values, 0);
            }

            _md5.TransformFinalBlock(permission, 0, 0);
            byte[] digest = _md5.Hash;
            _md5.Initialize();

            // Create the hash 50 times (only for 128 bit)
            if (_encryptionKey.Length == 16)
            {
                for (int idx = 0; idx < 50; idx++)
                {
                    digest = _md5.ComputeHash(digest);
                    _md5.Initialize();
                }
            }
            Array.Copy(digest, 0, _encryptionKey, 0, _encryptionKey.Length);
            //#endif
#endif
        }

        /// <summary>
        /// Computes the user key.
        /// </summary>
        void SetupUserKey(byte[] documentID)
        {
#if !NETFX_CORE
            //#if !SILVERLIGHT
            if (_encryptionKey.Length == 16)
            {
                _md5.TransformBlock(PasswordPadding, 0, PasswordPadding.Length, PasswordPadding, 0);
                _md5.TransformFinalBlock(documentID, 0, documentID.Length);
                byte[] digest = _md5.Hash;
                _md5.Initialize();
                Array.Copy(digest, 0, _userKey, 0, 16);
                for (int idx = 16; idx < 32; idx++)
                    _userKey[idx] = 0;
                //Encrypt the key
                for (int i = 0; i < 20; i++)
                {
                    for (int j = 0; j < _encryptionKey.Length; j++)
                        digest[j] = (byte)(_encryptionKey[j] ^ i);
                    PrepareAESKey(digest, 0, _encryptionKey.Length);
                    EncryptAES(_userKey, 0, 16);
                }
            }
            else
            {
                PrepareAESKey(_encryptionKey);
                EncryptAES(PasswordPadding, _userKey);
            }
            //#endif
#endif
        }

        /// <summary>
        /// Prepare the encryption key.
        /// </summary>
        void PrepareKey()
        {
            PrepareAESKey(_key, 0, _keySize);
        }

        /// <summary>
        /// Prepare the encryption key.
        /// </summary>
        void PrepareAESKey(byte[] key)
        {
            PrepareAESKey(key, 0, key.Length);
        }

        /// <summary>
        /// Prepare the encryption key.
        /// </summary>
        void PrepareAESKey(byte[] key, int offset, int length)
        {
            AESManaged.KeyParameter param = new AESManaged.KeyParameter(key, offset, length);
            _aes.Init(true, param);
        }

        /// <summary>
        /// Encrypts the data.
        /// </summary>
        // ReSharper disable InconsistentNaming
        void EncryptAES(byte[] data)
        // ReSharper restore InconsistentNaming
        {
            EncryptAES(data, 0, data.Length, data);
        }

        /// <summary>
        /// Encrypts the data.
        /// </summary>
        // ReSharper disable InconsistentNaming
        void EncryptAES(byte[] data, int offset, int length)
        // ReSharper restore InconsistentNaming
        {
            EncryptAES(data, offset, length, data);
        }

        /// <summary>
        /// Encrypts the data.
        /// </summary>
        void EncryptAES(byte[] inputData, byte[] outputData)
        {
            EncryptAES(inputData, 0, inputData.Length, outputData);
        }

        /// <summary>
        /// Encrypts the data.
        /// </summary>
        void EncryptAES(byte[] inputData, int offset, int length, byte[] outputData)
        {
            length += offset;
            byte padding = unchecked((byte)(length % 16));
            bool needsPadding = padding != 0;

            byte[] data = new byte[length + padding];
            Array.Copy(inputData, offset, data, 0, length);

            for (int idx = 0; idx < padding; idx++)
                data[length + idx] = padding;

            for (int idx = 0; idx < data.Length; idx += 16)
                _aes.ProcessBlock(data, idx, outputData, offset + idx);
        }

        /// <summary>
        /// Checks whether the calculated key correct.
        /// </summary>
        bool EqualsKey(byte[] value, int length)
        {
            for (int idx = 0; idx < length; idx++)
            {
                if (_userKey[idx] != value[idx])
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

            byte[] encryptionKeyWithSalt = new byte[_encryptionKey.Length + 4];
            Array.Copy(_encryptionKey, 0, encryptionKeyWithSalt, 0, _encryptionKey.Length);
            Array.Copy(KeySalt, 0, encryptionKeyWithSalt, _encryptionKey.Length, KeySalt.Length);

            _md5.TransformBlock(encryptionKeyWithSalt, 0, encryptionKeyWithSalt.Length, encryptionKeyWithSalt, 0);
            _md5.TransformFinalBlock(objectId, 0, objectId.Length);
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
            bool strongEncryption = _document._securitySettings.DocumentSecurityLevel == PdfDocumentSecurityLevel.Encrypted128Bit;

            PdfInteger vValue;
            PdfInteger length;
            PdfInteger rValue;

            if (strongEncryption)
            {
                vValue = new PdfInteger(2);
                length = new PdfInteger(128);
                rValue = new PdfInteger(3);
            }
            else
            {
                vValue = new PdfInteger(1);
                length = new PdfInteger(40);
                rValue = new PdfInteger(2);
            }

            if (String.IsNullOrEmpty(_userPassword))
                _userPassword = "";
            // Use user password twice if no owner password provided.
            if (String.IsNullOrEmpty(_ownerPassword))
                _ownerPassword = _userPassword;

            // Correct permission bits
            permissions |= (int)(strongEncryption ? (uint)0xfffff0c0 : (uint)0xffffffc0);
            permissions &= unchecked((int)0xfffffffc);

            PdfInteger pValue = new PdfInteger(permissions);

            Debug.Assert(_ownerPassword.Length > 0, "Empty owner password.");
            byte[] userPad = PadPassword(_userPassword);
            byte[] ownerPad = PadPassword(_ownerPassword);

            _md5.Initialize();
            _ownerKey = ComputeOwnerKey(userPad, ownerPad, strongEncryption);
            byte[] documentID = PdfEncoders.RawEncoding.GetBytes(_document.Internals.FirstDocumentID);

            bool isV4 = vValue.Value >= 4;
            InitWithUserPassword(documentID, _userPassword, _ownerKey, permissions, strongEncryption, isV4, true);

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
        byte[] _encryptionKey;

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

        readonly AESManaged _aes = new AESManaged();

        /// <summary>
        /// The encryption key for the owner.
        /// </summary>
        byte[] _ownerKey = new byte[32];

        /// <summary>
        /// The encryption key for the user.
        /// </summary>
        readonly byte[] _userKey = new byte[32];

        /// <summary>
        /// The encryption key for a particular object/generation.
        /// </summary>
        byte[] _key;

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
