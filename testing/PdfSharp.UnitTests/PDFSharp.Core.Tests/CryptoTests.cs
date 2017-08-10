﻿using NUnit.Framework;
using PdfSharp.Pdf;
using PdfSharp.Pdf.Security;

namespace PDFSharp.Core.Tests
{
    [TestFixture]
    public class CryptoTests
    {
        [Test(Description = "RC4 Crypto from AESV2SecurityHandler")]
        public void Test_RC4_AESV2SecurityHandler_1()
        {
            var aesV2Security = new PdfAESV2SecurityHandler(new PdfDictionary());

            var key = Hex2binary("0123456789abcdef");
            var input = Hex2binary("0123456789abcdef");
            byte[] result = new byte[input.Length];

            aesV2Security.PrepareRC4Key(key, length: key.Length);
            aesV2Security.EncryptRC4(input, result);

            var expected = Hex2binary("75b7878099e0c596");
            Assert.AreEqual(expected, result);

            aesV2Security.PrepareRC4Key(key, length: key.Length);
            aesV2Security.EncryptRC4(expected, result);

            Assert.AreEqual(input, result);

        }

        [Test(Description = "RC4 Crypto from AESV2SecurityHandler")]
        public void Test_RC4_AESV2SecurityHandler_2()
        {
            var aesV2Security = new PdfAESV2SecurityHandler(new PdfDictionary());

            var key = Hex2binary("0123456789abcdef");
            var input = Hex2binary("0000000000000000");
            byte[] result = new byte[input.Length];

            aesV2Security.PrepareRC4Key(key, length: key.Length);
            aesV2Security.EncryptRC4(input, result);

            var expected = Hex2binary("7494c2e7104b0879");
            Assert.AreEqual(expected, result);

            aesV2Security.PrepareRC4Key(key, length: key.Length);
            aesV2Security.EncryptRC4(expected, result);

            Assert.AreEqual(input, result);
        }

        [Test(Description = "RC4 Crypto from AESV2SecurityHandler")]
        public void Test_RC4_AESV2SecurityHandler_3()
        {
            var aesV2Security = new PdfAESV2SecurityHandler(new PdfDictionary());

            var key = Hex2binary("0000000000000000");
            var input = Hex2binary("0000000000000000");
            byte[] result = new byte[input.Length];

            aesV2Security.PrepareRC4Key(key, length: key.Length);
            aesV2Security.EncryptRC4(input, result);

            var expected = Hex2binary("de188941a3375d3a");
            Assert.AreEqual(expected, result);

            aesV2Security.PrepareRC4Key(key, length: key.Length);
            aesV2Security.EncryptRC4(expected, result);

            Assert.AreEqual(input, result);
        }

        [Test(Description = "RC4 Crypto from AESV2SecurityHandler")]
        public void Test_RC4_AESV2SecurityHandler_4()
        {
            var aesV2Security = new PdfAESV2SecurityHandler(new PdfDictionary());

            var key = Hex2binary("ef012345");
            var input = Hex2binary("00000000000000000000");
            byte[] result = new byte[input.Length];

            aesV2Security.PrepareRC4Key(key, length: key.Length);
            aesV2Security.EncryptRC4(input, result);

            var expected = Hex2binary("d6a141a7ec3c38dfbd61");
            Assert.AreEqual(expected, result);

            aesV2Security.PrepareRC4Key(key, length: key.Length);
            aesV2Security.EncryptRC4(expected, result);

            Assert.AreEqual(input, result);
        }

        [Test(Description = "RC4 Crypto from AESV2SecurityHandler")]
        public void Test_RC4_AESV2SecurityHandler_5()
        {
            var aesV2Security = new PdfAESV2SecurityHandler(new PdfDictionary());

            var key = Hex2binary("0123456789abcdef");
            var input = Hex2binary("010101010101010101010101010101010101010101010101010" +
                "10101010101010101010101010101010101010101010101010101010101010101010" +
                "10101010101010101010101010101010101010101010101010101010101010101010" +
                "10101010101010101010101010101010101010101010101010101010101010101010" +
                "10101010101010101010101010101010101010101010101010101010101010101010" +
                "10101010101010101010101010101010101010101010101010101010101010101010" +
                "10101010101010101010101010101010101010101010101010101010101010101010" +
                "10101010101010101010101010101010101010101010101010101010101010101010" +
                "10101010101010101010101010101010101010101010101010101010101010101010" +
                "10101010101010101010101010101010101010101010101010101010101010101010" +
                "10101010101010101010101010101010101010101010101010101010101010101010" +
                "10101010101010101010101010101010101010101010101010101010101010101010" +
                "10101010101010101010101010101010101010101010101010101010101010101010" +
                "10101010101010101010101010101010101010101010101010101010101010101010" +
                "10101010101010101010101010101010101010101010101010101010101010101010" +
                "101010101010101010101");
            byte[] result = new byte[input.Length];

            aesV2Security.PrepareRC4Key(key, length: key.Length);
            aesV2Security.EncryptRC4(input, result);

            var expected = Hex2binary("7595c3e6114a09780c4ad452338e1ffd9a1be9498f813d76" +
                "533449b6778dcad8c78a8d2ba9ac66085d0e53d59c26c2d1c490c1ebbe0ce66d1b6b" +
                "1b13b6b919b847c25a91447a95e75e4ef16779cde8bf0a95850e32af9689444fd377" +
                "108f98fdcbd4e726567500990bcc7e0ca3c4aaa304a387d20f3b8fbbcd42a1bd311d" +
                "7a4303dda5ab078896ae80c18b0af66dff319616eb784e495ad2ce90d7f772a81747" +
                "b65f62093b1e0db9e5ba532fafec47508323e671327df9444432cb7367cec82f5d44" +
                "c0d00b67d650a075cd4b70dedd77eb9b10231b6b5b741347396d62897421d43df9b4" +
                "2e446e358e9c11a9b2184ecbef0cd8e7a877ef968f1390ec9b3d35a5585cb009290e" +
                "2fcde7b5ec66d9084be44055a619d9dd7fc3166f9487f7cb272912426445998514c1" +
                "5d53a18c864ce3a2b7555793988126520eacf2e3066e230c91bee4dd5304f5fd0405" +
                "b35bd99c73135d3d9bc335ee049ef69b3867bf2d7bd1eaa595d8bfc0066ff8d31509" +
                "eb0c6caa006c807a623ef84c3d33c195d23ee320c40de0558157c822d4b8c569d849" +
                "aed59d4e0fd7f379586b4b7ff684ed6a189f7486d49b9c4bad9ba24b96abf924372c" +
                "8a8fffb10d55354900a77a3db5f205e1b99fcd8660863a159ad4abe40fa48934163d" +
                "dde542a6585540fd683cbfd8c00f12129a284deacc4cdefe58be7137541c047126c8" +
                "d49e2755ab181ab7e940b0c0");
            Assert.AreEqual(expected, result);

            aesV2Security.PrepareRC4Key(key, length: key.Length);
            aesV2Security.EncryptRC4(expected, result);

            Assert.AreEqual(input, result);
        }

        [Test(Description = "RC4 Crypto from AESV2SecurityHandler")]
        public void Test_RC4_AESV2SecurityHandler_6()
        {
            var aesV2Security = new PdfAESV2SecurityHandler(new PdfDictionary());

            var key = Hex2binary("fb029e3031323334");
            var input = Hex2binary("aaaa0300000008004500004e661a00008011be640a0001220a" +
                "ffffff00890089003a000080a601100001000000000000204543454a454845434643" +
                "4550464545494546464343414341434143414341414100002000011bd0b604");
            byte[] result = new byte[input.Length];

            aesV2Security.PrepareRC4Key(key, length: key.Length);
            aesV2Security.EncryptRC4(input, result);

            var expected = Hex2binary("f69c5806bd6ce84626bcbefb9474650aad1f7909b0f64d5" +
                "f58a503a258b7ed22eb0ea64930d3a056a55742fcce141d485f8aa836dea18df42c5" +
                "380805ad0c61a5d6f58f41040b24b7d1a693856ed0d4398e7aee3bf0e2a2ca8f7");
            Assert.AreEqual(expected, result);

            aesV2Security.PrepareRC4Key(key, length: key.Length);
            aesV2Security.EncryptRC4(expected, result);

            Assert.AreEqual(input, result);
        }

        [Test(Description = "RC4 Crypto from AESV2SecurityHandler")]
        public void Test_RC4_AESV2SecurityHandler_7()
        {
            var aesV2Security = new PdfAESV2SecurityHandler(new PdfDictionary());

            var key = Hex2binary("0123456789abcdef");
            var input = Hex2binary("123456789abcdef0123456789abcdef0123456789abcdef012345678");
            byte[] result = new byte[input.Length];

            aesV2Security.PrepareRC4Key(key, length: key.Length);
            aesV2Security.EncryptRC4(input, result);

            var expected = Hex2binary("66a0949f8af7d6891f7f832ba833c00c892ebe30143ce28740011ecf");
            Assert.AreEqual(expected, result);

            aesV2Security.PrepareRC4Key(key, length: key.Length);
            aesV2Security.EncryptRC4(expected, result);

            Assert.AreEqual(input, result);
        }

        [Test(Description = "RC4 Crypto from StandardSecurityHandler")]
        public void Test_RC4_StandardSecurityHandler_1()
        {
            var rc4Security = new PdfStandardSecurityHandler(new PdfDictionary());

            var key = Hex2binary("0123456789abcdef");
            var input = Hex2binary("0123456789abcdef");
            byte[] result = new byte[input.Length];

            rc4Security.PrepareRC4Key(key, length: key.Length);
            rc4Security.EncryptRC4(input, result);

            var expected = Hex2binary("75b7878099e0c596");
            Assert.AreEqual(expected, result);

            rc4Security.PrepareRC4Key(key, length: key.Length);
            rc4Security.EncryptRC4(expected, result);

            Assert.AreEqual(input, result);

        }

        [Test(Description = "RC4 Crypto from StandardSecurityHandler")]
        public void Test_RC4_StandardSecurityHandler_2()
        {
            var rc4Security = new PdfStandardSecurityHandler(new PdfDictionary());

            var key = Hex2binary("0123456789abcdef");
            var input = Hex2binary("0000000000000000");
            byte[] result = new byte[input.Length];

            rc4Security.PrepareRC4Key(key, length: key.Length);
            rc4Security.EncryptRC4(input, result);

            var expected = Hex2binary("7494c2e7104b0879");
            Assert.AreEqual(expected, result);

            rc4Security.PrepareRC4Key(key, length: key.Length);
            rc4Security.EncryptRC4(expected, result);

            Assert.AreEqual(input, result);
        }

        [Test(Description = "RC4 Crypto from StandardSecurityHandler")]
        public void Test_RC4_StandardSecurityHandler_3()
        {
            var rc4Security = new PdfStandardSecurityHandler(new PdfDictionary());

            var key = Hex2binary("0000000000000000");
            var input = Hex2binary("0000000000000000");
            byte[] result = new byte[input.Length];

            rc4Security.PrepareRC4Key(key, length: key.Length);
            rc4Security.EncryptRC4(input, result);

            var expected = Hex2binary("de188941a3375d3a");
            Assert.AreEqual(expected, result);

            rc4Security.PrepareRC4Key(key, length: key.Length);
            rc4Security.EncryptRC4(expected, result);

            Assert.AreEqual(input, result);
        }

        [Test(Description = "RC4 Crypto from StandardSecurityHandler")]
        public void Test_RC4_StandardSecurityHandler_4()
        {
            var rc4Security = new PdfStandardSecurityHandler(new PdfDictionary());

            var key = Hex2binary("ef012345");
            var input = Hex2binary("00000000000000000000");
            byte[] result = new byte[input.Length];

            rc4Security.PrepareRC4Key(key, length: key.Length);
            rc4Security.EncryptRC4(input, result);

            var expected = Hex2binary("d6a141a7ec3c38dfbd61");
            Assert.AreEqual(expected, result);

            rc4Security.PrepareRC4Key(key, length: key.Length);
            rc4Security.EncryptRC4(expected, result);

            Assert.AreEqual(input, result);
        }

        [Test(Description = "RC4 Crypto from StandardSecurityHandler")]
        public void Test_RC4_StandardSecurityHandler_5()
        {
            var rc4Security = new PdfStandardSecurityHandler(new PdfDictionary());

            var key = Hex2binary("0123456789abcdef");
            var input = Hex2binary("010101010101010101010101010101010101010101010101010" +
                "10101010101010101010101010101010101010101010101010101010101010101010" +
                "10101010101010101010101010101010101010101010101010101010101010101010" +
                "10101010101010101010101010101010101010101010101010101010101010101010" +
                "10101010101010101010101010101010101010101010101010101010101010101010" +
                "10101010101010101010101010101010101010101010101010101010101010101010" +
                "10101010101010101010101010101010101010101010101010101010101010101010" +
                "10101010101010101010101010101010101010101010101010101010101010101010" +
                "10101010101010101010101010101010101010101010101010101010101010101010" +
                "10101010101010101010101010101010101010101010101010101010101010101010" +
                "10101010101010101010101010101010101010101010101010101010101010101010" +
                "10101010101010101010101010101010101010101010101010101010101010101010" +
                "10101010101010101010101010101010101010101010101010101010101010101010" +
                "10101010101010101010101010101010101010101010101010101010101010101010" +
                "10101010101010101010101010101010101010101010101010101010101010101010" +
                "101010101010101010101");
            byte[] result = new byte[input.Length];

            rc4Security.PrepareRC4Key(key, length: key.Length);
            rc4Security.EncryptRC4(input, result);

            var expected = Hex2binary("7595c3e6114a09780c4ad452338e1ffd9a1be9498f813d76" +
                "533449b6778dcad8c78a8d2ba9ac66085d0e53d59c26c2d1c490c1ebbe0ce66d1b6b" +
                "1b13b6b919b847c25a91447a95e75e4ef16779cde8bf0a95850e32af9689444fd377" +
                "108f98fdcbd4e726567500990bcc7e0ca3c4aaa304a387d20f3b8fbbcd42a1bd311d" +
                "7a4303dda5ab078896ae80c18b0af66dff319616eb784e495ad2ce90d7f772a81747" +
                "b65f62093b1e0db9e5ba532fafec47508323e671327df9444432cb7367cec82f5d44" +
                "c0d00b67d650a075cd4b70dedd77eb9b10231b6b5b741347396d62897421d43df9b4" +
                "2e446e358e9c11a9b2184ecbef0cd8e7a877ef968f1390ec9b3d35a5585cb009290e" +
                "2fcde7b5ec66d9084be44055a619d9dd7fc3166f9487f7cb272912426445998514c1" +
                "5d53a18c864ce3a2b7555793988126520eacf2e3066e230c91bee4dd5304f5fd0405" +
                "b35bd99c73135d3d9bc335ee049ef69b3867bf2d7bd1eaa595d8bfc0066ff8d31509" +
                "eb0c6caa006c807a623ef84c3d33c195d23ee320c40de0558157c822d4b8c569d849" +
                "aed59d4e0fd7f379586b4b7ff684ed6a189f7486d49b9c4bad9ba24b96abf924372c" +
                "8a8fffb10d55354900a77a3db5f205e1b99fcd8660863a159ad4abe40fa48934163d" +
                "dde542a6585540fd683cbfd8c00f12129a284deacc4cdefe58be7137541c047126c8" +
                "d49e2755ab181ab7e940b0c0");
            Assert.AreEqual(expected, result);

            rc4Security.PrepareRC4Key(key, length: key.Length);
            rc4Security.EncryptRC4(expected, result);

            Assert.AreEqual(input, result);
        }

        [Test(Description = "RC4 Crypto from StandardSecurityHandler")]
        public void Test_RC4_StandardSecurityHandler_6()
        {
            var rc4Security = new PdfStandardSecurityHandler(new PdfDictionary());

            var key = Hex2binary("fb029e3031323334");
            var input = Hex2binary("aaaa0300000008004500004e661a00008011be640a0001220a" +
                "ffffff00890089003a000080a601100001000000000000204543454a454845434643" +
                "4550464545494546464343414341434143414341414100002000011bd0b604");
            byte[] result = new byte[input.Length];

            rc4Security.PrepareRC4Key(key, length: key.Length);
            rc4Security.EncryptRC4(input, result);

            var expected = Hex2binary("f69c5806bd6ce84626bcbefb9474650aad1f7909b0f64d5" +
                "f58a503a258b7ed22eb0ea64930d3a056a55742fcce141d485f8aa836dea18df42c5" +
                "380805ad0c61a5d6f58f41040b24b7d1a693856ed0d4398e7aee3bf0e2a2ca8f7");
            Assert.AreEqual(expected, result);

            rc4Security.PrepareRC4Key(key, length: key.Length);
            rc4Security.EncryptRC4(expected, result);

            Assert.AreEqual(input, result);
        }

        [Test(Description = "RC4 Crypto from StandardSecurityHandler")]
        public void Test_RC4_StandardSecurityHandler_7()
        {
            var rc4Security = new PdfStandardSecurityHandler(new PdfDictionary());

            var key = Hex2binary("0123456789abcdef");
            var input = Hex2binary("123456789abcdef0123456789abcdef0123456789abcdef012345678");
            byte[] result = new byte[input.Length];

            rc4Security.PrepareRC4Key(key, length: key.Length);
            rc4Security.EncryptRC4(input, result);

            var expected = Hex2binary("66a0949f8af7d6891f7f832ba833c00c892ebe30143ce28740011ecf");
            Assert.AreEqual(expected, result);

            rc4Security.PrepareRC4Key(key, length: key.Length);
            rc4Security.EncryptRC4(expected, result);

            Assert.AreEqual(input, result);
        }

        private byte[] Hex2binary(string value)
        {
            const string digits = "0123456789ABCDEF";

            value = value.ToUpper();
            int n = value.Length >> 1;
            var result = new byte[n];

            for (int destIndex = 0, sourceIndex = 0; destIndex < n; ++destIndex)
            {
                var d1 = value[sourceIndex++];
                var d2 = value[sourceIndex++];
                var byteValue = unchecked((byte)((digits.IndexOf(d1) << 4) | (digits.IndexOf(d2))));
                result[destIndex] = byteValue;
            }

            return result;
        }
    }
}
