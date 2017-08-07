using NUnit.Framework;
using PdfSharp.Pdf;
using PdfSharp.Pdf.Advanced;
using PdfSharp.Pdf.Internal;
using PdfSharp.Pdf.IO;
using PdfSharp.Pdf.Security;

namespace PDFSharp.Core.Tests
{
    [TestFixture]
    public class SecurityTests
    {
        [Test(Description = "PDF 1.4 Algorithm check")]
        public void PDF_14_CheckUserPassword()
        {
            var rc4Security = new PdfStandardSecurityHandler(new PdfDictionary());

            var userKey = new byte[] { 156, 169, 16, 184, 203, 151, 249, 67, 114, 149, 31, 121, 193, 243, 191, 50,
                                                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
            var uValue = new byte[] { 156, 169, 16, 184, 203, 151, 249, 67, 114, 149, 31, 121, 193, 243, 191,
                                            50, 40, 191, 78, 94, 78, 117, 138, 65, 100, 0, 78, 86, 255, 250, 1, 8 };

            var result = rc4Security.CheckUserPassword(userKey, uValue);
            Assert.AreEqual(PasswordValidity.UserPassword, result);
        }

        [Test(Description = "PDF 1.4 Algorithm check")]
        public void PDF_14_CheckOwnerPassword_40bit_Process()
        {
            var rc4Security = new PdfStandardSecurityHandler(new PdfDictionary());

            var ownerKey = new byte[] { 242, 192, 84, 134, 99 };
            var userKey = new byte[] { 41, 66, 196, 174, 54 };

            var oValue = PdfEncoders.RawEncoding.GetBytes("\u00dc\u00f0\u00ab\u00bb\u00d5\u00c5\u00eb\u008deL\u00b64\u00ea\u0019\u009f\u0085(z\u00f9\u0000\u0017\u00c9\u001b\u00f3\u00aa\u00b2\u000c@\u00a3\u00a7T\u00ba");
            var uValue = PdfEncoders.RawEncoding.GetBytes("lH\u00a2\u00b1\u00eb\u00dd\u008b\u00e0\u0090\u00a8\u0006\u00f7\u00bfi\u00e9\u00c9\u000d\u001c\u008e\u00b3\u0017\u00f0K\u0087\u009c\u00ac'\u000a\u0016\u009a\u00db\u00e4");
            var documentID = PdfEncoders.RawEncoding.GetBytes("\u001bH*zY\u0016\u00ea\u001fOI\u0088\u0019\u0094'x\u0015");
            var permissions = -3904;

            var encryptionKey = rc4Security.CreateEncryptionKey(documentID, string.Empty, oValue, permissions, false, 5, false, false);
            Assert.AreEqual(userKey, encryptionKey);

            var calculatedUValue = rc4Security.SetupUserKey(documentID, encryptionKey, false, 5);
            Assert.IsTrue(rc4Security.EqualsKey(uValue, calculatedUValue, 16));

            var result = rc4Security.CheckUserPassword(calculatedUValue, uValue);
            Assert.AreEqual(PasswordValidity.UserPassword, result);

            var calculatedOwnerKey = rc4Security.SetupOwnerKey("password", false, 5);
            Assert.AreEqual(ownerKey, calculatedOwnerKey);

            var calculatedOValue = rc4Security.CreateOwnerKey(ownerKey, string.Empty, false, 5);
            Assert.AreEqual(oValue, calculatedOValue);

            result = rc4Security.CheckOwnerPassword(documentID, permissions, ownerKey, oValue, uValue, false, 5, false, false);
            Assert.AreEqual(PasswordValidity.OwnerPassword, result);
        }

        [Test(Description = "PDF 1.4 Algorithm check")]
        public void PDF_14_CheckOwnerPassword_56bit_Process()
        {
            var rc4Security = new PdfStandardSecurityHandler(new PdfDictionary());

            var ownerKey = new byte[] { 30, 130, 22, 12, 228, 22, 112 };
            var userKey = new byte[] { 36, 129, 94, 55, 65, 25, 46 };

            var oValue = PdfEncoders.RawEncoding.GetBytes("\u00e4\u00f7\u00049\u0010\u00bf\u00c6R\u00c4\u0085tX\u00f9\u00ae\u001er\u00f3soS\u000a\u00e6b\u00955\u00af\u00c4\u008cB\u00f7\u00b7q");
            var uValue = PdfEncoders.RawEncoding.GetBytes("\u0083\u00ae\u00ab~\u00ef\u0013\u00e5\u0014\u0001\u0009\u00e2+\u0001\u0008\u005cp(\u00bfN^Nu\u008aAd\u0000NV\u00ff\u00fa\u0001\u0008");
            var documentID = PdfEncoders.RawEncoding.GetBytes("\u00c4H\u0019\u0000\u00a0KiN\u0022(,~\u001fv\u0005u");
            var permissions = -3904;

            var encryptionKey = rc4Security.CreateEncryptionKey(documentID, string.Empty, oValue, permissions, true, 7, false, false);
            Assert.AreEqual(userKey, encryptionKey);

            var calculatedUValue = rc4Security.SetupUserKey(documentID, encryptionKey, true, 7);
            Assert.IsTrue(rc4Security.EqualsKey(uValue, calculatedUValue, 16));

            var result = rc4Security.CheckUserPassword(calculatedUValue, uValue);
            Assert.AreEqual(PasswordValidity.UserPassword, result);

            var calculatedOwnerKey = rc4Security.SetupOwnerKey("password", true, 7);
            Assert.AreEqual(ownerKey, calculatedOwnerKey);

            var calculatedOValue = rc4Security.CreateOwnerKey(ownerKey, string.Empty, true, 7);
            Assert.AreEqual(oValue, calculatedOValue);

            result = rc4Security.CheckOwnerPassword(documentID, permissions, ownerKey, oValue, uValue, true, 7, false, false);
            Assert.AreEqual(PasswordValidity.OwnerPassword, result);
        }

        [Test(Description = "PDF 1.4 Algorithm check")]
        public void PDF_14_CheckOwnerPassword_64bit_Process()
        {
            var rc4Security = new PdfStandardSecurityHandler(new PdfDictionary());

            var ownerKey = new byte[] { 163, 195, 217, 27, 116, 59, 218, 93 };
            var userKey = new byte[] { 231, 99, 140, 9, 170, 16, 162, 156 };

            var oValue = PdfEncoders.RawEncoding.GetBytes("\u00ea\u0013\u00c1*V\u0090 \u0022\u0013\u00c5\u008d\u00fb\u00ce\u00cb3+\u00a9h\u0083\u00f9\u0010\u00c8\u000ahsSU|\u00c1on\u0007");
            var uValue = PdfEncoders.RawEncoding.GetBytes("\u00f5C\u008f\u00c7\u00dbX\u00bc\u00860A\u00cb\u0085\u008e\u00bal\u00f2(\u00bfN^Nu\u008aAd\u0000NV\u00ff\u00fa\u0001\u0008");
            var documentID = PdfEncoders.RawEncoding.GetBytes("\u0094~\u00ac\u0001\u00fa6\u00bc0#6\u00dbN\u001cG\u0092\u001f");
            var permissions = -3904;

            var encryptionKey = rc4Security.CreateEncryptionKey(documentID, string.Empty, oValue, permissions, true, 8, false, false);
            Assert.AreEqual(userKey, encryptionKey);

            var calculatedUValue = rc4Security.SetupUserKey(documentID, encryptionKey, true, 8);
            Assert.IsTrue(rc4Security.EqualsKey(uValue, calculatedUValue, 16));

            var result = rc4Security.CheckUserPassword(calculatedUValue, uValue);
            Assert.AreEqual(PasswordValidity.UserPassword, result);

            var calculatedOwnerKey = rc4Security.SetupOwnerKey("password", true, 8);
            Assert.AreEqual(ownerKey, calculatedOwnerKey);

            var calculatedOValue = rc4Security.CreateOwnerKey(ownerKey, string.Empty, true, 8);
            Assert.AreEqual(oValue, calculatedOValue);

            result = rc4Security.CheckOwnerPassword(documentID, permissions, ownerKey, oValue, uValue, true, 8, false, false);
            Assert.AreEqual(PasswordValidity.OwnerPassword, result);
        }

        [Test(Description = "PDF 1.4 Algorithm check")]
        public void PDF_14_CheckOwnerPassword_96bit_Process()
        {
            var rc4Security = new PdfStandardSecurityHandler(new PdfDictionary());

            var ownerKey = new byte[] { 33, 109, 180, 138, 186, 142, 27, 241, 171, 199, 229, 133 };
            var userKey = new byte[] { 141, 160, 211, 102, 187, 180, 126, 12, 99, 151, 217, 76 };

            var oValue = PdfEncoders.RawEncoding.GetBytes("U\u00ee@\u0009/c\u00b5\u0085fs\u0007qLw\u0010}\u008ej\u00fc\u000f\u009ds(\u00e3\u001d\u00b0\u00be\u008f\u00fee\u00af\u00bd");
            var uValue = PdfEncoders.RawEncoding.GetBytes("\u00fb\u0011\u0000k\u001e\u00e0\u0093pa\u00d3\u0012\u00d4~\u00a2\u00ff\u0096(\u00bfN^Nu\u008aAd\u0000NV\u00ff\u00fa\u0001\u0008");
            var documentID = PdfEncoders.RawEncoding.GetBytes("C'jP\u00a0\u0010oq_-hV\u00f5\u001c\u00c8;");
            var permissions = -3904;

            var encryptionKey = rc4Security.CreateEncryptionKey(documentID, string.Empty, oValue, permissions, true, 12, false, false);
            Assert.AreEqual(userKey, encryptionKey);

            var calculatedUValue = rc4Security.SetupUserKey(documentID, encryptionKey, true, 12);
            Assert.IsTrue(rc4Security.EqualsKey(uValue, calculatedUValue, 16));

            var result = rc4Security.CheckUserPassword(calculatedUValue, uValue);
            Assert.AreEqual(PasswordValidity.UserPassword, result);

            var calculatedOwnerKey = rc4Security.SetupOwnerKey("password", true, 12);
            Assert.AreEqual(ownerKey, calculatedOwnerKey);

            var calculatedOValue = rc4Security.CreateOwnerKey(ownerKey, string.Empty, true, 12);
            Assert.AreEqual(oValue, calculatedOValue);

            result = rc4Security.CheckOwnerPassword(documentID, permissions, ownerKey, oValue, uValue, true, 12, false, false);
            Assert.AreEqual(PasswordValidity.OwnerPassword, result);
        }

        [Test(Description = "PDF 1.4 Algorithm check")]
        public void PDF_14_CheckOwnerPassword_128bit_Process()
        {
            var rc4Security = new PdfStandardSecurityHandler(new PdfDictionary());

            var ownerKey = new byte[] { 109, 165, 6, 202, 207, 33, 85, 47, 95, 147, 0, 4, 175, 57, 198, 125 };
            var userKey = new byte[] { 84, 6, 141, 18, 152, 222, 190, 171, 146, 103, 17, 146, 128, 12, 85, 196 };

            var oValue = PdfEncoders.RawEncoding.GetBytes("\u0018U\u000a\u0091\u00c87PV\u009bM\u0084\u0007\u008d\u0094\u001a3H\u0017/>\u00fbZ)\u00c59\u00c6\u00c7\u00de\u00e1\u00dd0\u008f");
            var uValue = PdfEncoders.RawEncoding.GetBytes("\u009c\u00a9\u0010\u00b8\u00cb\u0097\u00f9Cr\u0095\u001fy\u00c1\u00f3\u00bf2(\u00bfN^Nu\u008aAd\u0000NV\u00ff\u00fa\u0001\u0008");
            var documentID = PdfEncoders.RawEncoding.GetBytes("\u00beG\u000dZ\u00881\u000e\u0018\u0008\u0015)f\u0087M].");
            var permissions = -3904;

            var encryptionKey = rc4Security.CreateEncryptionKey(documentID, string.Empty, oValue, permissions, true, 16, false, false);
            Assert.AreEqual(userKey, encryptionKey);

            var calculatedUValue = rc4Security.SetupUserKey(documentID, encryptionKey, true, 16);
            Assert.IsTrue(rc4Security.EqualsKey(uValue, calculatedUValue, 16));

            var result = rc4Security.CheckUserPassword(calculatedUValue, uValue);
            Assert.AreEqual(PasswordValidity.UserPassword, result);

            var calculatedOwnerKey = rc4Security.SetupOwnerKey("password", true, 16);
            Assert.AreEqual(ownerKey, calculatedOwnerKey);

            var calculatedOValue = rc4Security.CreateOwnerKey(ownerKey, string.Empty, true, 16);
            Assert.AreEqual(oValue, calculatedOValue);

            result = rc4Security.CheckOwnerPassword(documentID, permissions, ownerKey, oValue, uValue, true, 16, false, false);
            Assert.AreEqual(PasswordValidity.OwnerPassword, result);
        }

        [Test(Description = "PDF 1.4 Algorithm check")]
        public void PDF_14_CheckOwnerPassword_40bit()
        {
            var rc4Security = new PdfStandardSecurityHandler(new PdfDictionary());

            var ownerKey = new byte[] { 242, 192, 84, 134, 99 };

            var oValue = PdfEncoders.RawEncoding.GetBytes("\u00dc\u00f0\u00ab\u00bb\u00d5\u00c5\u00eb\u008deL\u00b64\u00ea\u0019\u009f\u0085(z\u00f9\u0000\u0017\u00c9\u001b\u00f3\u00aa\u00b2\u000c@\u00a3\u00a7T\u00ba");
            var uValue = PdfEncoders.RawEncoding.GetBytes("lH\u00a2\u00b1\u00eb\u00dd\u008b\u00e0\u0090\u00a8\u0006\u00f7\u00bfi\u00e9\u00c9\u000d\u001c\u008e\u00b3\u0017\u00f0K\u0087\u009c\u00ac'\u000a\u0016\u009a\u00db\u00e4");
            var documentID = PdfEncoders.RawEncoding.GetBytes("\u001bH*zY\u0016\u00ea\u001fOI\u0088\u0019\u0094'x\u0015");
            var permissions = -3904;

            var result = rc4Security.CheckOwnerPassword(documentID, permissions, ownerKey, oValue, uValue, false, 5, false, false);
            Assert.AreEqual(PasswordValidity.OwnerPassword, result);
        }

        [Test(Description = "PDF 1.4 Algorithm check")]
        public void PDF_14_CheckOwnerPassword_56bit()
        {
            var rc4Security = new PdfStandardSecurityHandler(new PdfDictionary());

            var ownerKey = new byte[] { 30, 130, 22, 12, 228, 22, 112 };

            var oValue = PdfEncoders.RawEncoding.GetBytes("\u00e4\u00f7\u00049\u0010\u00bf\u00c6R\u00c4\u0085tX\u00f9\u00ae\u001er\u00f3soS\u000a\u00e6b\u00955\u00af\u00c4\u008cB\u00f7\u00b7q");
            var uValue = PdfEncoders.RawEncoding.GetBytes("\u0083\u00ae\u00ab~\u00ef\u0013\u00e5\u0014\u0001\u0009\u00e2+\u0001\u0008\u005cp(\u00bfN^Nu\u008aAd\u0000NV\u00ff\u00fa\u0001\u0008");
            var documentID = PdfEncoders.RawEncoding.GetBytes("\u00c4H\u0019\u0000\u00a0KiN\u0022(,~\u001fv\u0005u");
            var permissions = -3904;

            var result = rc4Security.CheckOwnerPassword(documentID, permissions, ownerKey, oValue, uValue, true, 7, false, false);
            Assert.AreEqual(PasswordValidity.OwnerPassword, result);
        }

        [Test(Description = "PDF 1.4 Algorithm check")]
        public void PDF_14_CheckOwnerPassword_64bit()
        {
            var rc4Security = new PdfStandardSecurityHandler(new PdfDictionary());

            var ownerKey = new byte[] { 163, 195, 217, 27, 116, 59, 218, 93 };

            var oValue = PdfEncoders.RawEncoding.GetBytes("\u00ea\u0013\u00c1*V\u0090 \u0022\u0013\u00c5\u008d\u00fb\u00ce\u00cb3+\u00a9h\u0083\u00f9\u0010\u00c8\u000ahsSU|\u00c1on\u0007");
            var uValue = PdfEncoders.RawEncoding.GetBytes("\u00f5C\u008f\u00c7\u00dbX\u00bc\u00860A\u00cb\u0085\u008e\u00bal\u00f2(\u00bfN^Nu\u008aAd\u0000NV\u00ff\u00fa\u0001\u0008");
            var documentID = PdfEncoders.RawEncoding.GetBytes("\u0094~\u00ac\u0001\u00fa6\u00bc0#6\u00dbN\u001cG\u0092\u001f");
            var permissions = -3904;

            var result = rc4Security.CheckOwnerPassword(documentID, permissions, ownerKey, oValue, uValue, true, 8, false, false);
            Assert.AreEqual(PasswordValidity.OwnerPassword, result);
        }

        [Test(Description = "PDF 1.4 Algorithm check")]
        public void PDF_14_CheckOwnerPassword_96bit()
        {
            var rc4Security = new PdfStandardSecurityHandler(new PdfDictionary());

            var ownerKey = new byte[] { 33, 109, 180, 138, 186, 142, 27, 241, 171, 199, 229, 133 };

            var oValue = PdfEncoders.RawEncoding.GetBytes("U\u00ee@\u0009/c\u00b5\u0085fs\u0007qLw\u0010}\u008ej\u00fc\u000f\u009ds(\u00e3\u001d\u00b0\u00be\u008f\u00fee\u00af\u00bd");
            var uValue = PdfEncoders.RawEncoding.GetBytes("\u00fb\u0011\u0000k\u001e\u00e0\u0093pa\u00d3\u0012\u00d4~\u00a2\u00ff\u0096(\u00bfN^Nu\u008aAd\u0000NV\u00ff\u00fa\u0001\u0008");
            var documentID = PdfEncoders.RawEncoding.GetBytes("C'jP\u00a0\u0010oq_-hV\u00f5\u001c\u00c8;");
            var permissions = -3904;

            var result = rc4Security.CheckOwnerPassword(documentID, permissions, ownerKey, oValue, uValue, true, 12, false, false);
            Assert.AreEqual(PasswordValidity.OwnerPassword, result);
        }

        [Test(Description = "PDF 1.4 Algorithm check")]
        public void PDF_14_CheckOwnerPassword_128bit()
        {
            var rc4Security = new PdfStandardSecurityHandler(new PdfDictionary());

            var ownerKey = new byte[] { 109, 165, 6, 202, 207, 33, 85, 47, 95, 147, 0, 4, 175, 57, 198, 125 };

            var oValue = PdfEncoders.RawEncoding.GetBytes("\u0018U\u000a\u0091\u00c87PV\u009bM\u0084\u0007\u008d\u0094\u001a3H\u0017/>\u00fbZ)\u00c59\u00c6\u00c7\u00de\u00e1\u00dd0\u008f");
            var uValue = PdfEncoders.RawEncoding.GetBytes("\u009c\u00a9\u0010\u00b8\u00cb\u0097\u00f9Cr\u0095\u001fy\u00c1\u00f3\u00bf2(\u00bfN^Nu\u008aAd\u0000NV\u00ff\u00fa\u0001\u0008");
            var documentID = PdfEncoders.RawEncoding.GetBytes("\u00beG\u000dZ\u00881\u000e\u0018\u0008\u0015)f\u0087M].");
            var permissions = -3904;

            var result = rc4Security.CheckOwnerPassword(documentID, permissions, ownerKey, oValue, uValue, true, 16, false, false);
            Assert.AreEqual(PasswordValidity.OwnerPassword, result);
        }

        [Test(Description = "PDF 1.4 Algorithm check")]
        public void PDF_14_SetupUserPassword_40bit()
        {
            var rc4Security = new PdfStandardSecurityHandler(new PdfDictionary());
            var documentID = PdfEncoders.RawEncoding.GetBytes("\u001bH*zY\u0016\u00ea\u001fOI\u0088\u0019\u0094'x\u0015");

            var encryptionKey = new byte[] { 41, 66, 196, 174, 54 };

            var result = rc4Security.SetupUserKey(documentID, encryptionKey, false, 5);

            var expected = new byte[] { 108, 72, 162, 177, 235, 221, 139, 224, 144, 168, 6, 247, 191, 105, 233,
                                        201, 13, 28, 142, 179, 23, 240, 75, 135, 156, 172, 39, 10, 22, 154, 219, 228 };

            Assert.IsTrue(rc4Security.EqualsKey(expected, result, 16));
        }

        [Test(Description = "PDF 1.4 Algorithm check")]
        public void PDF_14_SetupUserPassword_56bit()
        {
            var rc4Security = new PdfStandardSecurityHandler(new PdfDictionary());

            var documentID = PdfEncoders.RawEncoding.GetBytes("\u00c4H\u0019\u0000\u00a0KiN\u0022(,~\u001fv\u0005u");

            var encryptionKey = new byte[] { 36, 129, 94, 55, 65, 25, 46 };

            var result = rc4Security.SetupUserKey(documentID, encryptionKey, true, 7);

            var expected = new byte[] { 131, 174, 171, 126, 239, 19, 229, 20, 1, 9, 226, 43, 1, 8, 92, 112,
                                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

            Assert.IsTrue(rc4Security.EqualsKey(expected, result, 16));
        }

        [Test(Description = "PDF 1.4 Algorithm check")]
        public void PDF_14_SetupUserPassword_64bit()
        {
            var rc4Security = new PdfStandardSecurityHandler(new PdfDictionary());

            var documentID = PdfEncoders.RawEncoding.GetBytes("\u0094~\u00ac\u0001\u00fa6\u00bc0#6\u00dbN\u001cG\u0092\u001f");

            var encryptionKey = new byte[] { 231, 99, 140, 9, 170, 16, 162, 156 };

            var result = rc4Security.SetupUserKey(documentID, encryptionKey, true, 8);

            var expected = new byte[] { 245, 67, 143, 199, 219, 88, 188, 134, 48, 65, 203, 133, 142, 186, 108, 242,
                                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

            Assert.IsTrue(rc4Security.EqualsKey(expected, result, 16));
        }

        [Test(Description = "PDF 1.4 Algorithm check")]
        public void PDF_14_SetupUserPassword_96bit()
        {
            var rc4Security = new PdfStandardSecurityHandler(new PdfDictionary());

            var documentID = PdfEncoders.RawEncoding.GetBytes("C'jP\u00a0\u0010oq_-hV\u00f5\u001c\u00c8;");

            var encryptionKey = new byte[] { 141, 160, 211, 102, 187, 180, 126, 12, 99, 151, 217, 76 };

            var result = rc4Security.SetupUserKey(documentID, encryptionKey, true, 12);

            var expected = new byte[] { 251, 17, 0, 107, 30, 224, 147, 112, 97, 211, 18, 212, 126, 162, 255, 150,
                                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, };

            Assert.IsTrue(rc4Security.EqualsKey(expected, result, 16));
        }

        [Test(Description = "PDF 1.4 Algorithm check")]
        public void PDF_14_SetupUserPassword_128bit()
        {
            var rc4Security = new PdfStandardSecurityHandler(new PdfDictionary());

            var documentID = PdfEncoders.RawEncoding.GetBytes("\u00beG\u000dZ\u00881\u000e\u0018\u0008\u0015)f\u0087M].");

            var encryptionKey = new byte[] { 81, 158, 10, 93, 109, 117, 128, 11, 192, 164, 171, 222, 124, 167, 123, 11 };

            var result = rc4Security.SetupUserKey(documentID, encryptionKey, true, 16);

            var expected = new byte[] { 68, 196, 212, 0, 20, 25, 10, 3, 1, 111, 236, 220, 198, 78, 113, 108,
                                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

            Assert.IsTrue(rc4Security.EqualsKey(expected, result, 16));
        }

        [Test(Description = "PDF 1.4 Algorithm check")]
        public void PDF_14_SetupOwnerPassword_40bit()
        {
            var rc4Security = new PdfStandardSecurityHandler(new PdfDictionary());

            var result = rc4Security.SetupOwnerKey("password", false, 5);

            var expected = new byte[] { 242, 192, 84, 134, 99 };

            Assert.AreEqual(expected, result);
        }

        [Test(Description = "PDF 1.4 Algorithm check")]
        public void PDF_14_SetupOwnerPassword_56bit()
        {
            var rc4Security = new PdfStandardSecurityHandler(new PdfDictionary());

            var result = rc4Security.SetupOwnerKey("password", true, 7);

            var expected = new byte[] { 30, 130, 22, 12, 228, 22, 112 };

            Assert.AreEqual(expected, result);
        }

        [Test(Description = "PDF 1.4 Algorithm check")]
        public void PDF_14_SetupOwnerPassword_64bit()
        {
            var rc4Security = new PdfStandardSecurityHandler(new PdfDictionary());

            var result = rc4Security.SetupOwnerKey("password", true, 8);

            var expected = new byte[] { 163, 195, 217, 27, 116, 59, 218, 93 };

            Assert.AreEqual(expected, result);
        }


        [Test(Description = "PDF 1.4 Algorithm check")]
        public void PDF_14_SetupOwnerPassword_96bit()
        {
            var rc4Security = new PdfStandardSecurityHandler(new PdfDictionary());

            var result = rc4Security.SetupOwnerKey("password", true, 12);

            var expected = new byte[] { 33, 109, 180, 138, 186, 142, 27, 241, 171, 199, 229, 133 };

            Assert.AreEqual(expected, result);
        }

        [Test(Description = "PDF 1.4 Algorithm check")]
        public void PDF_14_SetupOwnerPassword_128bit()
        {
            var rc4Security = new PdfStandardSecurityHandler(new PdfDictionary());

            var result = rc4Security.SetupOwnerKey("password", true, 16);

            var expected = new byte[] { 109, 165, 6, 202, 207, 33, 85, 47, 95, 147, 0, 4, 175, 57, 198, 125 };

            Assert.AreEqual(expected, result);
        }

        [Test(Description = "PDF 1.4 Algorithm check")]
        public void PDF_14_CreateEncryptionKey_40bit()
        {
            var rc4Security = new PdfStandardSecurityHandler(new PdfDictionary());

            var oValue = PdfEncoders.RawEncoding.GetBytes("\u00dc\u00f0\u00ab\u00bb\u00d5\u00c5\u00eb\u008deL\u00b64\u00ea\u0019\u009f\u0085(z\u00f9\u0000\u0017\u00c9\u001b\u00f3\u00aa\u00b2\u000c@\u00a3\u00a7T\u00ba");
            var documentID = PdfEncoders.RawEncoding.GetBytes("\u001bH*zY\u0016\u00ea\u001fOI\u0088\u0019\u0094'x\u0015");
            int permissions = -3904;

            var result = rc4Security.CreateEncryptionKey(documentID, string.Empty, oValue, permissions, false, 5, false, false);

            var expected = new byte[] { 41, 66, 196, 174, 54 };

            Assert.AreEqual(expected, result);
        }

        [Test(Description = "PDF 1.4 Algorithm check")]
        public void PDF_14_CreateEncryptionKey_56bit()
        {
            var rc4Security = new PdfStandardSecurityHandler(new PdfDictionary());

            var oValue = PdfEncoders.RawEncoding.GetBytes("\u00e4\u00f7\u00049\u0010\u00bf\u00c6R\u00c4\u0085tX\u00f9\u00ae\u001er\u00f3soS\u000a\u00e6b\u00955\u00af\u00c4\u008cB\u00f7\u00b7q");
            var documentID = PdfEncoders.RawEncoding.GetBytes("\u00c4H\u0019\u0000\u00a0KiN\u0022(,~\u001fv\u0005u");
            int permissions = -3904;

            var result = rc4Security.CreateEncryptionKey(documentID, string.Empty, oValue, permissions, true, 7, false, false);

            var expected = new byte[] { 36, 129, 94, 55, 65, 25, 46 };

            Assert.AreEqual(expected, result);
        }

        [Test(Description = "PDF 1.4 Algorithm check")]
        public void PDF_14_CreateEncryptionKey_64bit()
        {
            var rc4Security = new PdfStandardSecurityHandler(new PdfDictionary());

            var oValue = PdfEncoders.RawEncoding.GetBytes("\u00ea\u0013\u00c1*V\u0090 \u0022\u0013\u00c5\u008d\u00fb\u00ce\u00cb3+\u00a9h\u0083\u00f9\u0010\u00c8\u000ahsSU|\u00c1on\u0007");
            var documentID = PdfEncoders.RawEncoding.GetBytes("\u0094~\u00ac\u0001\u00fa6\u00bc0#6\u00dbN\u001cG\u0092\u001f");
            int permissions = -3904;

            var result = rc4Security.CreateEncryptionKey(documentID, string.Empty, oValue, permissions, true, 8, false, false);

            var expected = new byte[] { 231, 99, 140, 9, 170, 16, 162, 156 };

            Assert.AreEqual(expected, result);
        }

        [Test(Description = "PDF 1.4 Algorithm check")]
        public void PDF_14_CreateEncryptionKey_96bit()
        {
            var rc4Security = new PdfStandardSecurityHandler(new PdfDictionary());

            var oValue = PdfEncoders.RawEncoding.GetBytes("U\u00ee@\u0009/c\u00b5\u0085fs\u0007qLw\u0010}\u008ej\u00fc\u000f\u009ds(\u00e3\u001d\u00b0\u00be\u008f\u00fee\u00af\u00bd");
            var documentID = PdfEncoders.RawEncoding.GetBytes("C'jP\u00a0\u0010oq_-hV\u00f5\u001c\u00c8;");
            int permissions = -3904;

            var result = rc4Security.CreateEncryptionKey(documentID, string.Empty, oValue, permissions, true, 12, false, false);

            var expected = new byte[] { 141, 160, 211, 102, 187, 180, 126, 12, 99, 151, 217, 76 };

            Assert.AreEqual(expected, result);
        }

        [Test(Description = "PDF 1.4 Algorithm check")]
        public void PDF_14_CreateEncryptionKey_128bit()
        {
            var rc4Security = new PdfStandardSecurityHandler(new PdfDictionary());

            var oValue = PdfEncoders.RawEncoding.GetBytes("\u0018U\u000a\u0091\u00c87PV\u009bM\u0084\u0007\u008d\u0094\u001a3H\u0017/>\u00fbZ)\u00c59\u00c6\u00c7\u00de\u00e1\u00dd0\u008f");
            var documentID = PdfEncoders.RawEncoding.GetBytes("\u00beG\u000dZ\u00881\u000e\u0018\u0008\u0015)f\u0087M].");
            int permissions = -3904;

            var result = rc4Security.CreateEncryptionKey(documentID, string.Empty, oValue, permissions, true, 16, false, false);

            var expected = new byte[] { 84, 6, 141, 18, 152, 222, 190, 171, 146, 103, 17, 146, 128, 12, 85, 196 };

            Assert.AreEqual(expected, result);
        }

        [Test(Description = "PDF 1.5 Algorithm check")]
        public void PDF_15_CheckUserPassword()
        {
            var aesV2Security = new PdfAESV2SecurityHandler(new PdfDictionary());

            var userKey = new byte[] { 117, 176, 67, 198, 246, 191, 213, 197, 95, 170, 0, 248, 184, 132, 2, 68, 117, 169, 4, 32, 159, 101, 22, 220, 243, 118, 71, 153, 128, 17, 101, 62 };

            var uValue = PdfEncoders.RawEncoding.GetBytes("u\u00b0C\u00c6\u00f6\u00bf\u00d5\u00c5_\u00aa\u0000\u00f8\u00b8\u0084\u0002D\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000");

            var result = aesV2Security.CheckUserPassword(userKey, uValue);
            Assert.AreEqual(PasswordValidity.UserPassword, result);
        }

        [Test(Description = "PDF 1.5 Algorithm check")]
        public void PDF_15_CheckOwnerPassword()
        {
            var aesV2Security = new PdfAESV2SecurityHandler(new PdfDictionary());
            var rc4Security = new PdfStandardSecurityHandler(new PdfDictionary());

            var ownerKey = new byte[] { 109, 165, 6, 202, 207, 33, 85, 47, 95, 147, 0, 4, 175, 57, 198, 125 };

            var documentID = PdfEncoders.RawEncoding.GetBytes("\u003c\u004c\u005f\u003a\u0044\u0096\u00af\u0040\u009a\u009d\u00b3\u003c\u0078\u001c\u0076\u00ac");
            var oValue = PdfEncoders.RawEncoding.GetBytes("\u0073\u0046\u0014\u0076\u002e\u0079\u0035\u0027\u00db\u0097\u000a\u0035\u0022\u00b3\u00e1\u00d4\u00ad\u00bd\u009b\u003c\u00b4\u00a5\u0089\u0075\u0015\u00b2\u0059\u00f1\u0068\u00d9\u00e9\u00f4");
            var uValue = PdfEncoders.RawEncoding.GetBytes("\u0093\u0004\u0089\u00a9\u00bf\u008a\u0045\u00a6\u0088\u00a2\u00db\u00c2\u00a0\u00a8\u0067\u006e\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000");
            int permissions = 0x0000F0C0;

            var result = aesV2Security.CheckOwnerPassword(documentID, permissions, ownerKey, oValue, uValue, true);
            var result2 = rc4Security.CheckOwnerPassword(documentID, permissions, ownerKey, oValue, uValue, true, 16, true, true);

            Assert.AreEqual(result2, result);
            Assert.AreEqual(PasswordValidity.OwnerPassword, result);
        }

        [Test(Description = "PDF 1.5 Algorithm check")]
        public void PDF_15_SetupUserPassword()
        {
            var aesV2Security = new PdfAESV2SecurityHandler(new PdfDictionary());
            var rc4Security = new PdfStandardSecurityHandler(new PdfDictionary());

            var documentID = PdfEncoders.RawEncoding.GetBytes("\u003c\u004c\u005f\u003a\u0044\u0096\u00af\u0040\u009a\u009d\u00b3\u003c\u0078\u001c\u0076\u00ac");
            var encryptionKey = new byte[] { 254, 177, 210, 93, 233, 27, 134, 187, 10, 149, 235, 67, 213, 167, 243, 65 };

            var result = aesV2Security.SetupUserKey(documentID, encryptionKey);
            var result2 = rc4Security.SetupUserKey(documentID, encryptionKey, true, 16);

            Assert.AreEqual(result2, result);

            var expected = new byte[] { 147, 4, 137, 169, 191, 138, 69, 166, 136, 162, 219, 194, 160, 168, 103, 110,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

            Assert.AreEqual(expected, result);
        }

        [Test(Description = "PDF 1.5 Algorithm check")]
        public void PDF_15_CheckOwnerPassword_Process()
        {
            var aesV2Security = new PdfAESV2SecurityHandler(new PdfDictionary());

            var ownerKey = new byte[] { 109, 165, 6, 202, 207, 33, 85, 47, 95, 147, 0, 4, 175, 57, 198, 125 };
            var userKey = new byte[] { 254, 177, 210, 93, 233, 27, 134, 187, 10, 149, 235, 67, 213, 167, 243, 65 };

            var documentID = PdfEncoders.RawEncoding.GetBytes("\u003c\u004c\u005f\u003a\u0044\u0096\u00af\u0040\u009a\u009d\u00b3\u003c\u0078\u001c\u0076\u00ac");
            var oValue = PdfEncoders.RawEncoding.GetBytes("\u0073\u0046\u0014\u0076\u002e\u0079\u0035\u0027\u00db\u0097\u000a\u0035\u0022\u00b3\u00e1\u00d4\u00ad\u00bd\u009b\u003c\u00b4\u00a5\u0089\u0075\u0015\u00b2\u0059\u00f1\u0068\u00d9\u00e9\u00f4");
            var uValue = PdfEncoders.RawEncoding.GetBytes("\u0093\u0004\u0089\u00a9\u00bf\u008a\u0045\u00a6\u0088\u00a2\u00db\u00c2\u00a0\u00a8\u0067\u006e\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000");
            var permissions = 0x0000F0C0;

            var encryptionKey = aesV2Security.CreateEncryptionKey(documentID, string.Empty, oValue, permissions, true);
            Assert.AreEqual(userKey, encryptionKey);

            var calculatedUValue = aesV2Security.SetupUserKey(documentID, encryptionKey);
            Assert.IsTrue(aesV2Security.EqualsKey(uValue, calculatedUValue, 16));

            var result = aesV2Security.CheckUserPassword(calculatedUValue, uValue);
            Assert.AreEqual(PasswordValidity.UserPassword, result);

            var calculatedOwnerKey = aesV2Security.SetupOwnerKey("password");
            Assert.AreEqual(ownerKey, calculatedOwnerKey);

            var calculatedOValue = aesV2Security.CreateOwnerKey(ownerKey, string.Empty);
            Assert.AreEqual(oValue, calculatedOValue);

            result = aesV2Security.CheckOwnerPassword(documentID, permissions, ownerKey, oValue, uValue, true);
            Assert.AreEqual(PasswordValidity.OwnerPassword, result);
        }

        [Test(Description = "PDF 1.5 Algorithm check")]
        public void PDF_15_SetupOwnerPassword()
        {
            var aesV2Security = new PdfAESV2SecurityHandler(new PdfDictionary());
            var rc4Security = new PdfStandardSecurityHandler(new PdfDictionary());

            var result = aesV2Security.SetupOwnerKey("password");
            var result2 = rc4Security.SetupOwnerKey("password", true, 16);

            Assert.AreEqual(result2, result);

            var expected = new byte[] { 109, 165, 6, 202, 207, 33, 85, 47, 95, 147, 0, 4, 175, 57, 198, 125 };

            Assert.AreEqual(expected, result);
        }

        [Test(Description = "PDF 1.5 Algorithm check")]
        public void PDF_15_CreateEncryptionKey()
        {
            var aesV2Security = new PdfAESV2SecurityHandler(new PdfDictionary());
            var rc4Security = new PdfStandardSecurityHandler(new PdfDictionary());

            var documentID = PdfEncoders.RawEncoding.GetBytes("\u003c\u004c\u005f\u003a\u0044\u0096\u00af\u0040\u009a\u009d\u00b3\u003c\u0078\u001c\u0076\u00ac");
            var oValue = PdfEncoders.RawEncoding.GetBytes("\u0073\u0046\u0014\u0076\u002e\u0079\u0035\u0027\u00db\u0097\u000a\u0035\u0022\u00b3\u00e1\u00d4\u00ad\u00bd\u009b\u003c\u00b4\u00a5\u0089\u0075\u0015\u00b2\u0059\u00f1\u0068\u00d9\u00e9\u00f4");
            var permissions = 61632;

            var result = aesV2Security.CreateEncryptionKey(documentID, string.Empty, oValue, permissions, true);
            var result2 = rc4Security.CreateEncryptionKey(documentID, string.Empty, oValue, permissions, true, 16, true, true);

            Assert.AreEqual(result2, result);

            var expected = new byte[] { 254, 177, 210, 93, 233, 27, 134, 187, 10, 149, 235, 67, 213, 167, 243, 65 };

            Assert.AreEqual(expected, result);
        }

        [Test(Description = "PDF 1.7 Algorithm check")]
        public void PDF_17_CheckUserPassword_Process()
        {
            var aes256Security = new PdfAESV3SecurityHandler(new PdfDictionary());

            var userValidation = new byte[] { 117, 169, 4, 32, 159, 101, 22, 220 };
            var userSalt = new byte[] { 168, 94, 215, 192, 100, 38, 188, 40 };
            var uValue = new byte[] { 131, 242, 143, 160, 87, 2, 138, 134, 79,
                                           253, 189, 173, 224, 73, 144, 241, 190, 81,
                                           197, 15, 249, 105, 145, 151, 15, 194, 65,
                                           3, 1, 126, 187, 221 };
            var ueValue = new byte[] { 35, 150, 195, 169, 245, 51, 51, 255,
                                       158, 158, 33, 242, 231, 75, 125, 190,
                                       25, 126, 172, 114, 195, 244, 137, 245,
                                       234, 165, 42, 74, 60, 38, 17, 17 };

            var userKey = aes256Security.SetupUserKey("user", userSalt, ueValue, 5);

            var expected = new byte[] { 63, 114, 136, 209, 87, 61, 12, 30, 249, 1,
                                 186, 144, 254, 248, 163, 153, 151, 51, 133,
                                 10, 80, 152, 206, 15, 72, 187, 231, 33, 224,
                                 239, 13, 213 };

            Assert.AreEqual(expected, userKey);

            var result = aes256Security.CheckUserPassword("user", userValidation, uValue, 5);
            Assert.AreEqual(PasswordValidity.UserPassword, result);
        }

        [Test(Description = "PDF 1.7 Algorithm check")]
        public void PDF_17_CheckUserPassword()
        {
            var aes256Security = new PdfAESV3SecurityHandler(new PdfDictionary());

            var userValidation = new byte[] { 117, 169, 4, 32, 159, 101, 22, 220 };
            var uValue = new byte[] { 131, 242, 143, 160, 87, 2, 138, 134, 79,
                                           253, 189, 173, 224, 73, 144, 241, 190, 81,
                                           197, 15, 249, 105, 145, 151, 15, 194, 65,
                                           3, 1, 126, 187, 221 };

            var result = aes256Security.CheckUserPassword("user", userValidation, uValue, 5);
            Assert.AreEqual(PasswordValidity.UserPassword, result);
        }

        [Test(Description = "PDF 1.7 Algorithm check")]
        public void PDF_17_CheckOwnerPassword_Process()
        {
            var aes256Security = new PdfAESV3SecurityHandler(new PdfDictionary());

            var ownerValidation = new byte[] { 243, 118, 71, 153, 128, 17, 101, 62 };
            var ownerSalt = new byte[] { 200, 245, 242, 12, 218, 123, 24, 120 };
            var oeValue = new byte[] { 213, 202, 14, 189, 110, 76, 70, 191, 6,
                                        195, 10, 190, 157, 100, 144, 85, 8, 62,
                                        123, 178, 156, 229, 50, 40, 229, 216,
                                        54, 222, 34, 38, 106, 223 };
            var oValue = new byte[] { 60, 98, 137, 35, 51, 101, 200, 152, 210,
                                            178, 226, 228, 134, 205, 163, 24, 204,
                                            126, 177, 36, 106, 50, 36, 125, 210, 172,
                                            171, 120, 222, 108, 139, 115 };
            var uValue = new byte[] { 131, 242, 143, 160, 87, 2, 138, 134, 79, 253,
                                     189, 173, 224, 73, 144, 241, 190, 81, 197, 15,
                                     249, 105, 145, 151, 15, 194, 65, 3, 1, 126, 187,
                                     221, 117, 169, 4, 32, 159, 101, 22, 220, 168,
                                     94, 215, 192, 100, 38, 188, 40 };

            var ownerKey = aes256Security.SetupOwnerKey("owner", ownerSalt, uValue, oeValue, 5);

            var expected = new byte[] { 63, 114, 136, 209, 87, 61, 12, 30, 249, 1,
                                 186, 144, 254, 248, 163, 153, 151, 51, 133,
                                 10, 80, 152, 206, 15, 72, 187, 231, 33, 224,
                                 239, 13, 213 };

            Assert.AreEqual(expected, ownerKey);

            var result = aes256Security.CheckOwnerPassword("owner", ownerValidation, uValue, oValue, 5);
            Assert.AreEqual(PasswordValidity.OwnerPassword, result);
        }

        [Test(Description = "PDF 1.7 Algorithm check")]
        public void PDF_17_CheckOwnerPassword()
        {
            var aes256Security = new PdfAESV3SecurityHandler(new PdfDictionary());

            var ownerValidation = new byte[] { 243, 118, 71, 153, 128, 17, 101, 62 };
            var oValue = new byte[] { 60, 98, 137, 35, 51, 101, 200, 152, 210,
                                            178, 226, 228, 134, 205, 163, 24, 204,
                                            126, 177, 36, 106, 50, 36, 125, 210, 172,
                                            171, 120, 222, 108, 139, 115 };
            var uValue = new byte[] { 131, 242, 143, 160, 87, 2, 138, 134, 79, 253,
                                     189, 173, 224, 73, 144, 241, 190, 81, 197, 15,
                                     249, 105, 145, 151, 15, 194, 65, 3, 1, 126, 187,
                                     221, 117, 169, 4, 32, 159, 101, 22, 220, 168,
                                     94, 215, 192, 100, 38, 188, 40 };

            var result = aes256Security.CheckOwnerPassword("owner", ownerValidation, uValue, oValue, 5);
            Assert.AreEqual(PasswordValidity.OwnerPassword, result);
        }

        [Test(Description = "PDF 1.7 Algorithm check")]
        public void PDF_17_SetupUserPassword()
        {
            var aes256Security = new PdfAESV3SecurityHandler(new PdfDictionary());

            var userSalt = new byte[] { 168, 94, 215, 192, 100, 38, 188, 40 };
            var ueValue = new byte[] { 35, 150, 195, 169, 245, 51, 51, 255,
                                       158, 158, 33, 242, 231, 75, 125, 190,
                                       25, 126, 172, 114, 195, 244, 137, 245,
                                       234, 165, 42, 74, 60, 38, 17, 17 };

            var result = aes256Security.SetupUserKey("user", userSalt, ueValue, 5);

            var expected = new byte[] { 63, 114, 136, 209, 87, 61, 12, 30, 249, 1,
                                 186, 144, 254, 248, 163, 153, 151, 51, 133,
                                 10, 80, 152, 206, 15, 72, 187, 231, 33, 224,
                                 239, 13, 213 };

            Assert.AreEqual(expected, result);
        }

        [Test(Description = "PDF 1.7 Algorithm check")]
        public void PDF_17_SetupOwnerPassword()
        {
            var aes256Security = new PdfAESV3SecurityHandler(new PdfDictionary());

            var ownerSalt = new byte[] { 200, 245, 242, 12, 218, 123, 24, 120 };
            var oeValue = new byte[] { 213, 202, 14, 189, 110, 76, 70, 191, 6,
                                        195, 10, 190, 157, 100, 144, 85, 8, 62,
                                        123, 178, 156, 229, 50, 40, 229, 216,
                                        54, 222, 34, 38, 106, 223 };
            var uValue = new byte[] { 131, 242, 143, 160, 87, 2, 138, 134, 79, 253,
                               189, 173, 224, 73, 144, 241, 190, 81, 197, 15,
                               249, 105, 145, 151, 15, 194, 65, 3, 1, 126, 187,
                               221, 117, 169, 4, 32, 159, 101, 22, 220, 168,
                               94, 215, 192, 100, 38, 188, 40 };

            var result = aes256Security.SetupOwnerKey("owner", ownerSalt, uValue, oeValue, 5);

            var expected = new byte[] { 63, 114, 136, 209, 87, 61, 12, 30, 249, 1,
                                 186, 144, 254, 248, 163, 153, 151, 51, 133,
                                 10, 80, 152, 206, 15, 72, 187, 231, 33, 224,
                                 239, 13, 213 };

            Assert.AreEqual(expected, result);
        }

        [Test(Description = "PDF 2.0 Algorithm check")]
        public void PDF_20_CheckUserPassword()
        {
            var aes256Security = new PdfAESV3SecurityHandler(new PdfDictionary());

            var userValidation = new byte[] { 83, 245, 146, 101, 198, 247, 34, 198 };
            var uValue = new byte[] { 94, 230, 205, 75, 166, 99, 250, 76, 219,
                                     128, 17, 85, 57, 17, 33, 164, 150, 46,
                                     103, 176, 160, 156, 187, 233, 166, 223,
                                     163, 253, 147, 235, 95, 184 };

            var result = aes256Security.CheckUserPassword("user", userValidation, uValue, 6);
            Assert.AreEqual(PasswordValidity.UserPassword, result);
        }

        [Test(Description = "PDF 2.0 Algorithm check")]
        public void PDF_20_CheckOwnerPassword()
        {
            var aes256Security = new PdfAESV3SecurityHandler(new PdfDictionary());

            var ownerValidation = new byte[] { 142, 232, 169, 208, 202, 214, 5, 185 };
            var oValue = new byte[] { 88, 232, 62, 54, 245, 26, 245, 209, 137,
                                      123, 221, 72, 199, 49, 37, 217, 31, 74,
                                      115, 167, 127, 158, 176, 77, 45, 163, 87,
                                      47, 39, 90, 217, 141 };
            var uValue = new byte[] { 94, 230, 205, 75, 166, 99, 250, 76, 219, 128,
                               17, 85, 57, 17, 33, 164, 150, 46, 103, 176, 160,
                               156, 187, 233, 166, 223, 163, 253, 147, 235, 95,
                               184, 83, 245, 146, 101, 198, 247, 34, 198, 191,
                               11, 16, 94, 237, 216, 20, 175 };

            var result = aes256Security.CheckOwnerPassword("owner", ownerValidation, uValue, oValue, 6);
            Assert.AreEqual(PasswordValidity.OwnerPassword, result);
        }

        [Test(Description = "PDF 2.0 Algorithm check")]
        public void PDF_20_SetupUserPassword()
        {
            var aes256Security = new PdfAESV3SecurityHandler(new PdfDictionary());

            var userKeySalt = new byte[] { 191, 11, 16, 94, 237, 216, 20, 175 };
            var userEncryption = new byte[] { 121, 208, 2, 181, 230, 89, 156, 60, 253,
                                       143, 212, 28, 84, 180, 196, 177, 173,
                                       128, 221, 107, 46, 20, 94, 186, 135, 51,
                                       95, 24, 20, 223, 254, 36 };

            var result = aes256Security.SetupUserKey("user", userKeySalt, userEncryption, 6);

            var expected = new byte[] { 42, 218, 213, 39, 73, 91, 72, 79, 67, 38, 248,
                                 133, 18, 189, 61, 34, 107, 79, 29, 56, 59,
                                 181, 213, 118, 113, 34, 65, 210, 87, 174, 22,
                                 239 };

            Assert.AreEqual(expected, result);
        }

        [Test(Description = "PDF 2.0 Algorithm check")]
        public void PDF_20_SetupOwnerPassword()
        {
            var aes256Security = new PdfAESV3SecurityHandler(new PdfDictionary());

            var ownerKeySalt = new byte[] { 29, 208, 185, 46, 11, 76, 135, 149 };
            var ownerEncryption = new byte[] { 209, 73, 224, 77, 103, 155, 201, 181,
                                        190, 68, 223, 20, 62, 90, 56, 210, 5,
                                        240, 178, 128, 238, 124, 68, 254, 253,
                                        244, 62, 108, 208, 135, 10, 251 };
            var uValue = new byte[] { 94, 230, 205, 75, 166, 99, 250, 76, 219, 128,
                               17, 85, 57, 17, 33, 164, 150, 46, 103, 176, 160,
                               156, 187, 233, 166, 223, 163, 253, 147, 235, 95,
                               184, 83, 245, 146, 101, 198, 247, 34, 198, 191,
                               11, 16, 94, 237, 216, 20, 175 };

            var result = aes256Security.SetupOwnerKey("owner", ownerKeySalt, uValue, ownerEncryption, 6);

            var expected = new byte[] { 42, 218, 213, 39, 73, 91, 72, 79, 67, 38, 248,
                                 133, 18, 189, 61, 34, 107, 79, 29, 56, 59,
                                 181, 213, 118, 113, 34, 65, 210, 87, 174, 22,
                                 239 };

            Assert.AreEqual(expected, result);
        }

        [Test(Description = "RC4 Revision 3")]
        public void Test_RC4_128bit()
        {
            var dict = new PdfDictionary();
            dict.Elements.Add(PdfSecurityHandler.Keys.Filter, new PdfName(PdfSecurityHandler.Filter));
            dict.Elements.Add(PdfSecurityHandler.Keys.V, new PdfInteger(2));
            dict.Elements.Add(PdfSecurityHandler.Keys.Length, new PdfInteger(128));
            dict.Elements.Add(PdfStandardSecurityHandler.Keys.R, new PdfInteger(3));
            dict.Elements.Add(PdfStandardSecurityHandler.Keys.P, new PdfInteger(-1028));
            dict.Elements.Add(PdfStandardSecurityHandler.Keys.O, new PdfString("\u0080\u00c3\u0004\u0096\u0091\u006f\u0020\u0073\u006c\u003a\u00e6\u001b\u0013\u0054\u0091\u00f2\u000d\u0056\u0012\u00e3\u00ff\u005e\u00bb\u00e9\u0056\u004f\u00d8\u006b\u009a\u00ca\u007c\u005d", PdfStringEncoding.RawEncoding));
            dict.Elements.Add(PdfStandardSecurityHandler.Keys.U, new PdfString("\u006a\u000c\u008d\u003e\u0059\u0019\u0000\u00bc\u006a\u0064\u007d\u0091\u00bd\u00aa\u0000\u0018\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000", PdfStringEncoding.RawEncoding));
            dict.Reference = new PdfReference(new PdfObjectID(1, 1), 0);
            dict._document = new PdfDocument();
            dict._document.Internals.FirstDocumentID = "\u00f6\u00c6\u00af\u0017\u00f3\u0072\u0052\u008d\u0052\u004d\u009a\u0080\u00d1\u00ef\u00df\u0018";

            var stdCF = new PdfDictionary();
            stdCF.Elements.Add(PdfCryptoFilter.Keys.CFM, new PdfName(PdfCryptoFilter.V2));

            var cf = new PdfDictionary();
            cf.Elements.Add(PdfCryptoFilter.StdCF, stdCF);

            dict.Elements.Add(PdfSecurityHandler.Keys.CF, cf);

            Assert.IsTrue(PdfStandardSecurityHandler.CanHandle(dict));
            Assert.IsFalse(PdfAESV2SecurityHandler.CanHandle(dict));
            Assert.IsFalse(PdfAESV3SecurityHandler.CanHandle(dict));

            var rc4Security = new PdfStandardSecurityHandler(dict);

            Assert.AreEqual(PasswordValidity.UserPassword, rc4Security.ValidatePassword("123456"));
            Assert.AreEqual(PasswordValidity.OwnerPassword, rc4Security.ValidatePassword("654321"));
            Assert.AreEqual(PasswordValidity.Invalid, rc4Security.ValidatePassword(string.Empty));
            Assert.AreEqual(PasswordValidity.Invalid, rc4Security.ValidatePassword("wrong"));
        }

        [Test(Description = "RC4 Revision 3")]
        public void Test_RC4_40bit_Blank()
        {
            var dict = new PdfDictionary();
            dict.Elements.Add(PdfSecurityHandler.Keys.Filter, new PdfName(PdfSecurityHandler.Filter));
            dict.Elements.Add(PdfSecurityHandler.Keys.V, new PdfInteger(1));
            dict.Elements.Add(PdfSecurityHandler.Keys.Length, new PdfInteger(40));
            dict.Elements.Add(PdfStandardSecurityHandler.Keys.R, new PdfInteger(2));
            dict.Elements.Add(PdfStandardSecurityHandler.Keys.P, new PdfInteger(-3904));
            dict.Elements.Add(PdfStandardSecurityHandler.Keys.O, new PdfString("\u00dc\u00f0\u00ab\u00bb\u00d5\u00c5\u00eb\u008deL\u00b64\u00ea\u0019\u009f\u0085(z\u00f9\u0000\u0017\u00c9\u001b\u00f3\u00aa\u00b2\u000c@\u00a3\u00a7T\u00ba", PdfStringEncoding.RawEncoding));
            dict.Elements.Add(PdfStandardSecurityHandler.Keys.U, new PdfString("lH\u00a2\u00b1\u00eb\u00dd\u008b\u00e0\u0090\u00a8\u0006\u00f7\u00bfi\u00e9\u00c9\u000d\u001c\u008e\u00b3\u0017\u00f0K\u0087\u009c\u00ac'\u000a\u0016\u009a\u00db\u00e4", PdfStringEncoding.RawEncoding));
            dict.Reference = new PdfReference(new PdfObjectID(1, 1), 0);
            dict._document = new PdfDocument();
            dict._document.Internals.FirstDocumentID = "\u001bH*zY\u0016\u00ea\u001fOI\u0088\u0019\u0094'x\u0015";

            var stdCF = new PdfDictionary();
            stdCF.Elements.Add(PdfCryptoFilter.Keys.CFM, new PdfName(PdfCryptoFilter.V2));

            var cf = new PdfDictionary();
            cf.Elements.Add(PdfCryptoFilter.StdCF, stdCF);

            dict.Elements.Add(PdfSecurityHandler.Keys.CF, cf);

            Assert.IsTrue(PdfStandardSecurityHandler.CanHandle(dict));
            Assert.IsFalse(PdfAESV2SecurityHandler.CanHandle(dict));
            Assert.IsFalse(PdfAESV3SecurityHandler.CanHandle(dict));

            var rc4Security = new PdfStandardSecurityHandler(dict);

            Assert.AreEqual(PasswordValidity.UserPassword, rc4Security.ValidatePassword(string.Empty));
            Assert.AreEqual(PasswordValidity.OwnerPassword, rc4Security.ValidatePassword("password"));
            Assert.AreEqual(PasswordValidity.Invalid, rc4Security.ValidatePassword("wrong"));
        }

        [Test(Description = "RC4 Revision 3")]
        public void Test_RC4_56bit_Blank()
        {
            var dict = new PdfDictionary();
            dict.Elements.Add(PdfSecurityHandler.Keys.Filter, new PdfName(PdfSecurityHandler.Filter));
            dict.Elements.Add(PdfSecurityHandler.Keys.V, new PdfInteger(2));
            dict.Elements.Add(PdfSecurityHandler.Keys.Length, new PdfInteger(56));
            dict.Elements.Add(PdfStandardSecurityHandler.Keys.R, new PdfInteger(3));
            dict.Elements.Add(PdfStandardSecurityHandler.Keys.P, new PdfInteger(-3904));
            dict.Elements.Add(PdfStandardSecurityHandler.Keys.O, new PdfString("\u00e4\u00f7\u00049\u0010\u00bf\u00c6R\u00c4\u0085tX\u00f9\u00ae\u001er\u00f3soS\u000a\u00e6b\u00955\u00af\u00c4\u008cB\u00f7\u00b7q", PdfStringEncoding.RawEncoding));
            dict.Elements.Add(PdfStandardSecurityHandler.Keys.U, new PdfString("\u0083\u00ae\u00ab~\u00ef\u0013\u00e5\u0014\u0001\u0009\u00e2+\u0001\u0008\u005cp(\u00bfN^Nu\u008aAd\u0000NV\u00ff\u00fa\u0001\u0008", PdfStringEncoding.RawEncoding));
            dict.Reference = new PdfReference(new PdfObjectID(1, 1), 0);
            dict._document = new PdfDocument();
            dict._document.Internals.FirstDocumentID = "\u00c4H\u0019\u0000\u00a0KiN\u0022(,~\u001fv\u0005u";

            var stdCF = new PdfDictionary();
            stdCF.Elements.Add(PdfCryptoFilter.Keys.CFM, new PdfName(PdfCryptoFilter.V2));

            var cf = new PdfDictionary();
            cf.Elements.Add(PdfCryptoFilter.StdCF, stdCF);

            dict.Elements.Add(PdfSecurityHandler.Keys.CF, cf);

            Assert.IsTrue(PdfStandardSecurityHandler.CanHandle(dict));
            Assert.IsFalse(PdfAESV2SecurityHandler.CanHandle(dict));
            Assert.IsFalse(PdfAESV3SecurityHandler.CanHandle(dict));

            var rc4Security = new PdfStandardSecurityHandler(dict);

            Assert.AreEqual(PasswordValidity.UserPassword, rc4Security.ValidatePassword(string.Empty));
            Assert.AreEqual(PasswordValidity.OwnerPassword, rc4Security.ValidatePassword("password"));
            Assert.AreEqual(PasswordValidity.Invalid, rc4Security.ValidatePassword("wrong"));
        }

        [Test(Description = "RC4 Revision 3")]
        public void Test_RC4_64bit_Blank()
        {
            var dict = new PdfDictionary();
            dict.Elements.Add(PdfSecurityHandler.Keys.Filter, new PdfName(PdfSecurityHandler.Filter));
            dict.Elements.Add(PdfSecurityHandler.Keys.V, new PdfInteger(2));
            dict.Elements.Add(PdfSecurityHandler.Keys.Length, new PdfInteger(64));
            dict.Elements.Add(PdfStandardSecurityHandler.Keys.R, new PdfInteger(3));
            dict.Elements.Add(PdfStandardSecurityHandler.Keys.P, new PdfInteger(-3904));
            dict.Elements.Add(PdfStandardSecurityHandler.Keys.O, new PdfString("\u00ea\u0013\u00c1*V\u0090 \u0022\u0013\u00c5\u008d\u00fb\u00ce\u00cb3+\u00a9h\u0083\u00f9\u0010\u00c8\u000ahsSU|\u00c1on\u0007", PdfStringEncoding.RawEncoding));
            dict.Elements.Add(PdfStandardSecurityHandler.Keys.U, new PdfString("\u00f5C\u008f\u00c7\u00dbX\u00bc\u00860A\u00cb\u0085\u008e\u00bal\u00f2(\u00bfN^Nu\u008aAd\u0000NV\u00ff\u00fa\u0001\u0008", PdfStringEncoding.RawEncoding));
            dict.Reference = new PdfReference(new PdfObjectID(1, 1), 0);
            dict._document = new PdfDocument();
            dict._document.Internals.FirstDocumentID = "\u0094~\u00ac\u0001\u00fa6\u00bc0#6\u00dbN\u001cG\u0092\u001f";

            var stdCF = new PdfDictionary();
            stdCF.Elements.Add(PdfCryptoFilter.Keys.CFM, new PdfName(PdfCryptoFilter.V2));

            var cf = new PdfDictionary();
            cf.Elements.Add(PdfCryptoFilter.StdCF, stdCF);

            dict.Elements.Add(PdfSecurityHandler.Keys.CF, cf);

            Assert.IsTrue(PdfStandardSecurityHandler.CanHandle(dict));
            Assert.IsFalse(PdfAESV2SecurityHandler.CanHandle(dict));
            Assert.IsFalse(PdfAESV3SecurityHandler.CanHandle(dict));

            var rc4Security = new PdfStandardSecurityHandler(dict);

            Assert.AreEqual(PasswordValidity.UserPassword, rc4Security.ValidatePassword(string.Empty));
            Assert.AreEqual(PasswordValidity.OwnerPassword, rc4Security.ValidatePassword("password"));
            Assert.AreEqual(PasswordValidity.Invalid, rc4Security.ValidatePassword("wrong"));
        }

        [Test(Description = "RC4 Revision 3")]
        public void Test_RC4_96bit_Blank()
        {
            var dict = new PdfDictionary();
            dict.Elements.Add(PdfSecurityHandler.Keys.Filter, new PdfName(PdfSecurityHandler.Filter));
            dict.Elements.Add(PdfSecurityHandler.Keys.V, new PdfInteger(2));
            dict.Elements.Add(PdfSecurityHandler.Keys.Length, new PdfInteger(96));
            dict.Elements.Add(PdfStandardSecurityHandler.Keys.R, new PdfInteger(3));
            dict.Elements.Add(PdfStandardSecurityHandler.Keys.P, new PdfInteger(-3904));
            dict.Elements.Add(PdfStandardSecurityHandler.Keys.O, new PdfString("U\u00ee@\u0009/c\u00b5\u0085fs\u0007qLw\u0010}\u008ej\u00fc\u000f\u009ds(\u00e3\u001d\u00b0\u00be\u008f\u00fee\u00af\u00bd", PdfStringEncoding.RawEncoding));
            dict.Elements.Add(PdfStandardSecurityHandler.Keys.U, new PdfString("\u00fb\u0011\u0000k\u001e\u00e0\u0093pa\u00d3\u0012\u00d4~\u00a2\u00ff\u0096(\u00bfN^Nu\u008aAd\u0000NV\u00ff\u00fa\u0001\u0008", PdfStringEncoding.RawEncoding));
            dict.Reference = new PdfReference(new PdfObjectID(1, 1), 0);
            dict._document = new PdfDocument();
            dict._document.Internals.FirstDocumentID = "C'jP\u00a0\u0010oq_-hV\u00f5\u001c\u00c8;";

            var stdCF = new PdfDictionary();
            stdCF.Elements.Add(PdfCryptoFilter.Keys.CFM, new PdfName(PdfCryptoFilter.V2));

            var cf = new PdfDictionary();
            cf.Elements.Add(PdfCryptoFilter.StdCF, stdCF);

            dict.Elements.Add(PdfSecurityHandler.Keys.CF, cf);

            Assert.IsTrue(PdfStandardSecurityHandler.CanHandle(dict));
            Assert.IsFalse(PdfAESV2SecurityHandler.CanHandle(dict));
            Assert.IsFalse(PdfAESV3SecurityHandler.CanHandle(dict));

            var rc4Security = new PdfStandardSecurityHandler(dict);

            Assert.AreEqual(PasswordValidity.UserPassword, rc4Security.ValidatePassword(string.Empty));
            Assert.AreEqual(PasswordValidity.OwnerPassword, rc4Security.ValidatePassword("password"));
            Assert.AreEqual(PasswordValidity.Invalid, rc4Security.ValidatePassword("wrong"));
        }

        [Test(Description = "RC4 Revision 3")]
        public void Test_RC4_128bit_Blank()
        {
            var dict = new PdfDictionary();
            dict.Elements.Add(PdfSecurityHandler.Keys.Filter, new PdfName(PdfSecurityHandler.Filter));
            dict.Elements.Add(PdfSecurityHandler.Keys.V, new PdfInteger(2));
            dict.Elements.Add(PdfSecurityHandler.Keys.Length, new PdfInteger(128));
            dict.Elements.Add(PdfStandardSecurityHandler.Keys.R, new PdfInteger(3));
            dict.Elements.Add(PdfStandardSecurityHandler.Keys.P, new PdfInteger(-3904));
            dict.Elements.Add(PdfStandardSecurityHandler.Keys.O, new PdfString("\u0018U\u000a\u0091\u00c87PV\u009bM\u0084\u0007\u008d\u0094\u001a3H\u0017/>\u00fbZ)\u00c59\u00c6\u00c7\u00de\u00e1\u00dd0\u008f", PdfStringEncoding.RawEncoding));
            dict.Elements.Add(PdfStandardSecurityHandler.Keys.U, new PdfString("\u009c\u00a9\u0010\u00b8\u00cb\u0097\u00f9Cr\u0095\u001fy\u00c1\u00f3\u00bf2(\u00bfN^Nu\u008aAd\u0000NV\u00ff\u00fa\u0001\u0008", PdfStringEncoding.RawEncoding));
            dict.Reference = new PdfReference(new PdfObjectID(1, 1), 0);
            dict._document = new PdfDocument();
            dict._document.Internals.FirstDocumentID = "\u00beG\u000dZ\u00881\u000e\u0018\u0008\u0015)f\u0087M].";

            var stdCF = new PdfDictionary();
            stdCF.Elements.Add(PdfCryptoFilter.Keys.CFM, new PdfName(PdfCryptoFilter.V2));

            var cf = new PdfDictionary();
            cf.Elements.Add(PdfCryptoFilter.StdCF, stdCF);

            dict.Elements.Add(PdfSecurityHandler.Keys.CF, cf);

            Assert.IsTrue(PdfStandardSecurityHandler.CanHandle(dict));
            Assert.IsFalse(PdfAESV2SecurityHandler.CanHandle(dict));
            Assert.IsFalse(PdfAESV3SecurityHandler.CanHandle(dict));

            var rc4Security = new PdfStandardSecurityHandler(dict);

            Assert.AreEqual(PasswordValidity.UserPassword, rc4Security.ValidatePassword(string.Empty));
            Assert.AreEqual(PasswordValidity.OwnerPassword, rc4Security.ValidatePassword("password"));
            Assert.AreEqual(PasswordValidity.Invalid, rc4Security.ValidatePassword("wrong"));
        }

        [Test(Description = "AES128 Revision 4")]
        public void Test_AES_128bit_Blank_1()
        {
            var dict = new PdfDictionary();
            dict.Elements.Add(PdfSecurityHandler.Keys.Filter, new PdfName(PdfSecurityHandler.Filter));
            dict.Elements.Add(PdfSecurityHandler.Keys.V, new PdfInteger(4));
            dict.Elements.Add(PdfSecurityHandler.Keys.Length, new PdfInteger(128));
            dict.Elements.Add(PdfStandardSecurityHandler.Keys.R, new PdfInteger(4));
            dict.Elements.Add(PdfStandardSecurityHandler.Keys.P, new PdfInteger(0x0000F0C0));
            dict.Elements.Add(PdfStandardSecurityHandler.Keys.O, new PdfString("\u0009/\u009f\u00cd\u00b7\u00bd\u00ff\u000e!\u000c\u00ac\u00bf\u0089\u001d\u0012NO\u00bd\u0089$\u00a1w\u0005Z:1\u00b6*\u000eU}l", PdfStringEncoding.RawEncoding));
            dict.Elements.Add(PdfStandardSecurityHandler.Keys.U, new PdfString("u\u00b0C\u00c6\u00f6\u00bf\u00d5\u00c5_\u00aa\u0000\u00f8\u00b8\u0084\u0002D\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000", PdfStringEncoding.RawEncoding));
            dict.Reference = new PdfReference(new PdfObjectID(1, 1), 0);
            dict._document = new PdfDocument();
            dict._document.Internals.FirstDocumentID = "\u00da\u00b9\u0014s<\u00fbM\u00c4\u0094<\u0022\u008ex\u0008\u00dc\u0080";

            var stdCF = new PdfDictionary();
            stdCF.Elements.Add(PdfCryptoFilter.Keys.CFM, new PdfName(PdfCryptoFilter.AESV2));

            var cf = new PdfDictionary();
            cf.Elements.Add(PdfCryptoFilter.StdCF, stdCF);

            dict.Elements.Add(PdfSecurityHandler.Keys.CF, cf);

            Assert.IsFalse(PdfStandardSecurityHandler.CanHandle(dict));
            Assert.IsTrue(PdfAESV2SecurityHandler.CanHandle(dict));
            Assert.IsFalse(PdfAESV3SecurityHandler.CanHandle(dict));

            var aes128Security = new PdfAESV2SecurityHandler(dict);

            Assert.AreEqual(PasswordValidity.UserPassword, aes128Security.ValidatePassword(string.Empty));
            Assert.AreEqual(PasswordValidity.OwnerPassword, aes128Security.ValidatePassword("password"));
            Assert.AreEqual(PasswordValidity.Invalid, aes128Security.ValidatePassword("wrong"));
        }

        [Test(Description = "AES128 Revision 4")]
        public void Test_AES_128bit_Blank_2()
        {
            var dict = new PdfDictionary();
            dict.Elements.Add(PdfSecurityHandler.Keys.Filter, new PdfName(PdfSecurityHandler.Filter));
            dict.Elements.Add(PdfSecurityHandler.Keys.V, new PdfInteger(4));
            dict.Elements.Add(PdfSecurityHandler.Keys.Length, new PdfInteger(128));
            dict.Elements.Add(PdfStandardSecurityHandler.Keys.R, new PdfInteger(4));
            dict.Elements.Add(PdfStandardSecurityHandler.Keys.P, new PdfInteger(-1084));
            dict.Elements.Add(PdfStandardSecurityHandler.Keys.O, new PdfString("\u0073\u0046\u0014\u0076\u002e\u0079\u0035\u0027\u00db\u0097\u000a\u0035\u0022\u00b3\u00e1\u00d4\u00ad\u00bd\u009b\u003c\u00b4\u00a5\u0089\u0075\u0015\u00b2\u0059\u00f1\u0068\u00d9\u00e9\u00f4", PdfStringEncoding.RawEncoding));
            dict.Elements.Add(PdfStandardSecurityHandler.Keys.U, new PdfString("\u0093\u0004\u0089\u00a9\u00bf\u008a\u0045\u00a6\u0088\u00a2\u00db\u00c2\u00a0\u00a8\u0067\u006e\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000", PdfStringEncoding.RawEncoding));
            dict.Reference = new PdfReference(new PdfObjectID(1, 1), 0);
            dict._document = new PdfDocument();
            dict._document.Internals.FirstDocumentID = "\u003c\u004c\u005f\u003a\u0044\u0096\u00af\u0040\u009a\u009d\u00b3\u003c\u0078\u001c\u0076\u00ac";

            var stdCF = new PdfDictionary();
            stdCF.Elements.Add(PdfCryptoFilter.Keys.CFM, new PdfName(PdfCryptoFilter.AESV2));

            var cf = new PdfDictionary();
            cf.Elements.Add(PdfCryptoFilter.StdCF, stdCF);

            dict.Elements.Add(PdfSecurityHandler.Keys.CF, cf);

            Assert.IsFalse(PdfStandardSecurityHandler.CanHandle(dict));
            Assert.IsTrue(PdfAESV2SecurityHandler.CanHandle(dict));
            Assert.IsFalse(PdfAESV3SecurityHandler.CanHandle(dict));

            var aes128Security = new PdfAESV2SecurityHandler(dict);

            Assert.AreEqual(PasswordValidity.UserPassword, aes128Security.ValidatePassword(string.Empty));
            Assert.AreEqual(PasswordValidity.Invalid, aes128Security.ValidatePassword("wrong"));
        }

        [Test(Description = "AES256 Revision 5")]
        public void Test_AES_256bit()
        {
            var dict = new PdfDictionary();
            dict.Elements.Add(PdfSecurityHandler.Keys.Filter, new PdfName(PdfSecurityHandler.Filter));
            dict.Elements.Add(PdfSecurityHandler.Keys.V, new PdfInteger(5));
            dict.Elements.Add(PdfSecurityHandler.Keys.Length, new PdfInteger(256));
            dict.Elements.Add(PdfAESV3SecurityHandler.Keys.R, new PdfInteger(5));
            dict.Elements.Add(PdfAESV3SecurityHandler.Keys.P, new PdfInteger(-1084));
            dict.Elements.Add(PdfAESV3SecurityHandler.Keys.O, new PdfString("\u003c\u0062\u0089\u0023\u0033\u0065\u00c8\u0098\u00d2\u00b2\u00e2\u00e4\u0086\u00cd\u00a3\u0018\u00cc\u007e\u00b1\u0024\u006a\u0032\u0024\u007d\u00d2\u00ac\u00ab\u0078\u00de\u006c\u008b\u0073\u00f3\u0076\u0047\u0099\u0080\u0011\u0065\u003e\u00c8\u00f5\u00f2\u000c\u00da\u007b\u0018\u0078", PdfStringEncoding.RawEncoding));
            dict.Elements.Add(PdfAESV3SecurityHandler.Keys.U, new PdfString("\u0083\u00f2\u008f\u00a0\u0057\u0002\u008a\u0086\u004f\u00fd\u00bd\u00ad\u00e0\u0049\u0090\u00f1\u00be\u0051\u00c5\u000f\u00f9\u0069\u0091\u0097\u000f\u00c2\u0041\u0003\u0001\u007e\u00bb\u00dd\u0075\u00a9\u0004\u0020\u009f\u0065\u0016\u00dc\u00a8\u005e\u00d7\u00c0\u0064\u0026\u00bc\u0028", PdfStringEncoding.RawEncoding));
            dict.Elements.Add(PdfAESV3SecurityHandler.Keys.OE, new PdfString("\u00d5\u00ca\u000e\u00bd\u006e\u004c\u0046\u00bf\u0006\u00c3\u000a\u00be\u009d\u0064\u0090\u0055\u0008\u003e\u007b\u00b2\u009c\u00e5\u0032\u0028\u00e5\u00d8\u0036\u00de\u0022\u0026\u006a\u00df", PdfStringEncoding.RawEncoding));
            dict.Elements.Add(PdfAESV3SecurityHandler.Keys.UE, new PdfString("\u0023\u0096\u00c3\u00a9\u00f5\u0033\u0033\u00ff\u009e\u009e\u0021\u00f2\u00e7\u004b\u007d\u00be\u0019\u007e\u00ac\u0072\u00c3\u00f4\u0089\u00f5\u00ea\u00a5\u002a\u004a\u003c\u0026\u0011\u0011", PdfStringEncoding.RawEncoding));
            dict.Elements.Add(PdfAESV3SecurityHandler.Keys.Perms, new PdfString("\u00d8\u00fc\u0084\u0034\u00e5\u0065\u000d\u0042\u005d\u007f\u0066\u00fd\u003c\u004f\u004d\u004d", PdfStringEncoding.RawEncoding));
            dict.Reference = new PdfReference(new PdfObjectID(1, 1), 0);
            dict._document = new PdfDocument();
            dict._document.Internals.FirstDocumentID = "\u00f6\u00c6\u00af\u0017\u00f3\u0072\u0052\u008d\u0052\u004d\u009a\u0080\u00d1\u00ef\u00df\u0018";

            var stdCF = new PdfDictionary();
            stdCF.Elements.Add(PdfCryptoFilter.Keys.CFM, new PdfName(PdfCryptoFilter.AESV3));

            var cf = new PdfDictionary();
            cf.Elements.Add(PdfCryptoFilter.StdCF, stdCF);

            dict.Elements.Add(PdfSecurityHandler.Keys.CF, cf);

            Assert.IsFalse(PdfStandardSecurityHandler.CanHandle(dict));
            Assert.IsFalse(PdfAESV2SecurityHandler.CanHandle(dict));
            Assert.IsTrue(PdfAESV3SecurityHandler.CanHandle(dict));

            var aes256Security = new PdfAESV3SecurityHandler(dict);

            Assert.AreEqual(PasswordValidity.UserPassword, aes256Security.ValidatePassword("user"));
            Assert.AreEqual(PasswordValidity.OwnerPassword, aes256Security.ValidatePassword("owner"));
            Assert.AreEqual(PasswordValidity.Invalid, aes256Security.ValidatePassword(string.Empty));
            Assert.AreEqual(PasswordValidity.Invalid, aes256Security.ValidatePassword("wrong"));
        }

        [Test(Description = "AES256 Revision 6")]
        public void Test_AES_256bit_ISO()
        {
            var dict = new PdfDictionary();
            dict.Elements.Add(PdfSecurityHandler.Keys.Filter, new PdfName(PdfSecurityHandler.Filter));
            dict.Elements.Add(PdfSecurityHandler.Keys.V, new PdfInteger(5));
            dict.Elements.Add(PdfSecurityHandler.Keys.Length, new PdfInteger(256));
            dict.Elements.Add(PdfAESV3SecurityHandler.Keys.R, new PdfInteger(6));
            dict.Elements.Add(PdfAESV3SecurityHandler.Keys.P, new PdfInteger(-1084));
            dict.Elements.Add(PdfAESV3SecurityHandler.Keys.O, new PdfString("\u0058\u00e8\u003e\u0036\u00f5\u001a\u00f5\u00d1\u0089\u007b\u00dd\u0048\u00c7\u0031\u0025\u00d9\u001f\u004a\u0073\u00a7\u007f\u009e\u00b0\u004d\u002d\u00a3\u0057\u002f\u0027\u005a\u00d9\u008d\u008e\u00e8\u00a9\u00d0\u00ca\u00d6\u0005\u00b9\u001d\u00d0\u00b9\u002e\u000b\u004c\u0087\u0095", PdfStringEncoding.RawEncoding));
            dict.Elements.Add(PdfAESV3SecurityHandler.Keys.U, new PdfString("\u005e\u00e6\u00cd\u004b\u00a6\u0063\u00fa\u004c\u00db\u0080\u0011\u0055\u0039\u0011\u0021\u00a4\u0096\u002e\u0067\u00b0\u00a0\u009c\u00bb\u00e9\u00a6\u00df\u00a3\u00fd\u0093\u00eb\u005f\u00b8\u0053\u00f5\u0092\u0065\u00c6\u00f7\u0022\u00c6\u00bf\u000b\u0010\u005e\u00ed\u00d8\u0014\u00af", PdfStringEncoding.RawEncoding));
            dict.Elements.Add(PdfAESV3SecurityHandler.Keys.OE, new PdfString("\u00d1\u0049\u00e0\u004d\u0067\u009b\u00c9\u00b5\u00be\u0044\u00df\u0014\u003e\u005a\u0038\u00d2\u0005\u00f0\u00b2\u0080\u00ee\u007c\u0044\u00fe\u00fd\u00f4\u003e\u006c\u00d0\u0087\u000a\u00fb", PdfStringEncoding.RawEncoding));
            dict.Elements.Add(PdfAESV3SecurityHandler.Keys.UE, new PdfString("\u0079\u00d0\u0002\u00b5\u00e6\u0059\u009c\u003c\u00fd\u008f\u00d4\u001c\u0054\u00b4\u00c4\u00b1\u00ad\u0080\u00dd\u006b\u002e\u0014\u005e\u00ba\u0087\u0033\u005f\u0018\u0014\u00df\u00fe\u0024", PdfStringEncoding.RawEncoding));
            dict.Elements.Add(PdfAESV3SecurityHandler.Keys.Perms, new PdfString("\u006c\u00ad\u000f\u00a0\u00eb\u004d\u0086\u0057\u004d\u003e\u00cb\u00b5\u00e0\u0058\u00c9\u0037", PdfStringEncoding.RawEncoding));
            dict.Reference = new PdfReference(new PdfObjectID(1, 1), 0);
            dict._document = new PdfDocument();
            dict._document.Internals.FirstDocumentID = "\u00f6\u00c6\u00af\u0017\u00f3\u0072\u0052\u008d\u0052\u004d\u009a\u0080\u00d1\u00ef\u00df\u0018";

            var stdCF = new PdfDictionary();
            stdCF.Elements.Add(PdfCryptoFilter.Keys.CFM, new PdfName(PdfCryptoFilter.AESV3));

            var cf = new PdfDictionary();
            cf.Elements.Add(PdfCryptoFilter.StdCF, stdCF);

            dict.Elements.Add(PdfSecurityHandler.Keys.CF, cf);

            Assert.IsFalse(PdfStandardSecurityHandler.CanHandle(dict));
            Assert.IsFalse(PdfAESV2SecurityHandler.CanHandle(dict));
            Assert.IsTrue(PdfAESV3SecurityHandler.CanHandle(dict));

            var aes256Security = new PdfAESV3SecurityHandler(dict);

            Assert.AreEqual(PasswordValidity.UserPassword, aes256Security.ValidatePassword("user"));
            Assert.AreEqual(PasswordValidity.OwnerPassword, aes256Security.ValidatePassword("owner"));
            Assert.AreEqual(PasswordValidity.Invalid, aes256Security.ValidatePassword(string.Empty));
            Assert.AreEqual(PasswordValidity.Invalid, aes256Security.ValidatePassword("wrong"));
        }

        [Test(Description = "AES256 Revision 5")]
        public void Test_AES_256bit_Blank_1()
        {
            var dict = new PdfDictionary();
            dict.Elements.Add(PdfSecurityHandler.Keys.Filter, new PdfName(PdfSecurityHandler.Filter));
            dict.Elements.Add(PdfSecurityHandler.Keys.V, new PdfInteger(5));
            dict.Elements.Add(PdfSecurityHandler.Keys.Length, new PdfInteger(256));
            dict.Elements.Add(PdfStandardSecurityHandler.Keys.R, new PdfInteger(5));
            dict.Elements.Add(PdfStandardSecurityHandler.Keys.P, new PdfInteger(-3904));
            dict.Elements.Add(PdfStandardSecurityHandler.Keys.O, new PdfString("\u00d7\u0007\u00bb_\u00a7(}\u00f2\u00df\u0008\u00cae\u00b1\u001d\u00ce\u00fft\u00f4\u000d\u00c4\u000c\u0005\u00e4\u00d7\u00c3E\u00e1\u00f7\u001f\u008f\u00af\u00dbs\u009b?AD\u00d9\u0005\u000eV\u0090H8\u00b3\u00ad\u008f>", PdfStringEncoding.RawEncoding));
            dict.Elements.Add(PdfStandardSecurityHandler.Keys.U, new PdfString(")G\u00c8\u00a9\u00f9\u009ck\u00ee\u00f9$2\u00cf\u00a4\u000b@F\u00af\u00aa\u00ce\u0088\u00cb\u00c7\u009b\u001a\u00ef\u00a8/\u00c3\u008b`\u0009\u00e1\u0085\u00c8\u00c5-\u009d\u0002rT\u0018\u00c7\u0087x|\u00c7\u0017^", PdfStringEncoding.RawEncoding));
            dict.Elements.Add(PdfAESV3SecurityHandler.Keys.OE, new PdfString("$\u0003\u00f6\u00c0\u000cF\u00f6i\u00f3\u00db91\u00d6Li\u009a\u00f0G@8u\u00a0\u0081/d\u00ae\u00c3q\u00f4T\u00cc\u00a5", PdfStringEncoding.RawEncoding));
            dict.Elements.Add(PdfAESV3SecurityHandler.Keys.UE, new PdfString("gh9C\u00f0m\u00c2\u0095\u00a3\u00cbPG~\u00a7\u00b7\u0009\u0005\u0083\u0081\u00d3r\u0083+\u0016\u00b31\u00ce\u00bea\u0015}\u00a5", PdfStringEncoding.RawEncoding));
            dict.Elements.Add(PdfAESV3SecurityHandler.Keys.Perms, new PdfString("\u001c\u00ca9\u00df%\u00bdy\u00070\u00b9Y\u0009z\u00bdr2", PdfStringEncoding.RawEncoding));
            dict.Reference = new PdfReference(new PdfObjectID(1, 1), 0);
            dict._document = new PdfDocument();
            dict._document.Internals.FirstDocumentID = "\u00da\u00b9\u0014s<\u00fbM\u00c4\u0094<\u0022\u008ex\u0008\u00dc\u0080";

            var stdCF = new PdfDictionary();
            stdCF.Elements.Add(PdfCryptoFilter.Keys.CFM, new PdfName(PdfCryptoFilter.AESV3));

            var cf = new PdfDictionary();
            cf.Elements.Add(PdfCryptoFilter.StdCF, stdCF);

            dict.Elements.Add(PdfSecurityHandler.Keys.CF, cf);

            Assert.IsFalse(PdfStandardSecurityHandler.CanHandle(dict));
            Assert.IsFalse(PdfAESV2SecurityHandler.CanHandle(dict));
            Assert.IsTrue(PdfAESV3SecurityHandler.CanHandle(dict));

            var aes256Security = new PdfAESV3SecurityHandler(dict);

            Assert.AreEqual(PasswordValidity.UserPassword, aes256Security.ValidatePassword(string.Empty));
            Assert.AreEqual(PasswordValidity.OwnerPassword, aes256Security.ValidatePassword("password"));
            Assert.AreEqual(PasswordValidity.Invalid, aes256Security.ValidatePassword("wrong"));
        }

        [Test(Description = "AES256 Revision 5")]
        public void Test_AES_256bit_Blank_2()
        {
            var dict = new PdfDictionary();
            dict.Elements.Add(PdfSecurityHandler.Keys.Filter, new PdfName(PdfSecurityHandler.Filter));
            dict.Elements.Add(PdfSecurityHandler.Keys.V, new PdfInteger(5));
            dict.Elements.Add(PdfSecurityHandler.Keys.Length, new PdfInteger(256));
            dict.Elements.Add(PdfAESV3SecurityHandler.Keys.R, new PdfInteger(5));
            dict.Elements.Add(PdfAESV3SecurityHandler.Keys.P, new PdfInteger(-1084));
            dict.Elements.Add(PdfAESV3SecurityHandler.Keys.O, new PdfString("\u00b8\u0070\u0004\u00c3\u0067\u0026\u00fc\u0057\u00cc\u004e\u00d4\u0016\u00a1\u00e8\u0095\u0030\u0059\u005a\u00c9\u009e\u00b1\u002d\u0097\u00f3\u00fe\u0003\u0013\u0019\u0066\u0066\u005a\u006e\u008f\u00f5\u00eb\u00ec\u00cc\u0035\u0073\u0056\u0010\u0065\u00ce\u006c\u00b5\u00e9\u0047\u00c1", PdfStringEncoding.RawEncoding));
            dict.Elements.Add(PdfAESV3SecurityHandler.Keys.U, new PdfString("\u0083\u00d4\u007a\u0069\u00f1\u004f\u0030\u0096\u0031\u0012\u00cc\u0082\u00cb\u00ca\u00bf\u0035\u0079\u00fd\u0021\u00eb\u00e4\u00d1\u00b5\u001d\u00d6\u00fa\u0014\u00f3\u00be\u008f\u0071\u0073\u00ef\u0088\u00de\u00e2\u00e8\u00dc\u00f5\u0035\u00e4\u00b8\u0016\u00c8\u0014\u008d\u0065\u001e", PdfStringEncoding.RawEncoding));
            dict.Elements.Add(PdfAESV3SecurityHandler.Keys.OE, new PdfString("\u008f\u0019\u00e8\u00d4\u0027\u00d5\u0007\u00ca\u00c6\u00a1\u0011\u00a6\u0061\u005b\u0074\u00f4\u00df\u000f\u0084\u0029\u000f\u00e4\u00ef\u0046\u0037\u005b\u005b\u0011\u00a0\u008f\u0017\u0065", PdfStringEncoding.RawEncoding));
            dict.Elements.Add(PdfAESV3SecurityHandler.Keys.UE, new PdfString("\u0081\u00f5\u005d\u00b0\u0028\u0081\u00e4\u007f\u005f\u007c\u008f\u0085\u0062\u00a0\u007e\u0010\u00d0\u0088\u006c\u0078\u007b\u007e\u004a\u005e\u0091\u0032\u00b6\u0064\u0012\u0027\u0005\u00f6", PdfStringEncoding.RawEncoding));
            dict.Elements.Add(PdfAESV3SecurityHandler.Keys.Perms, new PdfString("\u0086\u0015\u0036\u0032\u000d\u00ae\u00a2\u00fb\u005d\u003b\u0022\u003d\u0071\u0012\u00b2\u0048", PdfStringEncoding.RawEncoding));
            dict.Reference = new PdfReference(new PdfObjectID(1, 1), 0);
            dict._document = new PdfDocument();
            dict._document.Internals.FirstDocumentID = "\u00f6\u00c6\u00af\u0017\u00f3\u0072\u0052\u008d\u0052\u004d\u009a\u0080\u00d1\u00ef\u00df\u0018";

            var stdCF = new PdfDictionary();
            stdCF.Elements.Add(PdfCryptoFilter.Keys.CFM, new PdfName(PdfCryptoFilter.AESV3));

            var cf = new PdfDictionary();
            cf.Elements.Add(PdfCryptoFilter.StdCF, stdCF);

            dict.Elements.Add(PdfSecurityHandler.Keys.CF, cf);

            Assert.IsFalse(PdfStandardSecurityHandler.CanHandle(dict));
            Assert.IsFalse(PdfAESV2SecurityHandler.CanHandle(dict));
            Assert.IsTrue(PdfAESV3SecurityHandler.CanHandle(dict));

            var aes256Security = new PdfAESV3SecurityHandler(dict);

            Assert.AreEqual(PasswordValidity.UserPassword, aes256Security.ValidatePassword(string.Empty));
            Assert.AreEqual(PasswordValidity.Invalid, aes256Security.ValidatePassword("wrong"));
        }

        [Test(Description = "AES256 Revision 6")]
        public void Test_AES_256bit_ISO_Blank()
        {
            var dict = new PdfDictionary();
            dict.Elements.Add(PdfSecurityHandler.Keys.Filter, new PdfName(PdfSecurityHandler.Filter));
            dict.Elements.Add(PdfSecurityHandler.Keys.V, new PdfInteger(5));
            dict.Elements.Add(PdfSecurityHandler.Keys.Length, new PdfInteger(256));
            dict.Elements.Add(PdfAESV3SecurityHandler.Keys.R, new PdfInteger(6));
            dict.Elements.Add(PdfAESV3SecurityHandler.Keys.P, new PdfInteger(-1084));
            dict.Elements.Add(PdfAESV3SecurityHandler.Keys.O, new PdfString("\u00f7\u00db\u0099\u0055\u00a6\u004d\u00ac\u006b\u00af\u00cf\u00d7\u0041\u0046\u0077\u00e9\u00c1\u0091\u00cb\u0044\u0067\u0049\u0023\u0052\u00cf\u000c\u0015\u0072\u00d7\u0034\u000d\u00ce\u00e9\u0091\u0040\u00e4\u0098\u0051\u0046\u00bf\u0088\u007e\u006a\u00de\u00ad\u008f\u00f4\u0040\u00c1", PdfStringEncoding.RawEncoding));
            dict.Elements.Add(PdfAESV3SecurityHandler.Keys.U, new PdfString("\u001a\u00a9\u00dc\u0091\u0038\u0083\u0093\u006b\u0029\u005b\u0011\u0037\u00b1\u0036\u00db\u00e8\u008e\u00fe\u0028\u00e5\u0089\u00d4\u000e\u00ad\u0012\u003b\u007d\u004e\u005f\u0036\u0066\u0065\u007a\u008b\u0047\u0018\u0005\u0059\u004f\u0068\u007d\u005a\u0048\u00a3\u005a\u0087\u0017\u002a", PdfStringEncoding.RawEncoding));
            dict.Elements.Add(PdfAESV3SecurityHandler.Keys.OE, new PdfString("\u00a4\u0061\u0088\u0020\u0068\u001b\u007f\u00cd\u00d5\u00ca\u0063\u00d8\u0052\u0083\u00e5\u00d6\u001c\u00d2\u0098\u0007\u0098\u0034\u00ba\u00af\u001b\u00b4\u007f\u0051\u00f8\u001e\u0055\u007d", PdfStringEncoding.RawEncoding));
            dict.Elements.Add(PdfAESV3SecurityHandler.Keys.UE, new PdfString("\u00a0\u000a\u005a\u0055\u0027\u001d\u0027\u002c\u000b\u00fe\u000e\u00a2\u004c\u00f9\u0062\u005e\u00a1\u00b9\u00d6\u0076\u0037\u0062\u00b2\u0036\u00a9\u004e\u0099\u00f1\u00a4\u0044\u0065\u0071", PdfStringEncoding.RawEncoding));
            dict.Elements.Add(PdfAESV3SecurityHandler.Keys.Perms, new PdfString("\u0003\u00f2\u0069\u0007\u000d\u00c3\u00f9\u00f2\u0028\u0080\u00b7\u00f5\u00dd\u00d1\u0063\u00eb", PdfStringEncoding.RawEncoding));
            dict.Reference = new PdfReference(new PdfObjectID(1, 1), 0);
            dict._document = new PdfDocument();
            dict._document.Internals.FirstDocumentID = "\u00f6\u00c6\u00af\u0017\u00f3\u0072\u0052\u008d\u0052\u004d\u009a\u0080\u00d1\u00ef\u00df\u0018";

            var stdCF = new PdfDictionary();
            stdCF.Elements.Add(PdfCryptoFilter.Keys.CFM, new PdfName(PdfCryptoFilter.AESV3));

            var cf = new PdfDictionary();
            cf.Elements.Add(PdfCryptoFilter.StdCF, stdCF);

            dict.Elements.Add(PdfSecurityHandler.Keys.CF, cf);

            Assert.IsFalse(PdfStandardSecurityHandler.CanHandle(dict));
            Assert.IsFalse(PdfAESV2SecurityHandler.CanHandle(dict));
            Assert.IsTrue(PdfAESV3SecurityHandler.CanHandle(dict));

            var aes256Security = new PdfAESV3SecurityHandler(dict);

            Assert.AreEqual(PasswordValidity.UserPassword, aes256Security.ValidatePassword(string.Empty));
            Assert.AreEqual(PasswordValidity.Invalid, aes256Security.ValidatePassword("wrong"));
        }
    }
}
