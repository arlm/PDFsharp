using NUnit.Framework;
using PdfSharp.Pdf.Security;
using System;

namespace PDFSharp.Core.Tests
{
    [TestFixture]
    public class StringPrepTest
    {
        [Test(Description = "StringPrep with SaslPrep profile")]
        public void SaslPrepTest()
        {
            Assert.AreEqual("IX", StringPrep.SaslPrep("I\u00ADX"));
            Assert.AreEqual("user", StringPrep.SaslPrep("user"));
            Assert.AreEqual("USER", StringPrep.SaslPrep("USER"));
            Assert.AreEqual("a", StringPrep.SaslPrep("\u00AA"));
            Assert.AreEqual("IX", StringPrep.SaslPrep("\u2168"));
            Assert.Throws<ArgumentException>(() => StringPrep.SaslPrep("\u0007"));
            //Assert.Throws<ArgumentException>(() => StringPrep.SaslPrep("\u0627\u0031"));
        }
    }
}
