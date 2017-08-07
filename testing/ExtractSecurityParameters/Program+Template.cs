namespace ExtractSecurityParameters
{
    partial class Program
    {
        const string template = @"
public class TestSuite
{{    
    [Test(Description = "" Revision 3"")]
    public void Test()
    {{
        var dict = new PdfDictionary();
        dict.Elements.Add(PdfSecurityHandler.Keys.Filter, new PdfName(PdfSecurityHandler.Filter));
        dict.Elements.Add(PdfSecurityHandler.Keys.V, new PdfInteger({0}));
        dict.Elements.Add(PdfSecurityHandler.Keys.Length, new PdfInteger({1}));
        dict.Elements.Add(PdfStandardSecurityHandler.Keys.R, new PdfInteger({2}));
        dict.Elements.Add(PdfStandardSecurityHandler.Keys.P, new PdfInteger(0x{3:X8}));
        dict.Elements.Add(PdfStandardSecurityHandler.Keys.EncryptMetadata, new PdfBoolean({4}));
        dict.Elements.Add(PdfStandardSecurityHandler.Keys.O, new PdfString(""{5}"", PdfStringEncoding.RawEncoding));
        dict.Elements.Add(PdfStandardSecurityHandler.Keys.U, new PdfString(""{6}"", PdfStringEncoding.RawEncoding));
        dict.Elements.Add(PdfAESV3SecurityHandler.Keys.OE, new PdfString(""{7}"", PdfStringEncoding.RawEncoding));
        dict.Elements.Add(PdfAESV3SecurityHandler.Keys.UE, new PdfString(""{8}"", PdfStringEncoding.RawEncoding));
        dict.Elements.Add(PdfAESV3SecurityHandler.Keys.Perms, new PdfString(""{9}"", PdfStringEncoding.RawEncoding));
        dict.Reference = new PdfReference(new PdfObjectID(1, 1), 0);
        dict._document = new PdfDocument();
        dict._document.Internals.FirstDocumentID = ""{10}"";

        var stdCF = new PdfDictionary();
        stdCF.Elements.Add(PdfCryptoFilter.Keys.CFM, new PdfName(PdfCryptoFilter.V2));

        var cf = new PdfDictionary();
        cf.Elements.Add(PdfCryptoFilter.StdCF, stdCF);

        dict.Elements.Add(PdfSecurityHandler.Keys.CF, cf);

        Assert.IsTrue(PdfStandardSecurityHandler.CanHandle(dict));
        Assert.IsFalse(PdfAESV2SecurityHandler.CanHandle(dict));
        Assert.IsFalse(PdfAESV3SecurityHandler.CanHandle(dict));

        var rc4Security = new PdfStandardSecurityHandler(dict);

        Assert.AreEqual(PasswordValidity.Invalid, rc4Security.ValidatePassword(string.Empty));
    }}
}}
";
    }
}
