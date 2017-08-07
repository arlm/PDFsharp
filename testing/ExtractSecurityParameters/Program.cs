using PdfSharp;
using PdfSharp.Pdf;
using PdfSharp.Pdf.Advanced;
using PdfSharp.Pdf.IO;
using PdfSharp.Pdf.Security;
using System;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;

namespace ExtractSecurityParameters
{
    partial class Program
    {
        static int Main(string[] args)
        {
            var options = new Options();

            if (CommandLine.Parser.Default.ParseArguments(args, options))
            {
                if (options.Verbose)
                {
                    Console.WriteLine("\nInput filename: {0}", options.InputFile);
                    Console.WriteLine("Output filename: {0}", options.OutputFile);
                }

                var inputPath = Path.GetFullPath(options.InputFile);

                if (!File.Exists(inputPath))
                {
                    Console.WriteLine($"\nERROR: the file \"{inputPath}\" does not exist or can't be accessed!");
                    return (int)ErrorCode.InputFileNotFound;
                }

                var outputPath = Path.GetFullPath(options.OutputFile);
                var outputDir = Path.GetDirectoryName(outputPath);

                if (!Directory.Exists(outputDir))
                {
                    Console.WriteLine($"\nERROR: the directory \"{outputDir}\" does not exist or can't be accessed!");
                    return (int)ErrorCode.DirectoryNotFound;
                }

                if (File.Exists(outputPath))
                {
                    Console.WriteLine($"\nWARNING: the file \"{outputPath}\" already exists and will be overwritten.");
                }

                var pdfVersion = PdfReader.TestPdfFile(inputPath);

                if (pdfVersion >= 10 && pdfVersion <= 20)
                {
                    if (options.Verbose)
                    {
                        Console.WriteLine($"\nPDF version {pdfVersion / 10.0}");
                    }
                }
                else
                {
                    return (int)ErrorCode.InvalidPdfFile;
                }

                var response = Open(options.InputFile, PdfDocumentOpenMode.InformationOnly);

                if (options.Verbose)
                {
                    Console.Write(response);
                }

                using (var writer = new StreamWriter(outputPath, false, Encoding.UTF8))
                {
                    writer.Write(response);
                }

                Console.WriteLine($"\nWrote results to {outputPath} ...\n");

                return (int)ErrorCode.Sucess;
            }

            return (int)ErrorCode.CommandLineError;
        }

        /// <summary>
        /// Opens an existing PDF document.
        /// </summary>
        private static string Open(string path, PdfDocumentOpenMode openmode)
        {
            Stream stream = null;

            try
            {
                stream = new FileStream(path, FileMode.Open, FileAccess.Read);
                var response = Open(stream, openmode);

                return response;
            }
            catch
            {
            }
            finally
            {
                stream?.Close();
            }

            return string.Empty;
        }

        /// <summary>
        /// Opens an existing PDF document.
        /// </summary>
        private static string Open(Stream stream, PdfDocumentOpenMode openmode)
        {
            PdfDocument document;

            try
            {
                Lexer lexer = new Lexer(stream);
                document = new PdfDocument(lexer);
                document._state |= DocumentState.Imported;
                document._openMode = openmode;
                document._fileSize = stream.Length;

                // Get file version.
                byte[] header = new byte[1024];
                stream.Position = 0;
                stream.Read(header, 0, 1024);
                document._version = PdfReader.GetPdfFileVersion(header);

                if (document._version == 0)
                {
                    throw new InvalidOperationException(PSSR.InvalidPdf);
                }

                document._irefTable.IsUnderConstruction = true;
                Parser parser = new Parser(document);
                // Read all trailers or cross-reference streams, but no objects.
                document._trailer = parser.ReadTrailer();

                document._irefTable.IsUnderConstruction = false;

                // Is document encrypted?
                PdfReference xrefEncrypt = document._trailer.Elements[PdfTrailer.Keys.Encrypt] as PdfReference;

                if (xrefEncrypt != null)
                {
                    //xrefEncrypt.Value = parser.ReadObject(null, xrefEncrypt.ObjectID, false);
                    PdfObject encrypt = parser.ReadObject(null, xrefEncrypt.ObjectID, false, false);

                    encrypt.Reference = xrefEncrypt;
                    xrefEncrypt.Value = encrypt;

                    var dict = encrypt as PdfDictionary;
                    var v = dict.Elements.GetInteger(PdfSecurityHandler.Keys.V);
                    var r = dict.Elements.GetInteger(PdfStandardSecurityHandler.Keys.R);
                    var length = dict.Elements.GetInteger(PdfSecurityHandler.Keys.Length);
                    var p = dict.Elements.GetInteger(PdfStandardSecurityHandler.Keys.P);
                    var encryptMetadata = true;

                    if (dict.Elements.ContainsKey(PdfStandardSecurityHandler.Keys.EncryptMetadata))
                    {
                        encryptMetadata = dict.Elements.GetBoolean(PdfStandardSecurityHandler.Keys.EncryptMetadata);
                    }

                    var o = EncodeNonAsciiCharacters(dict.Elements.GetString(PdfStandardSecurityHandler.Keys.O));
                    var u = EncodeNonAsciiCharacters(dict.Elements.GetString(PdfStandardSecurityHandler.Keys.U));
                    var oe = EncodeNonAsciiCharacters(dict.Elements.GetString(PdfAESV3SecurityHandler.Keys.OE));
                    var ue = EncodeNonAsciiCharacters(dict.Elements.GetString(PdfAESV3SecurityHandler.Keys.UE));
                    var perms = EncodeNonAsciiCharacters(dict.Elements.GetString(PdfAESV3SecurityHandler.Keys.Perms));
                    var id = EncodeNonAsciiCharacters(dict.Owner.Internals.FirstDocumentID);

                    return string.Format(template, v, length, r, p, encryptMetadata.ToString().ToLower(), o, u, oe, ue, perms, id);
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine(ex.Message);
                throw;
            }

            return string.Empty;
        }

        static string EncodeNonAsciiCharacters(string value)
        {
            StringBuilder sb = new StringBuilder();

            foreach (char c in value)
            {
                if (c >= 0x20 && c <= 0x7f && c != '"' && c != '\\')
                {
                    sb.Append(c);
                }
                else
                {
                    // This character is too big for ASCII
                    string encodedValue = "\\u" + ((int)c).ToString("x4");
                    sb.Append(encodedValue);
                }
            }

            return sb.ToString();
        }

        static string DecodeEncodedNonAsciiCharacters(string value)
        {
            return Regex.Replace(
                value,
                @"\\u(?<Value>[a-zA-Z0-9]{4})",
                m => ((char)int.Parse(m.Groups["Value"].Value, NumberStyles.HexNumber)).ToString()
            );
        }
    }
}
