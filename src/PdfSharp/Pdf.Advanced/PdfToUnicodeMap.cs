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
using System.Text;
using System.IO;
using PdfSharp.Fonts;
using PdfSharp.Pdf.Filters;
using PdfSharp.Fonts.CID;
using PdfSharp.Internal;
using PdfSharp.Pdf.Content.Objects;

namespace PdfSharp.Pdf.Advanced
{
    /// <summary>
    /// Represents a ToUnicode map for composite font.
    /// </summary>
    public sealed class PdfToUnicodeMap : PdfDictionary
    {
        public PdfToUnicodeMap(PdfDocument document)
            : base(document)
        {
            _versionControlInfo = new CIDVersionControl();
        }

        internal PdfToUnicodeMap(PdfDocument document, CMapInfo cmapInfo)
            : base(document)
        {
            _cmapInfo = cmapInfo;
            _versionControlInfo = new CIDVersionControl();
        }

        internal PdfToUnicodeMap(PdfDictionary dictionary)
            : base(dictionary)
        {
            _versionControlInfo = new CIDVersionControl();
        }

        /// <summary>
        /// Gets or sets the CID Versíon Control info.
        /// </summar
        public CIDVersionControl CIDVersíonControl
        {
            get { return _versionControlInfo; }
            set { _versionControlInfo = value; }
        }
        CIDVersionControl _versionControlInfo;

        /// <summary>
        /// Gets or sets the CMap info.
        /// </summary>
        internal CMapInfo CMapInfo
        {
            get { return _cmapInfo; }
            set { _cmapInfo = value; }
        }
        CMapInfo _cmapInfo;

        /// <summary>
        /// Gets or sets the CMap table.
        /// </summary>
        public CMap CMapTable
        {
            get { return _cmapTable; }
            set { _cmapTable = value; }
        }
        CMap _cmapTable;

        /// <summary>
        /// Creates the ToUnicode map from the CMapInfo.
        /// </summary>
        internal override void PrepareForSave()
        {
            base.PrepareForSave();

            // This code comes literally from PDF Reference
            string prefix =
              "/CIDInit /ProcSet findresource begin\n" +
              "12 dict begin\n" +
              "begincmap\n" +
              "/CIDSystemInfo " + _versionControlInfo + " def\n" +
              "/CMapName /Adobe-Identity-UCS def /CMapType 2 def\n";
            string suffix = "endcmap CMapName currentdict /CMap defineresource pop end end";

            Dictionary<int, char> glyphIndexToCharacter = new Dictionary<int, char>();
            int lowIndex = 65536, hiIndex = -1;
            foreach (KeyValuePair<char, int> entry in _cmapInfo.CharacterToGlyphIndex)
            {
                int index = (int)entry.Value;
                lowIndex = Math.Min(lowIndex, index);
                hiIndex = Math.Max(hiIndex, index);
                //glyphIndexToCharacter.Add(index, entry.Key);
                glyphIndexToCharacter[index] = entry.Key;
            }

            MemoryStream ms = new MemoryStream();
#if !SILVERLIGHT && !NETFX_CORE
            StreamWriter wrt = new StreamWriter(ms, Encoding.ASCII);
#else
            StreamWriter wrt = new StreamWriter(ms, Encoding.UTF8);
#endif
            wrt.Write(prefix);

            wrt.WriteLine("1 begincodespacerange");
            wrt.WriteLine(String.Format("<{0:X4}><{1:X4}>", lowIndex, hiIndex));
            wrt.WriteLine("endcodespacerange");

            // Sorting seems not necessary. The limit is 100 entries, we will see.
            wrt.WriteLine(String.Format("{0} beginbfrange", glyphIndexToCharacter.Count));
            foreach (KeyValuePair<int, char> entry in glyphIndexToCharacter)
                wrt.WriteLine(String.Format("<{0:X4}><{0:X4}><{1:X4}>", entry.Key, (int)entry.Value));
            wrt.WriteLine("endbfrange");

            wrt.Write(suffix);
#if !UWP
            wrt.Close();
#else
            wrt.Dispose();
#endif

            // Compress like content streams
            byte[] bytes = ms.ToArray();
#if !UWP
            ms.Close();
#else
            ms.Dispose();
#endif
            if (Owner.Options.CompressContentStreams)
            {
                Elements.SetName("/Filter", "/FlateDecode");
                bytes = Filtering.FlateDecode.Encode(bytes, _document.Options.FlateEncodeMode);
            }
            //PdfStream stream = CreateStream(bytes);
            else
            {
                Elements.Remove("/Filter");
            }

            if (Stream == null)
                CreateStream(bytes);
            else
            {
                Stream.Value = bytes;
                Elements.SetInteger(PdfStream.Keys.Length, Stream.Length);
            }
        }

        public sealed class Keys : PdfStream.Keys
        {
            // No new keys.
        }

        private void ParseStream()
        {
            _cmapTable = new CMap(this);

            CIDParser parser;

            if (Stream != null)
            {
                PdfItem filter = Elements["/Filter"];

                if (filter != null)
                {
                    parser = new CIDParser(Stream.UnfilteredValue);
                }
                else
                {
                    parser = new CIDParser(Stream.Value);
                }
            }
            else
            {
                return;
            }

            var innerContent = parser.ReadContent();
            var index = 0;

            if ((innerContent[index++] as CIDOperator)?.OpCode.OpCodeName != CIDOpCodeName.findresource)
            {
                ContentReaderDiagnostics.ThrowContentReaderException("findresource operation not found");
            }

            if ((innerContent[index++] as CIDOperator)?.OpCode.OpCodeName != CIDOpCodeName.begin)
            {
                ContentReaderDiagnostics.ThrowContentReaderException("begin not found after findresource operation");
            }

            var dict = innerContent[index++] as CIDOperator;
            if (dict?.OpCode.OpCodeName != CIDOpCodeName.dict)
            {
                ContentReaderDiagnostics.ThrowContentReaderException("CMap dictionary not found");
            }

            var dictCount = (dict.Operands[0] as CInteger)?.Value ?? 0;

            if (dictCount == 0)
            {
                ContentReaderDiagnostics.ThrowContentReaderException("CMap dictionary should not be empty");
            }

            if (dictCount < 7)
            {
                ContentReaderDiagnostics.ThrowContentReaderException("CMap dictionary does not have the minimum requirements");
            }

            dictCount -= 5;

            if ((innerContent[index++] as CIDOperator)?.OpCode.OpCodeName != CIDOpCodeName.begin)
            {
                ContentReaderDiagnostics.ThrowContentReaderException("begin not found after dict element");
            }

            if ((innerContent[index++] as CIDOperator)?.OpCode.OpCodeName != CIDOpCodeName.begincmap)
            {
                ContentReaderDiagnostics.ThrowContentReaderException("begincmap not found");
            }

            CIDOpCodeName? opCode = null;

            while (opCode != CIDOpCodeName.endcmap && index < innerContent.Count)
            {
                var element = innerContent[index++] as CIDOperator;
                opCode = element?.OpCode.OpCodeName;

#if DEBUG
                if ((index % 50) == 0)
                {
                    Logger.Log("opCode {0}/{1}", index, innerContent.Count);
                }
#endif

                if (!opCode.HasValue)
                {
                    continue;
                }

                switch (opCode.Value)
                {
                    case CIDOpCodeName.CIDSystemInfo:
                    case CIDOpCodeName.Dictionary:
                    case CIDOpCodeName.dict:
                        {
                            _versionControlInfo.ParseStream(innerContent, ref index, element);

                            if ((innerContent[index++] as CIDOperator)?.OpCode.OpCodeName != CIDOpCodeName.def)
                            {
                                ContentReaderDiagnostics.ThrowContentReaderException("def not found after CIDSystemInfo dictionary");
                            }
                        }

                        break;

                    case CIDOpCodeName.def:
                        break;

                    case CIDOpCodeName.begincodespacerange:
                        {
                            var range = (element.Operands[0] as CInteger)?.Value ?? 0;

                            element = innerContent[index++] as CIDOperator;
                            opCode = element?.OpCode.OpCodeName;

                            if (!opCode.HasValue)
                            {
                                continue;
                            }

                            if (opCode.Value != CIDOpCodeName.endcodespacerange)
                            {
                                ContentReaderDiagnostics.ThrowContentReaderException("begincodespacerange without a matchingendcodespacerange");
                            }

                            if (range > 0)
                            {
                                _cmapTable.ImportCodeSpaceRange(element.Operands, range);
                            }
                        }

                        break;

                    case CIDOpCodeName.beginbfchar:
                        {
                            var range = (element.Operands[0] as CInteger)?.Value ?? 0;

                            element = innerContent[index++] as CIDOperator;
                            opCode = element?.OpCode.OpCodeName;

                            if (!opCode.HasValue)
                            {
                                continue;
                            }

                            if (opCode.Value != CIDOpCodeName.endbfchar)
                            {
                                ContentReaderDiagnostics.ThrowContentReaderException("beginbfchar without a endbfchar");
                            }

                            if (range > 0)
                            {
                                _cmapTable.ImportCharacterMap(element.Operands, range);
                            }
                        }

                        break;

                    case CIDOpCodeName.beginbfrange:
                        {
                            var range = (element.Operands[0] as CInteger)?.Value ?? 0;

                            element = innerContent[index++] as CIDOperator;
                            opCode = element?.OpCode.OpCodeName;

                            if (!opCode.HasValue)
                            {
                                continue;
                            }

                            if (opCode.Value != CIDOpCodeName.endbfrange)
                            {
                                ContentReaderDiagnostics.ThrowContentReaderException("beginbfrange without a endbfrange");
                            }

                            if (range > 0)
                            {
                                _cmapTable.ImportCharacterMapRange(element.Operands, range);
                            }
                        }

                        break;

                    case CIDOpCodeName.begincidchar:
                        {
                            var range = (element.Operands[0] as CInteger)?.Value ?? 0;

                            element = innerContent[index++] as CIDOperator;
                            opCode = element?.OpCode.OpCodeName;

                            if (!opCode.HasValue)
                            {
                                continue;
                            }

                            if (opCode.Value != CIDOpCodeName.endcidchar)
                            {
                                ContentReaderDiagnostics.ThrowContentReaderException("begincidchar without a endcidchar");
                            }

                            if (range > 0)
                            {
                                _cmapTable.ImportValidCharacters(element.Operands, range);
                            }
                        }

                        break;

                    case CIDOpCodeName.begincidrange:
                        {
                            var range = (element.Operands[0] as CInteger)?.Value ?? 0;

                            element = innerContent[index++] as CIDOperator;
                            opCode = element?.OpCode.OpCodeName;

                            if (!opCode.HasValue)
                            {
                                continue;
                            }

                            if (opCode.Value != CIDOpCodeName.endcidrange)
                            {
                                ContentReaderDiagnostics.ThrowContentReaderException("begincidrange without a endcidrange");
                            }

                            if (range > 0)
                            {
                                _cmapTable.ImportValidCharactersRange(element.Operands, range);
                            }
                        }

                        break;

                    case CIDOpCodeName.beginnotdefchar:
                        {
                            var range = (element.Operands[0] as CInteger)?.Value ?? 0;

                            element = innerContent[index++] as CIDOperator;
                            opCode = element?.OpCode.OpCodeName;

                            if (!opCode.HasValue)
                            {
                                continue;
                            }

                            if (opCode.Value != CIDOpCodeName.endnotdefchar)
                            {
                                ContentReaderDiagnostics.ThrowContentReaderException("beginnotdefchar without a endnotdefchar");
                            }

                            if (range > 0)
                            {
                                _cmapTable.ImportInvalidCharacters(element.Operands, range);
                            }
                        }

                        break;

                    case CIDOpCodeName.beginnotdefrange:
                        {
                            var range = (element.Operands[0] as CInteger)?.Value ?? 0;

                            element = innerContent[index++] as CIDOperator;
                            opCode = element?.OpCode.OpCodeName;

                            if (!opCode.HasValue)
                            {
                                continue;
                            }

                            if (opCode.Value != CIDOpCodeName.beginnotdefrange)
                            {
                                ContentReaderDiagnostics.ThrowContentReaderException("beginnotdefchar without a endnotdefrange");
                            }

                            if (range > 0)
                            {
                                _cmapTable.ImportInvalidCharactersRange(element.Operands, range);
                            }
                        }

                        break;

                    case CIDOpCodeName.endcmap:
                        break;

                    default:
                        ContentReaderDiagnostics.ThrowContentReaderException($"operation not expected: {element.OpCode.Name}");
                        break;
                }
            }

            if ((innerContent[index++] as CIDOperator)?.OpCode.OpCodeName != CIDOpCodeName.CMapName)
            {
                ContentReaderDiagnostics.ThrowContentReaderException("CMapName not found");
            }

            if ((innerContent[index++] as CIDOperator)?.OpCode.OpCodeName != CIDOpCodeName.currentdict)
            {
                ContentReaderDiagnostics.ThrowContentReaderException("currentdict not found");
            }

            var resource = innerContent[index++] as CIDOperator;
            if (resource?.OpCode.OpCodeName == CIDOpCodeName.defineresource)
            {
                var resourceName = (resource.Operands[0] as CName)?.Name;
                if (resourceName != "/CMap")
                {
                    ContentReaderDiagnostics.ThrowContentReaderException("defineresource is not using a /CMap resource type");
                }
            }
            else
            {
                ContentReaderDiagnostics.ThrowContentReaderException("defineresource not found");
            }

            if ((innerContent[index++] as CIDOperator)?.OpCode.OpCodeName != CIDOpCodeName.pop)
            {
                ContentReaderDiagnostics.ThrowContentReaderException("stack pop command not found");
            }

            if ((innerContent[index++] as CIDOperator)?.OpCode.OpCodeName != CIDOpCodeName.end)
            {
                ContentReaderDiagnostics.ThrowContentReaderException("end not found for CMap Dictionary");
            }

            if ((innerContent[index++] as CIDOperator)?.OpCode.OpCodeName != CIDOpCodeName.end)
            {
                ContentReaderDiagnostics.ThrowContentReaderException("end not found for findresource operation");
            }
        }

        public static PdfToUnicodeMap FromDictionary(PdfDictionary toUnicodeMap)
        {
            var result = new PdfToUnicodeMap(toUnicodeMap);
            result.ParseStream();

            return result;
        }

        public static PdfToUnicodeMap FromCMap(CMap toUnicodeCMap)
        {
            var result = new PdfToUnicodeMap(new PdfDictionary());
            result._cmapTable = toUnicodeCMap;

            return result;
        }
    }
}
