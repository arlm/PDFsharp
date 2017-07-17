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
using PdfSharp.Internal;
using PdfSharp.Pdf;
using PdfSharp.Pdf.Content.Objects;

namespace PdfSharp.Fonts.CID
{
    public sealed class CIDVersionControl : PdfDictionary
    {
        /// <summary>
        /// Initializes a new page. The page must be added to a document before it can be used.
        /// Depending of the IsMetric property of the current region the page size is set to
        /// A4 or Letter respectively. If this size is not appropriate it should be changed before
        /// any drawing operations are performed on the page.
        /// </summary>
        public CIDVersionControl()
        {
            Elements.SetName(Keys.Registry, "Adobe");
            Elements.SetName(Keys.Ordering, "UCS");
            Elements.SetName(Keys.Supplement, "0");
        }

        internal CIDVersionControl(PdfDictionary dict)
           : base(dict)
        {
        }

        /// <summary>
        /// Gets or sets the bleed box.
        /// </summary>
        public string Ordering
        {
            get { return Elements.GetString(Keys.Ordering, true); }
            set { Elements.SetString(Keys.Ordering, value); }
        }

        /// <summary>
        /// Gets or sets the bleed box.
        /// </summary>
        public string Registry
        {
            get { return Elements.GetString(Keys.Registry, true); }
            set { Elements.SetString(Keys.Registry, value); }
        }

        /// <summary>
        /// Gets or sets the bleed box.
        /// </summary>
        public int Supplement
        {
            get { return Elements.GetInteger(Keys.Supplement, true); }
            set { Elements.SetInteger(Keys.Supplement, value); }
        }

        /// <summary>
        /// Predefined keys common to CID Version Control information.
        /// </summary>
        internal class Keys : KeysBase
        {
            /// <summary>
            /// (Required; non-inheritable) A rectangle, expressed in default user space units, defining the
            /// boundaries of the physical medium on which the page is intended to be displayed or printed.
            /// </summary>
            [KeyInfo(KeyType.String | KeyType.Required)]
            public const string Ordering = "/Ordering";

            /// <summary>
            /// (Required; non-inheritable) Contains the version control information
            /// </summary>
            [KeyInfo(KeyType.String | KeyType.Required)]
            public const string Registry = "/Registry";

            /// <summary>
            /// (Required; non-inheritable)  A rectangle, expressed in default user space units, defining the
            /// visible region of default user space. When the page is displayed or printed, its contents
            /// are to be clipped (cropped) to this rectangle and then imposed on the output medium in some
            /// implementation defined manner. Default value: the value of MediaBox.
            /// </summary>
            [KeyInfo(KeyType.Integer | KeyType.Required)]
            public const string Supplement = "/Supplement";
        }

        internal void ParseStream(CSequence innerContent, ref int index, CIDOperator cmapDictionary)
        {
            if (cmapDictionary?.OpCode.OpCodeName == CIDOpCodeName.CIDSystemInfo)
            {
                cmapDictionary = innerContent[index++] as CIDOperator;
                cmapDictionary.Operands.Insert(0, new CName(CMapDictionary.Keys.CIDSystemInfo));
            }

            if (cmapDictionary?.OpCode.OpCodeName == CIDOpCodeName.Dictionary)
            {
                var cmapDictionaryName = (cmapDictionary.Operands[0] as CName)?.Name;
                var cmapDictionaryString = (cmapDictionary.Operands[1] as CString)?.Value ?? string.Empty;

                if (cmapDictionaryName != CMapDictionary.Keys.CIDSystemInfo)
                {
                    ContentReaderDiagnostics.ThrowContentReaderException("CIDSystemInfo dictionary not found");
                }

                var isValid = cmapDictionaryString.Contains("/Registry") &&
                    cmapDictionaryString.Contains("/Ordering") &&
                    cmapDictionaryString.Contains("/Supplement");

                var formattedItems = cmapDictionaryString
                    .Substring(2, cmapDictionaryString.Length - 4)
                    .Replace("(", "[(")
                    .Replace(")", ")]")
                    .Replace("<", "[<")
                    .Replace(">", ">]");

                var rawItems = formattedItems.Split(new char[] { ' ', '\n', '[', ']' }, StringSplitOptions.RemoveEmptyEntries);
                var items = new List<string>(6);

                foreach (var item in rawItems)
                {
                    if (item != "def")
                    {
                        items.Add(item);
                    }
                }

                if (items.Count != 6)
                {
                    ContentReaderDiagnostics.ThrowContentReaderException("Invalid CIDSystemInfo dictionary length");
                }

                GetCIDSystemInfoItems(items[0], items[1]);
                GetCIDSystemInfoItems(items[2], items[3]);
                GetCIDSystemInfoItems(items[4], items[5]);
            }
            else if (cmapDictionary?.OpCode.OpCodeName == CIDOpCodeName.dict)
            {
                var cmapDictionaryName = (cmapDictionary.Operands[0] as CName)?.Name;
                var cmapDictionaryCount = (cmapDictionary.Operands[1] as CInteger)?.Value ?? 0;

                if (cmapDictionaryName != "/CIDSystemInfo")
                {
                    ContentReaderDiagnostics.ThrowContentReaderException("CIDSystemInfo dictionary not found");
                }

                if (cmapDictionaryCount != 3)
                {
                    ContentReaderDiagnostics.ThrowContentReaderException("Invalid CIDSystemInfo dictionary");
                }

                var cOperator = innerContent[index++] as CIDOperator;
                if (cOperator?.OpCode.OpCodeName == CIDOpCodeName.dup)
                {
                    cOperator = innerContent[index++] as CIDOperator;
                }

                if (cOperator?.OpCode.OpCodeName != CIDOpCodeName.begin)
                {
                    ContentReaderDiagnostics.ThrowContentReaderException("begin not found after CIDSystemInfo dictionary");
                }

                var def1 = innerContent[index++] as CIDOperator;
                var item1 = GetDictionaryEntry(def1);

                var def2 = innerContent[index++] as CIDOperator;
                var item2 = GetDictionaryEntry(def2);

                var def3 = innerContent[index++] as CIDOperator;
                var item3 = GetDictionaryEntry(def3);

                GetCIDSystemInfoItems(item1.Key, item1.Value);
                GetCIDSystemInfoItems(item2.Key, item2.Value);
                GetCIDSystemInfoItems(item3.Key, item3.Value);

                if ((innerContent[index++] as CIDOperator)?.OpCode.OpCodeName != CIDOpCodeName.end)
                {
                    ContentReaderDiagnostics.ThrowContentReaderException("end not found after CIDSystemInfo dictionary definition");
                }
            }
            else
            {
                ContentReaderDiagnostics.ThrowContentReaderException("CIDSystemInfo dictionary not found");
            }
        }

        internal void GetCIDSystemInfoItems(string key, PdfItem value)
        {
            switch (key)
            {
                case Keys.Registry:
                    if (!(value is PdfString))
                    {
                        ContentReaderDiagnostics.ThrowContentReaderException("/Registry CIDSystemInfo element should be of PdfString type");
                    }

                    break;

                case Keys.Ordering:
                    if (!(value is PdfString))
                    {
                        ContentReaderDiagnostics.ThrowContentReaderException("/Ordering CIDSystemInfo element should be of PdfString type");
                    }

                    break;

                case Keys.Supplement:
                    if (!(value is PdfInteger))
                    {
                        ContentReaderDiagnostics.ThrowContentReaderException("/Supplement CIDSystemInfo element should be of PdfInteger type");
                    }

                    break;

                default:
                    ContentReaderDiagnostics.ThrowContentReaderException("Invalid CIDSystemInfo dictionary");
                    break;
            }

            if (Elements.ContainsKey(key))
            {
                Elements.Remove(key);
            }

            Elements.Add(key, value);
        }

        internal void GetCIDSystemInfoItems(string key, string value)
        {
            switch (key)
            {
                case Keys.Registry:
                    {
                        var pdfString = new PdfString(value.Substring(1, value.Length - 2));

                        if (Elements.ContainsKey(key))
                        {
                            Elements[key] = pdfString;
                        }
                        else
                        {
                            Elements.Add(key, pdfString);
                        }
                    }

                    break;

                case Keys.Ordering:
                    {
                        var pdfString = new PdfString(value.Substring(1, value.Length - 2));

                        if (Elements.ContainsKey(key))
                        {
                            Elements[key] = pdfString;
                        }
                        else
                        {
                            Elements.Add(key, pdfString);
                        }
                    }

                    break;

                case Keys.Supplement:
                    {
                        int intValue;

                        if (int.TryParse(value, out intValue))
                        {
                            var pdfInteger = new PdfInteger(intValue);

                            if (Elements.ContainsKey(key))
                            {
                                Elements[key] = pdfInteger;
                            }
                            else
                            {
                                Elements.Add(key, pdfInteger);
                            }
                        }
                        else
                        {
                            ContentReaderDiagnostics.ThrowContentReaderException("Invalid /Supplement element on CIDSystemInfo dictionary");
                        }
                    }

                    break;

                default:
                    ContentReaderDiagnostics.ThrowContentReaderException("Invalid CIDSystemInfo dictionary");
                    break;
            }
        }

        internal KeyValuePair<string, PdfItem> GetDictionaryEntry(CIDOperator def)
        {
            if (def?.OpCode.OpCodeName == CIDOpCodeName.def)
            {
                if (def.Operands.Count == 0)
                {
                    ContentReaderDiagnostics.ThrowContentReaderException("definitions should not be empty");
                }

                var key = (def.Operands[0] as CName)?.Name;
                var stringValue = (def.Operands[1] as CString)?.Value;
                var nameValue = (def.Operands[1] as CName)?.Name;
                var integerValue = (def.Operands[1] as CInteger)?.Value;

                if (string.IsNullOrEmpty(key))
                {
                    ContentReaderDiagnostics.ThrowContentReaderException("definition key should not be empty");
                }

                if (!string.IsNullOrEmpty(stringValue))
                {
                    return new KeyValuePair<string, PdfItem>(key, new PdfString(stringValue));
                }

                if (!string.IsNullOrEmpty(nameValue))
                {
                    return new KeyValuePair<string, PdfItem>(key, new PdfName(nameValue));
                }

                if (integerValue.HasValue)
                {
                    return new KeyValuePair<string, PdfItem>(key, new PdfInteger(integerValue.Value));
                }
            }

            ContentReaderDiagnostics.ThrowContentReaderException("definition not found");
            return default(KeyValuePair<string, PdfItem>);
        }
    }
}