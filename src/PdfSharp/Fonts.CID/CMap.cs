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
using System.Collections;
using System.Collections.Generic;
using System.Text;
using PdfSharp.Pdf.Content.Objects;
using PdfSharp.Pdf;
using PdfSharp.Internal;

namespace PdfSharp.Fonts.CID
{
    public sealed class CMap : PdfObject, IEnumerable<CIDRange>
    {
        private Dictionary<CIDRange, string> characterMap = new Dictionary<CIDRange, string>();
        private List<CIDRange> codespace = new List<CIDRange>();
        private Dictionary<CIDRange, string> namedCharacterMap = new Dictionary<CIDRange, string>();

        internal CMap(PdfDictionary dictionary)
            : base(dictionary)
        {
        }

        /// <summary>
        /// Gets the number of codespace ranges.
        /// </summary>
        public int Count
        {
            get { return codespace.Count; }
        }

        /// <summary>
        /// Gets the codespace range with the specified index.
        /// </summary>
        public CIDRange this[int index]
        {
            get
            {
                if (index < 0 || index >= Count)
                    throw new ArgumentOutOfRangeException(nameof(index), index, "Index out of range");

                return codespace[index];
            }
        }

        public IEnumerator GetEnumerator()
        {
            throw new NotImplementedException();
        }

        /// <summary>
        /// Determines if the character is contained within this CIDMappingRange.
        /// </summary>
        public bool Contains(char character)
        {
            foreach (var range in characterMap.Keys)
            {
                if (range.Contains(character))
                {
                    return true;
                }
            }

            return false;
        }

        /// <summary>
        /// Determines if the character first byte is contained within this CIDMappingRange.
        /// </summary>
        public bool ContainsByte(char character)
        {
            foreach (var range in characterMap.Keys)
            {
                if (range.ContainsByte(character))
                {
                    return true;
                }
            }

            return false;
        }

        public bool Map(char character, out string result)
        {
            var found = false;
            result = null;

            foreach (var range in characterMap)
            {
                if (range.Key.Contains(character))
                {
                    if (range.Key.High != range.Key.Low)
                    {
                        var offset = unchecked((char)(character - range.Key.Low));
                        var newValue = range.Value.Remove(range.Value.Length - 1);
                        var newChar = unchecked((char)(range.Value[range.Value.Length - 1] + offset));
                        newValue += newChar;

                        var chars = new List<byte>();

                        foreach (var @char in newValue)
                        {
                            chars.Add(unchecked((byte)((@char & 0xFF00) >> 8)));
                            chars.Add(unchecked((byte)(@char & 0xFF)));
                        }

                        result = new string(Encoding.BigEndianUnicode.GetChars(chars.ToArray()));
                    }
                    else
                    {
                        var chars = new List<byte>();

                        if (range.Value.Length == 1 && range.Value[0] == 0xFFFD)
                        {
                            chars.Add(unchecked((byte)((character & 0xFF00) >> 8)));
                            chars.Add(unchecked((byte)(character & 0xFF)));
                        }
                        else
                        {
                            foreach (var @char in range.Value)
                            {
                                chars.Add(unchecked((byte)((@char & 0xFF00) >> 8)));
                                chars.Add(unchecked((byte)(@char & 0xFF)));
                            }
                        }

                        result = new string(Encoding.BigEndianUnicode.GetChars(chars.ToArray()));
                    }

                    found = true;
                    break;
                }
            }

            return found;
        }

        IEnumerator<CIDRange> IEnumerable<CIDRange>.GetEnumerator()
        {
            return new CIDCodeSpaceEnumerator(this);
        }

        internal void ImportCharacterMap(CSequence sequence, int count)
        {
            if (sequence.Count > 200)
            {
                ContentReaderDiagnostics.ThrowContentReaderException("The character map array must contain at most 100 endpoint pairs");
            }

            if (sequence.Count != count * 2)
            {
                ContentReaderDiagnostics.ThrowContentReaderException("The character map array endpoint consists of a series of pairs, this array have an odd length");
            }

            for (int index = 0; index < sequence.Count; index += 2)
            {
                var srcCode = sequence[index] as CString;

                if (srcCode?.CStringType != CStringType.HexString)
                {
                    ContentReaderDiagnostics.ThrowContentReaderException("srcCode should be an Hexadecimal string");
                }
                else if (srcCode.Value.Length == 0 || srcCode.Value.Length > 2)
                {
                    ContentReaderDiagnostics.ThrowContentReaderException("srcCode should have one or two-bytes only");
                }

                var range = new CIDRange(srcCode, srcCode);
                var dstCode = sequence[index + 1];
                Add(range, dstCode);
            }
        }

        internal void ImportCharacterMapRange(CSequence sequence, int count)
        {
            if (sequence.Count > 300)
            {
                ContentReaderDiagnostics.ThrowContentReaderException("The chracter map range array must contain at most 100 endpoint triplets");
            }

            if (sequence.Count != count * 3)
            {
                ContentReaderDiagnostics.ThrowContentReaderException("The chracter map range array consists of a series of triplets, this array length is not divisible by 3");
            }

            for (int index = 0; index < sequence.Count; index++)
            {
                if (sequence[index] is CArray)
                {
                    var array = sequence[index] as CArray;
                    var srcCodeLo = array[0] as CString;
                    var srcCodeHi = array[1] as CString;

                    if (srcCodeLo?.CStringType != CStringType.HexString)
                    {
                        ContentReaderDiagnostics.ThrowContentReaderException("srcCodeLo should be an Hexadecimal string");
                    }
                    else if (srcCodeLo.Value.Length == 0 || srcCodeLo.Value.Length > 2)
                    {
                        ContentReaderDiagnostics.ThrowContentReaderException("srcCodeLo should have one or two-bytes only");
                    }

                    if (srcCodeHi?.CStringType != CStringType.HexString)
                    {
                        ContentReaderDiagnostics.ThrowContentReaderException("srcCodeHi should be an Hexadecimal (one or two-byte) string");
                    }
                    else if (srcCodeHi.Value.Length == 0 || srcCodeHi.Value.Length > 2)
                    {
                        ContentReaderDiagnostics.ThrowContentReaderException("srcCodeHi should have one or two-bytes only");
                    }
                    else if (srcCodeLo.Value.Length != srcCodeHi.Value.Length)
                    {
                        ContentReaderDiagnostics.ThrowContentReaderException("srcCodeLo and srcCodeHi should have the same number of bytes");
                    }

                    var range = new CIDRange(srcCodeLo, srcCodeHi);

                    for (var character = 0; character < range.Count; character++)
                    {
                        var tempRange = new CIDRange(range[character], range[character]);
                        var dstCode = array[character + 2];
                        Add(tempRange, dstCode);
                    }
                }
                else
                {
                    var srcCodeLo = sequence[index] as CString;
                    var srcCodeHi = sequence[index + 1] as CString;

                    if (srcCodeLo?.CStringType != CStringType.HexString)
                    {
                        ContentReaderDiagnostics.ThrowContentReaderException("srcCodeLo should be an Hexadecimal string");
                    }
                    else if (srcCodeLo.Value.Length == 0 || srcCodeLo.Value.Length > 2)
                    {
                        ContentReaderDiagnostics.ThrowContentReaderException("srcCodeLo should have one or two-bytes only");
                    }

                    if (srcCodeHi?.CStringType != CStringType.HexString)
                    {
                        ContentReaderDiagnostics.ThrowContentReaderException("srcCodeHi should be an Hexadecimal (one or two-byte) string");
                    }
                    else if (srcCodeHi.Value.Length == 0 || srcCodeHi.Value.Length > 2)
                    {
                        ContentReaderDiagnostics.ThrowContentReaderException("srcCodeHi should have one or two-bytes only");
                    }
                    else if (srcCodeLo.Value.Length != srcCodeHi.Value.Length)
                    {
                        ContentReaderDiagnostics.ThrowContentReaderException("srcCodeLo and srcCodeHi should have the same number of bytes");
                    }

                    var range = new CIDRange(srcCodeLo, srcCodeHi);
                    var dstCode = sequence[index + 2];
                    Add(range, dstCode);

                    index += 2;
                }
            }
        }

        internal void ImportCodeSpaceRange(CSequence sequence, int count)
        {
            if (sequence.Count > 200)
            {
                ContentReaderDiagnostics.ThrowContentReaderException("The codespace range array must contain at most 100 endpoint pairs");
            }

            if (sequence.Count != count * 2)
            {
                ContentReaderDiagnostics.ThrowContentReaderException("The codespace range array endpoint consists of a series of pairs, this array have an odd length");
            }

            for (int index = 0; index < sequence.Count; index += 2)
            {
                var srcCodeLo = sequence[index] as CString;
                var srcCodeHi = sequence[index + 1] as CString;

                if (srcCodeLo?.CStringType != CStringType.HexString)
                {
                    ContentReaderDiagnostics.ThrowContentReaderException("srcCodeLo should be an Hexadecimal string");
                }
                else if (srcCodeLo.Value.Length == 0 || srcCodeLo.Value.Length > 2)
                {
                    ContentReaderDiagnostics.ThrowContentReaderException("srcCodeLo should have one or two-bytes only");
                }

                if (srcCodeHi?.CStringType != CStringType.HexString)
                {
                    ContentReaderDiagnostics.ThrowContentReaderException("srcCodeHi should be an Hexadecimal (one or two-byte) string");
                }
                else if (srcCodeHi.Value.Length == 0 || srcCodeHi.Value.Length > 2)
                {
                    ContentReaderDiagnostics.ThrowContentReaderException("srcCodeHi should have one or two-bytes only");
                }
                else if (srcCodeLo.Value.Length != srcCodeHi.Value.Length)
                {
                    ContentReaderDiagnostics.ThrowContentReaderException("srcCodeLo and srcCodeHi should have the same number of bytes");
                }

                var range = new CIDRange(srcCodeLo, srcCodeHi, CIDRange.RangeType.Rectangular);

                codespace.Add(range);
            }
        }

        internal void ImportInvalidCharacters(CSequence sequence, int count)
        {
            if (sequence.Count > 200)
            {
                ContentReaderDiagnostics.ThrowContentReaderException("The notdef range array must contain at most 100 endpoint pairs");
            }

            if (sequence.Count != count * 2)
            {
                ContentReaderDiagnostics.ThrowContentReaderException("The notdef range array endpoint consists of a series of pairs, this array have an odd length");
            }

            for (int index = 0; index < sequence.Count; index += 2)
            {
                var srcCode = sequence[index] as CString;

                if (srcCode?.CStringType != CStringType.HexString)
                {
                    ContentReaderDiagnostics.ThrowContentReaderException("srcCode should be an Hexadecimal string");
                }
                else if (srcCode.Value.Length == 0 || srcCode.Value.Length > 2)
                {
                    ContentReaderDiagnostics.ThrowContentReaderException("srcCode should have one or two-bytes only");
                }

                var range = new CIDRange(srcCode, srcCode);
                var dstCode = sequence[index + 1];
                Add(range, dstCode);
            }
        }

        internal void ImportInvalidCharactersRange(CSequence sequence, int count)
        {
            if (sequence.Count > 300)
            {
                ContentReaderDiagnostics.ThrowContentReaderException("The notdef range array must contain at most 100 endpoint triplets");
            }

            if (sequence.Count != count * 3)
            {
                ContentReaderDiagnostics.ThrowContentReaderException("The notdef range array consists of a series of triplets, this array length is not divisible by 3");
            }

            for (int index = 0; index < sequence.Count; index += 3)
            {
                var srcCodeLo = sequence[index] as CString;
                var srcCodeHi = sequence[index + 1] as CString;

                if (srcCodeLo?.CStringType != CStringType.HexString)
                {
                    ContentReaderDiagnostics.ThrowContentReaderException("srcCodeLo should be an Hexadecimal string");
                }
                else if (srcCodeLo.Value.Length == 0 || srcCodeLo.Value.Length > 2)
                {
                    ContentReaderDiagnostics.ThrowContentReaderException("srcCodeLo should have one or two-bytes only");
                }

                if (srcCodeHi?.CStringType != CStringType.HexString)
                {
                    ContentReaderDiagnostics.ThrowContentReaderException("srcCodeHi should be an Hexadecimal (one or two-byte) string");
                }
                else if (srcCodeHi.Value.Length == 0 || srcCodeHi.Value.Length > 2)
                {
                    ContentReaderDiagnostics.ThrowContentReaderException("srcCodeHi should have one or two-bytes only");
                }
                else if (srcCodeLo.Value.Length != srcCodeHi.Value.Length)
                {
                    ContentReaderDiagnostics.ThrowContentReaderException("srcCodeLo and srcCodeHi should have the same number of bytes");
                }

                var range = new CIDRange(srcCodeLo, srcCodeHi);
                var dstCode = sequence[index + 2];
                Add(range, dstCode);
            }
        }

        internal void ImportValidCharacters(CSequence sequence, int count)
        {
            if (sequence.Count > 200)
            {
                ContentReaderDiagnostics.ThrowContentReaderException("The cid code array must contain at most 100 endpoint pairs");
            }

            if (sequence.Count != count * 2)
            {
                ContentReaderDiagnostics.ThrowContentReaderException("The cid code array endpoint consists of a series of pairs, this array have an odd length");
            }

            for (int index = 0; index < sequence.Count; index += 2)
            {
                var srcCode = sequence[index] as CString;

                if (srcCode?.CStringType != CStringType.HexString)
                {
                    ContentReaderDiagnostics.ThrowContentReaderException("srcCode should be an Hexadecimal string");
                }
                else if (srcCode.Value.Length == 0 || srcCode.Value.Length > 2)
                {
                    ContentReaderDiagnostics.ThrowContentReaderException("srcCode should have one or two-bytes only");
                }

                var range = new CIDRange(srcCode, srcCode);
                var dstCode = sequence[index + 1];
                Add(range, dstCode);
            }
        }

        internal void ImportValidCharactersRange(CSequence sequence, int count)
        {
            if (sequence.Count > 300)
            {
                ContentReaderDiagnostics.ThrowContentReaderException("The cid code range array must contain at most 100 endpoint triplets");
            }

            if (sequence.Count != count * 3)
            {
                ContentReaderDiagnostics.ThrowContentReaderException("The cid code range array consists of a series of triplets, this array length is not divisible by 3");
            }

            for (int index = 0; index < sequence.Count; index += 3)
            {
                var srcCodeLo = sequence[index] as CString;
                var srcCodeHi = sequence[index + 1] as CString;

                if (srcCodeLo?.CStringType != CStringType.HexString)
                {
                    ContentReaderDiagnostics.ThrowContentReaderException("srcCodeLo should be an Hexadecimal string");
                }
                else if (srcCodeLo.Value.Length == 0 || srcCodeLo.Value.Length > 2)
                {
                    ContentReaderDiagnostics.ThrowContentReaderException("srcCodeLo should have one or two-bytes only");
                }

                if (srcCodeHi?.CStringType != CStringType.HexString)
                {
                    ContentReaderDiagnostics.ThrowContentReaderException("srcCodeHi should be an Hexadecimal (one or two-byte) string");
                }
                else if (srcCodeHi.Value.Length == 0 || srcCodeHi.Value.Length > 2)
                {
                    ContentReaderDiagnostics.ThrowContentReaderException("srcCodeHi should have one or two-bytes only");
                }
                else if (srcCodeLo.Value.Length != srcCodeHi.Value.Length)
                {
                    ContentReaderDiagnostics.ThrowContentReaderException("srcCodeLo and srcCodeHi should have the same number of bytes");
                }

                var range = new CIDRange(srcCodeLo, srcCodeHi);
                var dstCode = sequence[index + 2];
                Add(range, dstCode);
            }
        }

        private void Add(CIDRange tempRange, CObject dstCode)
        {
            var nameValue = dstCode as CName;
            var integerValue = dstCode as CInteger;
            var hexValue = dstCode as CString;
            var arrayValue = dstCode as CArray;

            if (nameValue != null)
            {
                namedCharacterMap.Add(tempRange, nameValue.Name);
            }

            if (integerValue != null)
            {
                characterMap.Add(tempRange, integerValue.Value.ToString());
            }

            if (hexValue != null)
            {
                char? dstChar = null;

                if (hexValue?.CStringType != CStringType.HexString)
                {
                    ContentReaderDiagnostics.ThrowContentReaderException("dstChar should be an Hexadecimal string");
                }
                else if (hexValue.Value.Length == 0)
                {
                    ContentReaderDiagnostics.ThrowContentReaderException("dstChar should have zero byte length");
                }
                else if (hexValue.Value.Length == 1)
                {
                    dstChar = hexValue.Value[0];
                    characterMap.Add(tempRange, dstChar.Value.ToString());
                }
                else
                {
                    var dstBuffer = new byte[hexValue.Value.Length];

                    for (int dstIndex = 0; dstIndex < dstBuffer.Length; dstIndex++)
                    {
                        dstBuffer[dstIndex] = unchecked((byte)(hexValue.Value[dstIndex] & 0xFF));
                    }

                    var chars = Encoding.BigEndianUnicode.GetChars(dstBuffer);
                    characterMap.Add(tempRange, new string(chars));
                }
            }

            if (arrayValue != null)
            {
                if (arrayValue.Count != tempRange.Count)
                {
                    ContentReaderDiagnostics.ThrowContentReaderException("dstCode array must have the same number of elements as the range length");
                }

                for (int index = 0; index < tempRange.Count; index++)
                {
                    dstCode = arrayValue[index];

                    nameValue = dstCode as CName;
                    integerValue = dstCode as CInteger;
                    hexValue = dstCode as CString;

                    var newRange = new CIDRange(tempRange.Low + index, tempRange.Low + index);

                    if (nameValue != null)
                    {
                        namedCharacterMap.Add(newRange, nameValue.Name);
                    }

                    if (integerValue != null)
                    {
                        characterMap.Add(newRange, Convert.ToChar(integerValue.Value).ToString());
                    }

                    if (hexValue != null)
                    {
                        char dstChar;

                        if (hexValue?.CStringType != CStringType.HexString)
                        {
                            ContentReaderDiagnostics.ThrowContentReaderException("dstChar should be an Hexadecimal string");
                        }
                        else if (hexValue.Value.Length == 0)
                        {
                            ContentReaderDiagnostics.ThrowContentReaderException("dstChar should have zero byte length");
                        }
                        else if (hexValue.Value.Length == 1)
                        {
                            dstChar = hexValue.Value[0];
                            characterMap.Add(newRange, dstChar.ToString());
                        }
                        else
                        {
                            var dstBuffer = new byte[hexValue.Value.Length];

                            for (int dstIndex = 0; dstIndex < dstBuffer.Length; dstIndex++)
                            {
                                dstBuffer[dstIndex] = unchecked((byte)(hexValue.Value[dstIndex] & 0xFF));
                            }

                            var chars = Encoding.BigEndianUnicode.GetChars(dstBuffer);
                            characterMap.Add(newRange, new string(chars));
                        }
                    }
                }
            }
        }

        private class CIDCodeSpaceEnumerator : IEnumerator<CIDRange>
        {
            private readonly CMap _list;

            private CIDRange _currentElement;

            private int _index;

            object IEnumerator.Current
            {
                get { return Current; }
            }

            internal CIDCodeSpaceEnumerator(CMap list)
            {
                _list = list;
                _index = -1;
            }

            public CIDRange Current
            {
                get
                {
                    if (_index == -1 || _index >= _list.Count)
                        throw new InvalidOperationException("List out of range");
                    return _currentElement;
                }
            }

            public void Dispose()
            {
                // Nothing to do.
            }

            public bool MoveNext()
            {
                if (_index < _list.Count - 1)
                {
                    _index++;
                    _currentElement = _list[_index];
                    return true;
                }
                _index = _list.Count;
                return false;
            }

            public void Reset()
            {
                _currentElement = null;
                _index = -1;
            }
        }
    }
}
