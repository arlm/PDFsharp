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
using System.Diagnostics;
using System.Globalization;
using PdfSharp.Internal;
using PdfSharp.Pdf;
using PdfSharp.Pdf.Advanced;
using PdfSharp.Pdf.Content.Objects;
using PdfSharp.Pdf.Internal;

namespace PdfSharp.Fonts.CID
{
    /// <summary>
    /// Represents a CID codespace range value, that is internally an array with 2 interger values.
    /// </summary>
    [DebuggerDisplay("{DebuggerDisplay}")]
    public sealed class CIDRange : PdfObject
    {
        /// <summary>
        /// Represents an empty CIDRange.
        /// </summary>
        public static readonly CIDRange Empty = new CIDRange();

        private readonly ushort _high;

        private readonly ushort _low;

        private readonly int _count;

        private readonly RangeType _type;

        /// <summary>
        /// Initializes a new instance of the CIDRange class.
        /// </summary>
        public CIDRange(RangeType type = RangeType.Linear)
        {
            _type = type;
        }

        /// <summary>
        /// Initializes a new instance of the CIDRange class with two end-popints specifying
        /// the low and high ends of the range.
        /// </summary>
        public CIDRange(int low, int high, RangeType type = RangeType.Linear)
        {
            _type = type;
            _low = unchecked((ushort)low);
            _high = unchecked((ushort)high);

            if (_type == RangeType.Linear)
            {
                _count = Math.Abs(_high - _low + 1);
            }
            else
            {
                byte loFirst = unchecked((byte)((_low & 0xFF00) >> 8));
                byte loSecond = unchecked((byte)(_low & 0x00FF));
                byte hiFirst = unchecked((byte)((_high & 0xFF00) >> 8));
                byte hiSecond = unchecked((byte)(_high & 0x00FF));

                _count = Math.Abs(hiFirst - loFirst + 1) * Math.Abs(hiSecond - loSecond + 1);
            }
        }

        /// <summary>
        /// Initializes a new instance of the CIDRange class with two end-popints specifying
        /// the low and high ends of the range.
        /// </summary>
        public CIDRange(CString low, CString high, RangeType type = RangeType.Linear)
        {
            if (low.CStringType != CStringType.HexString)
            {
                throw new ArgumentException("The string should be of HexString type", nameof(low));
            }

            if (low.Value.Length == 0 || low.Value.Length > 2)
            {
                throw new ArgumentException("The string have one or two bytes only", nameof(low));
            }

            if (high.CStringType != CStringType.HexString)
            {
                throw new ArgumentException("The string should be of HexString type", nameof(high));
            }

            if (high.Value.Length == 0 || high.Value.Length > 2)
            {
                throw new ArgumentException("The string have one or two bytes only", nameof(high));
            }

            if (low.Value.Length != high.Value.Length)
            {
                ContentReaderDiagnostics.ThrowContentReaderException("low and high strings should have the same number of bytes");
            }

            _type = type;

            if (low.Value.Length == 1)
            {
                _low = unchecked((ushort)(low.Value[0] & 0xFF));
                _high = unchecked((ushort)(high.Value[0] & 0xFF));
            }
            else
            {
                _low = unchecked((ushort)((low.Value[0] & 0xFF) << 8 | low.Value[1] & 0xFF));
                _high = unchecked((ushort)((high.Value[0] & 0xFF) << 8 | high.Value[1] & 0xFF));
            }

            if (_type == RangeType.Linear)
            {
                _count = Math.Abs(_high - _low + 1);
            }
            else
            {
                byte loFirst = unchecked((byte)((_low & 0xFF00) >> 8));
                byte loSecond = unchecked((byte)(_low & 0x00FF));
                byte hiFirst = unchecked((byte)((_high & 0xFF00) >> 8));
                byte hiSecond = unchecked((byte)(_high & 0x00FF));

                _count = Math.Abs(hiFirst - loFirst + 1) * Math.Abs(hiSecond - loSecond + 1);
            }
        }

        /// <summary>
        /// Initializes a new instance of the CIDRange class  with two end-popints specifying
        /// the low and high ends of the range.
        /// </summary>
        internal CIDRange(char low, char high, RangeType type = RangeType.Linear)
        {
            _type = type;
            _low = low;
            _high = high;

            if (_type == RangeType.Linear)
            {
                _count = Math.Abs(_high - _low + 1);
            }
            else
            {
                byte loFirst = unchecked((byte)((_low & 0xFF00) >> 8));
                byte loSecond = unchecked((byte)(_low & 0x00FF));
                byte hiFirst = unchecked((byte)((_high & 0xFF00) >> 8));
                byte hiSecond = unchecked((byte)(_high & 0x00FF));

                _count = Math.Abs(hiFirst - loFirst + 1) * Math.Abs(hiSecond - loSecond + 1);
            }
        }

        /// <summary>
        /// Initializes a new instance of the CIDRange class with the specified PdfArray.
        /// </summary>
        internal CIDRange(PdfItem item, RangeType type = RangeType.Linear)
        {
            if (item == null || item is PdfNull)
            {
                return;
            }

            if (item is PdfReference)
            {
                item = ((PdfReference)item).Value;
            }

            PdfArray array = item as PdfArray;
            if (array == null)
            {
                throw new InvalidOperationException("Unexpected token");
            }

            _type = type;
            _low = unchecked((ushort)array.Elements.GetInteger(0));
            _high = unchecked((ushort)array.Elements.GetInteger(1));

            if (_type == RangeType.Linear)
            {
                _count = Math.Abs(_high - _low + 1);
            }
            else
            {
                byte loFirst = unchecked((byte)((_low & 0xFF00) >> 8));
                byte loSecond = unchecked((byte)(_low & 0x00FF));
                byte hiFirst = unchecked((byte)((_high & 0xFF00) >> 8));
                byte hiSecond = unchecked((byte)(_high & 0x00FF));

                _count = Math.Abs(hiFirst - loFirst + 1) * Math.Abs(hiSecond - loSecond + 1);
            }
        }

        /// <summary>
        /// Gets or sets the number of elements present on this range.
        /// </summary>
        public int Count
        {
            get { return _count; }
        }

        /// <summary>
        /// Gets or sets the Nth element value on this range.
        /// </summary>
        public int this[int index]
        {
            get
            {
                if (_type == RangeType.Rectangular)
                {
                    throw new InvalidOperationException("Rectangular ranges cannot be accessed by index");
                }

                if (index < 0 || index > _count)
                {
                    throw new ArgumentOutOfRangeException(nameof(index), "Element not present on this range");
                }

                return _low + index;
            }
        }

        /// <summary>
        /// Gets the high end of this CIDRange.
        /// </summary>
        public ushort High
        {
            get { return _high; }
        }

        /// <summary>
        /// Tests whether all coordinate are zero.
        /// </summary>
        public bool IsEmpty
        {
            // ReSharper disable CompareOfFloatsByEqualityOperator
            get { return _low == 0 && _high == 0; }
            // ReSharper restore CompareOfFloatsByEqualityOperator
        }

        /// <summary>
        /// Gets the low end of this CIDRange.
        /// </summary>
        public ushort Low
        {
            get { return _low; }
        }

        /// <summary>
        /// Gets the DebuggerDisplayAttribute text.
        /// </summary>
        // ReSharper disable UnusedMember.Local
        private string DebuggerDisplay
        // ReSharper restore UnusedMember.Local
        {
            get
            {
                return string.Format(CultureInfo.InvariantCulture,
                    "Low={0:X4}, High={1:X4}", _low, _high);
            }
        }

        /// <summary>
        /// Tests whether two structures differ in one or more coordinates.
        /// </summary>
        public static bool operator !=(CIDRange left, CIDRange right)
        {
            return !(left == right);
        }

        /// <summary>
        /// Tests whether two structures have equal coordinates.
        /// </summary>
        public static bool operator ==(CIDRange left, CIDRange right)
        {
            // ReSharper disable CompareOfFloatsByEqualityOperator
            // use: if (Object.ReferenceEquals(left, null))
            if ((object)left != null)
            {
                if ((object)right != null)
                    return left._low == right._low && left._high == right._high;
                return false;
            }
            return (object)right == null;
            // ReSharper restore CompareOfFloatsByEqualityOperator
        }

        /// <summary>
        /// Clones this instance.
        /// </summary>
        public new CIDRange Clone()
        {
            return (CIDRange)Copy();
        }

        /// <summary>
        /// Determines if the character is contained within this CIDMappingRange.
        /// </summary>
        public bool Contains(char character)
        {
            // Treat range inclusive/inclusive.
            if (_type == RangeType.Linear)
            {
                return _low <= character && _high >= character;
            }

            byte loFirst = unchecked((byte)((_low & 0xFF00) >> 8));
            byte loSecond = unchecked((byte)(_low & 0x00FF));
            byte hiFirst = unchecked((byte)((_high & 0xFF00) >> 8));
            byte hiSecond = unchecked((byte)(_high & 0x00FF));
            byte charFirst = unchecked((byte)((character & 0xFF00) >> 8));
            byte charSecond = unchecked((byte)(character & 0x00FF));

            return loFirst <= charFirst && hiFirst >= charFirst && loSecond <= charSecond && hiSecond >= charSecond;
        }

        /// <summary>
        /// Determines if the character first byte is contained within this CIDMappingRange.
        /// </summary>
        public bool ContainsByte(char character)
        {
            if ((character & 0xFF00) > 0)
            {
                return this.Contains(character);
            }

            // Treat range inclusive/inclusive.
            if (_type == RangeType.Linear)
            {
                var lowerLimit = (_low >> 8) <= (character & 0x00FF);
                var higherLimit = (this._high >> 8) >= (character & 0x00FF);
                return lowerLimit && higherLimit;
            }

            byte loFirst = unchecked((byte)(_low >> 8));
            byte hiFirst = unchecked((byte)(_high >> 8));
            byte charSecond = unchecked((byte)(character & 0x00FF));

            return loFirst <= charSecond && hiFirst >= charSecond;
        }

        /// <summary>
        /// Determines if the specified endpoints are contained within this CIDRange.
        /// </summary>
        public bool Contains(int low, int high)
        {
            // Treat range inclusive/inclusive.
            return _low <= low && _high >= high;
        }

        /// <summary>
        /// Determines if the codespace range represented by range is entirely contained within this CIDRange.
        /// </summary>
        public bool Contains(CIDRange range)
        {
            return _low <= range._low && range._high <= High;
        }

        /// <summary>
        /// Tests whether the specified object is a CIDRange and has equal coordinates.
        /// </summary>
        public override bool Equals(object obj)
        {
            // ReSharper disable CompareOfFloatsByEqualityOperator
            var range = obj as CIDRange;
            if (range != null)
            {
                return range._low == _low && range._high == _high;
            }
            return false;
            // ReSharper restore CompareOfFloatsByEqualityOperator
        }

        /// <summary>
        /// Serves as a hash function for a particular type.
        /// </summary>
        public override int GetHashCode()
        {
            return _low ^ _high;
        }

        /// <summary>
        /// Returns the rectangle as a string in the form «[&lt;low&gt; &lt;high&gt;».
        /// </summary>
        public override string ToString()
        {
            return PdfEncoders.Format("<{0:X4}> <{1:X4}>", _low, _high);
        }

        /// <summary>
        /// Implements cloning this instance.
        /// </summary>
        protected override object Copy()
        {
            CIDRange rect = (CIDRange)base.Copy();
            return rect;
        }

        public enum RangeType
        {
            Linear,
            Rectangular
        }
    }
}