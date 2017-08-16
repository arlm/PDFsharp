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

using System.Diagnostics;
using PdfSharp.Pdf.Content;

using CObject = PdfSharp.Pdf.Content.Objects.CObject;
using CSequence = PdfSharp.Pdf.Content.Objects.CSequence;

namespace PdfSharp.Fonts.CID
{
    /// <summary>
    /// Represents an operator a PDF content stream.
    /// </summary>
    [DebuggerDisplay("({Name}, operands={Operands.Count})")]
    public class CIDOperator : CObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="CIDOperator"/> class.
        /// </summary>
        protected CIDOperator()
        { }

        internal CIDOperator(CIDOpCode opcode)
        {
            _opcode = opcode;
        }

        /// <summary>
        /// Creates a new object that is a copy of the current instance.
        /// </summary>
        public new CIDOperator Clone()
        {
            return (CIDOperator)Copy();
        }

        /// <summary>
        /// Implements the copy mechanism of this class.
        /// </summary>
        protected override CObject Copy()
        {
            CObject obj = base.Copy();
            return obj;
        }

        /// <summary>
        /// Gets or sets the name of the operator
        /// </summary>
        /// <value>The name.</value>
        public virtual string Name
        {
            get { return _opcode.Name; }
        }

        /// <summary>
        /// Gets or sets the operands.
        /// </summary>
        /// <value>The operands.</value>
        public CSequence Operands
        {
            get { return _seqence ?? (_seqence = new CSequence()); }
        }

        private CSequence _seqence;

        /// <summary>
        /// Gets the operator description for this instance.
        /// </summary>
        public CIDOpCode OpCode
        {
            get { return _opcode; }
        }

        private readonly CIDOpCode _opcode;

        /// <summary>
        /// Returns a string that represents the current operator.
        /// </summary>
        public override string ToString()
        {
            if (_opcode.OpCodeName == CIDOpCodeName.Dictionary)
                return " ";

            return Name;
        }

        internal override void WriteObject(ContentWriter writer)
        {
            int count = _seqence != null ? _seqence.Count : 0;
            for (int idx = 0; idx < count; idx++)
            {
                // ReSharper disable once PossibleNullReferenceException because the loop is not entered if _sequence is null
                _seqence[idx].WriteObject(writer);
            }
            writer.WriteLineRaw(ToString());
        }
    }
}
