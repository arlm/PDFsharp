﻿#region PDFsharp - A .NET library for processing PDF
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
using System.IO;
using PdfSharp.Internal;
using PdfSharp.Pdf;
using PdfSharp.Pdf.Content;
using PdfSharp.Pdf.Content.Objects;

#pragma warning disable 1591

namespace PdfSharp.Fonts.CID
{
    /// <summary>
    /// Provides the functionality to parse PDF content streams.
    /// </summary>
    public sealed class CIDParser
    {
        public CIDParser(PdfDictionary dictionary)
        {
            _dictionary = dictionary;
            byte[] bytes = dictionary.Stream.UnfilteredValue;
            _lexer = new CLexer(bytes);
        }

        public CIDParser(byte[] content)
        {
            _lexer = new CLexer(content);
        }

        public CIDParser(MemoryStream content)
        {
            _lexer = new CLexer(content.ToArray());
        }

        public CIDParser(CLexer lexer)
        {
            _lexer = lexer;
        }

        public CSymbol Symbol
        {
            get { return _lexer.Symbol; }
        }

        public CSequence ReadContent()
        {
            CSequence sequence = new CSequence();
            ParseObject(sequence, CSymbol.Eof);

            return sequence;
        }

        /// <summary>
        /// Parses whatever comes until the specified stop symbol is reached.
        /// </summary>
        void ParseObject(CSequence sequence, CSymbol stop)
        {
            CSymbol symbol;
            while ((symbol = ScanNextToken()) != CSymbol.Eof)
            {
                if (symbol == stop)
                    return;

                CString s;
                CIDOperator op;
                switch (symbol)
                {
                    case CSymbol.Comment:
                        // ignore comments
                        break;

                    case CSymbol.Integer:
                        CInteger n = new CInteger();
                        n.Value = _lexer.TokenToInteger;
                        _operands.Add(n);
                        break;

                    case CSymbol.Real:
                        CReal r = new CReal();
                        r.Value = _lexer.TokenToReal;
                        _operands.Add(r);
                        break;

                    case CSymbol.String:
                        s = new CString();
                        s.Value = _lexer.Token;
                        s.CStringType = CStringType.String;
                        _operands.Add(s);
                        break;

                    case CSymbol.HexString:
                        s = new CString();
                        s.Value = _lexer.Token;
                        s.CStringType = CStringType.HexString;
                        _operands.Add(s);
                        break;

                    case CSymbol.UnicodeString:
                        s = new CString();
                        s.Value = _lexer.Token;
                        s.CStringType = CStringType.UnicodeString;
                        _operands.Add(s);
                        break;

                    case CSymbol.UnicodeHexString:
                        s = new CString();
                        s.Value = _lexer.Token;
                        s.CStringType = CStringType.UnicodeHexString;
                        _operands.Add(s);
                        break;

                    case CSymbol.Dictionary:
                        s = new CString();
                        s.Value = _lexer.Token;
                        s.CStringType = CStringType.Dictionary;
                        _operands.Add(s);
                        op = CreateOperator(CIDOpCodeName.Dictionary);
                        //_operands.Clear();
                        sequence.Add(op);

                        break;

                    case CSymbol.Name:
                        CName name = new CName();
                        name.Name = _lexer.Token;
                        _operands.Add(name);
                        break;

                    case CSymbol.Operator:
                        op = CreateOperator();
                        //_operands.Clear();

                        if (op.OpCode.OpCodeName != CIDOpCodeName.cvn)
                        {
                            sequence.Add(op);
                        }

                        break;

                    case CSymbol.BeginArray:
                        CArray array = new CArray();
                        CSequence tempOperands = null;

                        if (_operands.Count != 0)
                        {
                            tempOperands = new CSequence();
                            tempOperands.Add(_operands);
                            _operands.Clear();
                        }

                        ParseObject(array, CSymbol.EndArray);
                        array.Add(_operands);
                        _operands.Clear();

                        if (tempOperands != null)
                        {
                            _operands.Add(tempOperands);
                            tempOperands = null;
                        }

                        _operands.Add((CObject)array);
                        break;

                    case CSymbol.EndArray:
                        ContentReaderDiagnostics.HandleUnexpectedCharacter(']');
                        break;

#if DEBUG
                    default:
                        Debug.Assert(false);
                        break;
#endif
                }
            }
        }

        CIDOperator CreateOperator()
        {
            string name = _lexer.Token;
            CIDOperator op = CIDOpCodes.OperatorFromName(name);
            return CreateOperator(op);
        }

        CIDOperator CreateOperator(CIDOpCodeName nameop)
        {
            string name = nameop.ToString();
            CIDOperator op = CIDOpCodes.OperatorFromName(name);
            return CreateOperator(op);
        }

        CIDOperator CreateOperator(CIDOperator op)
        {
            if (op.OpCode.OpCodeName == CIDOpCodeName.cvn)
            {
                if (_operands.Count >= 1)
                {
                    CString text = _operands[0] as CString;
                    CSequence sequence = new CSequence();

                    if (text != null && !string.IsNullOrEmpty(text.Value))
                    {
                        CName name = new CName();
                        name.Name = text.Value;
                        _operands[0] = name;
                        sequence.Add(text);
                    }
                    else if (_operands[0] is CName)
                    {
                        sequence.Add(_operands[0]);
                    }

                    op.Operands.Add(sequence);
                    return op;
                }
            }

            op.Operands.Add(_operands);
            _operands.Clear();

            return op;
        }

        CSymbol ScanNextToken()
        {
            return _lexer.ScanNextToken();
        }

        CSymbol ScanNextToken(out string token)
        {
            CSymbol symbol = _lexer.ScanNextToken();
            token = _lexer.Token;
            return symbol;
        }

        /// <summary>
        /// Reads the next symbol that must be the specified one.
        /// </summary>
        CSymbol ReadSymbol(CSymbol symbol)
        {
            CSymbol current = _lexer.ScanNextToken();
            if (symbol != current)
                ContentReaderDiagnostics.ThrowContentReaderException(PSSR.UnexpectedToken(_lexer.Token));
            return current;
        }

        readonly CSequence _operands = new CSequence();
        PdfDictionary _dictionary;
        readonly CLexer _lexer;
    }
}