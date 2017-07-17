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

using System.Collections.Generic;
using System.Diagnostics;

namespace PdfSharp.Fonts.CID
{
    /// <summary>
    /// Static class with all PDF op-codes.
    /// </summary>
    public static class CIDOpCodes
    {
        private static readonly CIDOpCode begin = new CIDOpCode("begin", CIDOpCodeName.begin, -1, null, CIDOpCodeFlags.None,
                        "Begins a new scope block");

        private static readonly CIDOpCode beginbfchar = new CIDOpCode("beginbfchar", CIDOpCodeName.beginbfchar, 1, null, CIDOpCodeFlags.None,
                        "Begins a character substitution definition");

        private static readonly CIDOpCode beginbfrange = new CIDOpCode("beginbfrange", CIDOpCodeName.beginbfrange, 1, null, CIDOpCodeFlags.None,
                        "Begins a character range substitution definition");

        private static readonly CIDOpCode begincidchar = new CIDOpCode("begincidchar", CIDOpCodeName.begincidchar, 1, null, CIDOpCodeFlags.None,
                        "Begins a valid CID code character definition");

        private static readonly CIDOpCode begincidrange = new CIDOpCode("begincidrange", CIDOpCodeName.begincidrange, 1, null, CIDOpCodeFlags.None,
                        "Begins a valid CID code range definition");

        private static readonly CIDOpCode begincmap = new CIDOpCode("begincmap", CIDOpCodeName.begincmap, 0, null, CIDOpCodeFlags.None,
                        "Begins a CMap description");

        private static readonly CIDOpCode begincodespacerange = new CIDOpCode("begincodespacerange", CIDOpCodeName.begincodespacerange, 1, null, CIDOpCodeFlags.None,
                        "Begins a codespace definition");

        private static readonly CIDOpCode beginnotdefchar = new CIDOpCode("beginnotdefchar", CIDOpCodeName.beginnotdefchar, 1, null, CIDOpCodeFlags.None,
                        "Begins a not-valid CID character definition");

        private static readonly CIDOpCode beginnotdefrange = new CIDOpCode("beginnotdefrange", CIDOpCodeName.beginnotdefrange, 1, null, CIDOpCodeFlags.None,
                        "Begins a not-valid CID code range definition");

        private static readonly CIDOpCode CIDSystemInfo = new CIDOpCode("CIDSystemInfo", CIDOpCodeName.CIDSystemInfo, 0, null, CIDOpCodeFlags.None,
                        "A Reference to the CIDSystemInfo that should actually be a Name (this is an accepted error)");

        private static readonly CIDOpCode CMapName = new CIDOpCode("CMapName", CIDOpCodeName.CMapName, 0, null, CIDOpCodeFlags.None,
                "A Reference to the CMapName instance key defined earlier in the CMap dictionary");

        private static readonly CIDOpCode currentdict = new CIDOpCode("currentdict", CIDOpCodeName.currentdict, 0, null, CIDOpCodeFlags.None,
                        "Defines the resource category");

        private static readonly CIDOpCode cvn = new CIDOpCode("cvn", CIDOpCodeName.cvn, 1, "name, convertion", CIDOpCodeFlags.None,
                        "Converts a string to a name");

        private static readonly CIDOpCode def = new CIDOpCode("def", CIDOpCodeName.def, 0, null, CIDOpCodeFlags.None,
                        "Defines a dictionary key and value");

        private static readonly CIDOpCode dup = new CIDOpCode("dup", CIDOpCodeName.dup, 0, null, CIDOpCodeFlags.None,
                        "Duplicates an object on the stack");

        private static readonly CIDOpCode defineresource = new CIDOpCode("defineresource", CIDOpCodeName.defineresource, 0, null, CIDOpCodeFlags.None,
                        "Registers a resource instance");

        private static readonly CIDOpCode dict = new CIDOpCode("dict", CIDOpCodeName.dict, -1, "name, dictionary", CIDOpCodeFlags.None,
                        "PostScript language dictionary resource");

        private static readonly CIDOpCode Dictionary = new CIDOpCode("Dictionary", CIDOpCodeName.Dictionary, -1, "name, dictionary", CIDOpCodeFlags.None,
                        "E.g.: /Name << ... >>");

        private static readonly CIDOpCode end = new CIDOpCode("end", CIDOpCodeName.end, 0, null, CIDOpCodeFlags.None,
                        "Finishes the current scope block");

        private static readonly CIDOpCode endbfchar = new CIDOpCode("endbfchar", CIDOpCodeName.endbfchar, 0, null, CIDOpCodeFlags.None,
                        "Finishes a character substitution definition");

        private static readonly CIDOpCode endbfrange = new CIDOpCode("endbfrange", CIDOpCodeName.endbfrange, 0, null, CIDOpCodeFlags.None,
                        "Finishes a character range substitution definition");

        private static readonly CIDOpCode endcidchar = new CIDOpCode("endcidchar", CIDOpCodeName.endcidchar, 0, null, CIDOpCodeFlags.None,
                        "Finishes a valid CID code character definition");

        private static readonly CIDOpCode endcidrange = new CIDOpCode("endcidrange", CIDOpCodeName.endcidrange, 0, null, CIDOpCodeFlags.None,
                        "Finishes a valid CID code range definition");

        private static readonly CIDOpCode endcmap = new CIDOpCode("endcmap", CIDOpCodeName.endcmap, 0, null, CIDOpCodeFlags.None,
                        "Finishes the CMap definition");

        private static readonly CIDOpCode endcodespacerange = new CIDOpCode("endcodespacerange", CIDOpCodeName.endcodespacerange, 0, null, CIDOpCodeFlags.None,
                        "Fnishes a codespace definition");

        private static readonly CIDOpCode endnotdefchar = new CIDOpCode("endnotdefchar", CIDOpCodeName.endnotdefchar, 0, null, CIDOpCodeFlags.None,
                        "Finishes a not-valid CID character definition");

        private static readonly CIDOpCode endnotdefrange = new CIDOpCode("endnotdefrange", CIDOpCodeName.endnotdefrange, 0, null, CIDOpCodeFlags.None,
                        "Finishes a not-valid CID code range definition");

        private static readonly CIDOpCode findresource = new CIDOpCode("findresource", CIDOpCodeName.findresource, 0, null, CIDOpCodeFlags.None,
                        "Initialization of the necessary support files");

        private static readonly CIDOpCode pop = new CIDOpCode("pop", CIDOpCodeName.pop, -1, null, CIDOpCodeFlags.None,
                        "Pops the resouce from the stack");

        private static readonly CIDOpCode usecmap = new CIDOpCode("usecmap", CIDOpCodeName.usecmap, 1, null, CIDOpCodeFlags.None,
                        "Uses a CMap definition as basis, inheriting its content");

        private static readonly CIDOpCode usefont = new CIDOpCode("usefont", CIDOpCodeName.usefont, 1, null, CIDOpCodeFlags.None,
                        "Changes the font for the operations following this command");

        private static readonly Dictionary<string, CIDOpCode> StringToOpCode;

        /// <summary>
        /// Array of all OpCodes.
        /// </summary>
        private static readonly CIDOpCode[] ops = // new OpCode[]
            {
                // Must be defined behind the code above to ensure that the values are initialized.
                Dictionary,
                def, begincmap, endbfchar, endcmap, begin, begincodespacerange, endcodespacerange, beginbfchar, pop, end, findresource, dict, beginbfrange, endbfrange,
                CMapName, currentdict, defineresource, begincidrange, endcidrange, beginnotdefrange, endnotdefrange, usecmap, usefont, begincidchar, endcidchar,
                beginnotdefchar, endnotdefchar, CIDSystemInfo, dup, cvn
            };

        /// <summary>
        /// Initializes the <see cref="CIDOpCodes"/> class.
        /// </summary>
        static CIDOpCodes()
        {
            StringToOpCode = new Dictionary<string, CIDOpCode>();
            for (int idx = 0; idx < ops.Length; idx++)
            {
                CIDOpCode op = ops[idx];
                StringToOpCode.Add(op.Name, op);
            }
        }

        /// <summary>
        /// Operators from name.
        /// </summary>
        /// <param name="name">The name.</param>
        static public CIDOperator OperatorFromName(string name)
        {
            CIDOperator op = null;
            CIDOpCode opcode = StringToOpCode[name];
            if (opcode != null)
            {
                op = new CIDOperator(opcode);
            }
            else
            {
                Debug.Assert(false, "Unknown operator in PDF content stream.");
            }
            return op;
        }

        // ReSharper restore InconsistentNaming
    }

    /// <summary>
    /// Represents a PDF content stream operator description.
    /// </summary>
    public sealed class CIDOpCode
    {
        /// <summary>
        /// The description from Adobe PDF Reference.
        /// </summary>
        public readonly string Description;

        /// <summary>
        /// The flags.
        /// </summary>
        public readonly CIDOpCodeFlags Flags;

        /// <summary>
        /// The name of the operator.
        /// </summary>
        public readonly string Name;

        /// <summary>
        /// The enum value of the operator.
        /// </summary>
        public readonly CIDOpCodeName OpCodeName;

        /// <summary>
        /// The number of operands. -1 indicates a variable number of operands.
        /// </summary>
        public readonly int Operands;

        /// <summary>
        /// The postscript equivalent, or null, if no such operation exists.
        /// </summary>
        public readonly string Postscript;

        /// <summary>
        /// Initializes a new instance of the <see cref="CIDOpCode"/> class.
        /// </summary>
        /// <param name="name">The name.</param>
        /// <param name="opcodeName">The enum value of the operator.</param>
        /// <param name="operands">The number of operands.</param>
        /// <param name="postscript">The postscript equivalent, or null, if no such operation exists.</param>
        /// <param name="flags">The flags.</param>
        /// <param name="description">The description from Adobe PDF Reference.</param>
        internal CIDOpCode(string name, CIDOpCodeName opcodeName, int operands, string postscript, CIDOpCodeFlags flags, string description)
        {
            Name = name;
            OpCodeName = opcodeName;
            Operands = operands;
            Postscript = postscript;
            Flags = flags;
            Description = description;
        }
    }
}
