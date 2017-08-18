using System;
using System.Collections.Generic;
using System.Text;

namespace PdfSharp.Pdf.Security
{
    internal class StringPrep
    {
        /// <summary>
		/// Determines if the character is a non-ASCII space.
		/// </summary>
		/// <remarks>
		/// This list was obtained from http://tools.ietf.org/html/rfc3454#appendix-C.1.2
		/// </remarks>
		/// <returns><c>true</c> if the character is a non-ASCII space; otherwise, <c>false</c>.</returns>
		/// <param name="c">The character.</param>
		static bool IsNonAsciiSpace(char c)
        {
            switch (c)
            {
                case '\u00A0': // NO-BREAK SPACE
                case '\u1680': // OGHAM SPACE MARK
                case '\u2000': // EN QUAD
                case '\u2001': // EM QUAD
                case '\u2002': // EN SPACE
                case '\u2003': // EM SPACE
                case '\u2004': // THREE-PER-EM SPACE
                case '\u2005': // FOUR-PER-EM SPACE
                case '\u2006': // SIX-PER-EM SPACE
                case '\u2007': // FIGURE SPACE
                case '\u2008': // PUNCTUATION SPACE
                case '\u2009': // THIN SPACE
                case '\u200A': // HAIR SPACE
                case '\u200B': // ZERO WIDTH SPACE
                case '\u202F': // NARROW NO-BREAK SPACE
                case '\u205F': // MEDIUM MATHEMATICAL SPACE
                case '\u3000': // IDEOGRAPHIC SPACE
                    return true;
                default:
                    return false;
            }
        }

        /// <summary>
		/// Determines if the character is commonly mapped to nothing.
		/// </summary>
		/// <remarks>
		/// This list was obtained from http://tools.ietf.org/html/rfc3454#appendix-B.1
		/// </remarks>
		/// <returns><c>true</c> if the character is commonly mapped to nothing; otherwise, <c>false</c>.</returns>
		/// <param name="c">The character.</param>
		static bool IsCommonlyMappedToNothing(char c)
        {
            switch (c)
            {
                case '\u00AD':
                case '\u034F':
                case '\u1806':
                case '\u180B':
                case '\u180C':
                case '\u180D':
                case '\u200B':
                case '\u200C':
                case '\u200D':
                case '\u2060':
                case '\uFE00':
                case '\uFE01':
                case '\uFE02':
                case '\uFE03':
                case '\uFE04':
                case '\uFE05':
                case '\uFE06':
                case '\uFE07':
                case '\uFE08':
                case '\uFE09':
                case '\uFE0A':
                case '\uFE0B':
                case '\uFE0C':
                case '\uFE0D':
                case '\uFE0E':
                case '\uFE0F':
                case '\uFEFF':
                    return true;
                default:
                    return false;
            }
        }

        /// <summary>
		/// Determines if the character is prohibited.
		/// </summary>
		/// <remarks>
		/// This list was obtained from http://tools.ietf.org/html/rfc3454#appendix-C.3
		/// </remarks>
		/// <returns><c>true</c> if the character is prohibited; otherwise, <c>false</c>.</returns>
		/// <param name="s">The string.</param>
		/// <param name="index">The character index.</param>
		static bool IsProhibited(string s, int index)
        {
            int u = char.ConvertToUtf32(s, index);

            // Private Use characters: http://tools.ietf.org/html/rfc3454#appendix-C.3
            if ((u >= 0xE000 && u <= 0xF8FF) || (u >= 0xF0000 && u <= 0xFFFFD) || (u >= 0x100000 && u <= 0x10FFFD))
                return true;

            // Non-character code points: http://tools.ietf.org/html/rfc3454#appendix-C.4
            if ((u >= 0xFDD0 && u <= 0xFDEF) || (u >= 0xFFFE && u <= 0xFFFF) || (u >= 0x1FFFE && u <= 0x1FFFF) ||
                (u >= 0x2FFFE && u <= 0x2FFFF) || (u >= 0x3FFFE && u <= 0x3FFFF) || (u >= 0x4FFFE && u <= 0x4FFFF) ||
                (u >= 0x5FFFE && u <= 0x5FFFF) || (u >= 0x6FFFE && u <= 0x6FFFF) || (u >= 0x7FFFE && u <= 0x7FFFF) ||
                (u >= 0x8FFFE && u <= 0x8FFFF) || (u >= 0x9FFFE && u <= 0x9FFFF) || (u >= 0xAFFFE && u <= 0xAFFFF) ||
                (u >= 0xBFFFE && u <= 0xBFFFF) || (u >= 0xCFFFE && u <= 0xCFFFF) || (u >= 0xDFFFE && u <= 0xDFFFF) ||
                (u >= 0xEFFFE && u <= 0xEFFFF) || (u >= 0xFFFFE && u <= 0xFFFFF) || (u >= 0x10FFFE && u <= 0x10FFFF))
                return true;

            // Surrogate code points: http://tools.ietf.org/html/rfc3454#appendix-C.5
            if (u >= 0xD800 && u <= 0xDFFF)
                return true;

            // Inappropriate for plain text characters: http://tools.ietf.org/html/rfc3454#appendix-C.6
            switch (u)
            {
                case 0xFFF9: // INTERLINEAR ANNOTATION ANCHOR
                case 0xFFFA: // INTERLINEAR ANNOTATION SEPARATOR
                case 0xFFFB: // INTERLINEAR ANNOTATION TERMINATOR
                case 0xFFFC: // OBJECT REPLACEMENT CHARACTER
                case 0xFFFD: // REPLACEMENT CHARACTER
                    return true;
            }

            // Inappropriate for canonical representation: http://tools.ietf.org/html/rfc3454#appendix-C.7
            if (u >= 0x2FF0 && u <= 0x2FFB)
                return true;

            // Change display properties or are deprecated: http://tools.ietf.org/html/rfc3454#appendix-C.8
            switch (u)
            {
                case 0x0340: // COMBINING GRAVE TONE MARK
                case 0x0341: // COMBINING ACUTE TONE MARK
                case 0x200E: // LEFT-TO-RIGHT MARK
                case 0x200F: // RIGHT-TO-LEFT MARK
                case 0x202A: // LEFT-TO-RIGHT EMBEDDING
                case 0x202B: // RIGHT-TO-LEFT EMBEDDING
                case 0x202C: // POP DIRECTIONAL FORMATTING
                case 0x202D: // LEFT-TO-RIGHT OVERRIDE
                case 0x202E: // RIGHT-TO-LEFT OVERRIDE
                case 0x206A: // INHIBIT SYMMETRIC SWAPPING
                case 0x206B: // ACTIVATE SYMMETRIC SWAPPING
                case 0x206C: // INHIBIT ARABIC FORM SHAPING
                case 0x206D: // ACTIVATE ARABIC FORM SHAPING
                case 0x206E: // NATIONAL DIGIT SHAPES
                case 0x206F: // NOMINAL DIGIT SHAPES
                    return true;
            }

            // Tagging characters: http://tools.ietf.org/html/rfc3454#appendix-C.9
            if (u == 0xE0001 || (u >= 0xE0020 && u <= 0xE007F))
                return true;

            return false;
        }

        /// <summary>
        /// Prepares the user name or password string.
        /// </summary>
        /// <remarks>
        /// Prepares a user name or password string according to the rules of rfc4013.
        /// </remarks>
        /// <returns>The prepared string.</returns>
        /// <param name="s">The string to prepare.</param>
        /// <exception cref="System.ArgumentNullException">
        /// <paramref name="s"/> is <c>null</c>.
        /// </exception>
        /// <exception cref="System.ArgumentException">
        /// <paramref name="s"/> contains prohibited characters.
        /// </exception>
        public static string SaslPrep(string s)
        {
            if (s == null)
                throw new ArgumentNullException(nameof(s));

            if (s.Length == 0)
                return s;

            var builder = new StringBuilder(s.Length);
            for (int i = 0; i < s.Length; i++)
            {
                if (IsNonAsciiSpace(s[i]))
                {
                    // non-ASII space characters [StringPrep, C.1.2] that can be
                    // mapped to SPACE (U+0020).
                    builder.Append(' ');
                }
                else if (IsCommonlyMappedToNothing(s[i]))
                {
                    // the "commonly mapped to nothing" characters [StringPrep, B.1]
                    // that can be mapped to nothing.
                }
                else if (char.IsControl(s[i]))
                {
                    throw new ArgumentException("Control characters are prohibited.", nameof(s));
                }
                else if (IsProhibited(s, i))
                {
                    throw new ArgumentException("One or more characters in the string are prohibited.", nameof(s));
                }
                else
                {
                    builder.Append(s[i]);
                }
            }

#if !NETFX_CORE && !NETSTANDARD
            return builder.ToString().Normalize(NormalizationForm.FormKC);
#else
			return builder.ToString ();
#endif
        }
    }
}
