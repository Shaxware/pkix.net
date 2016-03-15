using System;

namespace PKI.ManagedAPI {
	/// <summary>
	/// This enumeration contains string formatting options.
	/// </summary>
	[Flags]
	public enum CryptFormatting : uint {
		/// <summary>
		/// Do not append any new line characters to the encoded string. The default behavior is to use a carriage return/line
		/// feed (CR/LF) pair (0x0D/0x0A) to represent a new line.
		/// <para><strong>Windows Server 2003 and Windows XP:</strong> This value is not supported.</para>
		/// </summary>
		CRYPT_STRING_NOCRLF = 0x40000000,
		/// <summary>
		/// Only use the line feed (LF) character (0x0A) for a new line. The default behavior is to use a CR/LF pair
		/// (0x0D/0x0A) to represent a new line.
		/// </summary>
		CRYPT_STRING_NOCR = 0x80000000
	}
}
