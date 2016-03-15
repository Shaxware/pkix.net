namespace System.Security.Cryptography.X509Certificates {
	/// <summary>
	/// Defines the encoding type for X.509 objects.
	/// </summary>
	/// <remarks>Currently this class is supported only by <see cref="X509CRL2"/> class.</remarks>
	public enum X509EncodingType {
		/// <summary>
		/// Base64, with X.509 CRL beginning and ending headers
		/// </summary>
		Base64Header = 0,
		/// <summary>
		/// Base64, without headers.
		/// </summary>
		Base64 = 1,
		/// <summary>
		/// Pure binary copy.
		/// </summary>
		Binary = 4
	}
}
#region Full enums
/*
typedef enum EncodingType {
  XCN_CRYPT_STRING_BASE64HEADER          = 0,
  XCN_CRYPT_STRING_BASE64                = 0x1,
  XCN_CRYPT_STRING_BINARY                = 0x2,
  XCN_CRYPT_STRING_BASE64REQUESTHEADER   = 0x3,
  XCN_CRYPT_STRING_HEX                   = 0x4,
  XCN_CRYPT_STRING_HEXASCII              = 0x5,
  XCN_CRYPT_STRING_BASE64_ANY            = 0x6,
  XCN_CRYPT_STRING_ANY                   = 0x7,
  XCN_CRYPT_STRING_HEX_ANY               = 0x8,
  XCN_CRYPT_STRING_BASE64X509CRLHEADER   = 0x9,
  XCN_CRYPT_STRING_HEXADDR               = 0xa,
  XCN_CRYPT_STRING_HEXASCIIADDR          = 0xb,
  XCN_CRYPT_STRING_HEXRAW                = 0xc,
  XCN_CRYPT_STRING_NOCRLF                = 0x40000000,
  XCN_CRYPT_STRING_NOCR                  = 0x80000000 
} EncodingType;
*/
#endregion