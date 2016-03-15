using System;

namespace PKI.ManagedAPI {
	/// <summary>
	/// This enumeration contains string formats used in CryptoAPI. See remarks for string formats examples.
	/// </summary>
	/// <remarks>
	/// The following section displays example string formats.
	/// 
	/// <example><strong>CRYPT_STRING_BASE64HEADER</strong>
	/// <code>
	/// -----BEGIN CERTIFICATE-----
	/// MIIEITCCA+CgAwIBAgIUKMmxmDbjbHqt+Yzwj5lflBxuQwEwCQYHKoZIzjgEAzAjMSEwHwYDVQQD
	/// ExhUb2tlbiBTaWduaW5nIFB1YmxpYyBLZXkwHhcNMTIxMTE2MTgzODMwWhcNMTIxMTIzMTgzODMw
	/// WjAtMSswKQYDVQQDHiIAYgBiADEANAAxADkAYQAyAGMAZgBjADEAZQAwADAAOAAAMIGfMA0GCSqG
	/// &lt;...&gt;
	/// -----END CERTIFICATE-----
	/// </code>
	/// </example>
	/// <example><strong>CRYPT_STRING_BASE64HEADER</strong>
	/// <code>
	/// MIIEITCCA+CgAwIBAgIUKMmxmDbjbHqt+Yzwj5lflBxuQwEwCQYHKoZIzjgEAzAjMSEwHwYDVQQD
	/// ExhUb2tlbiBTaWduaW5nIFB1YmxpYyBLZXkwHhcNMTIxMTE2MTgzODMwWhcNMTIxMTIzMTgzODMw
	/// WjAtMSswKQYDVQQDHiIAYgBiADEANAAxADkAYQAyAGMAZgBjADEAZQAwADAAOAAAMIGfMA0GCSqG
	/// &lt;...&gt;
	/// </code>
	/// </example>
	/// <example><strong>CRYPT_STRING_BASE64REQUESTHEADER</strong>
	/// <code>
	/// -----BEGIN NEW CERTIFICATE REQUEST-----
	/// MIIDBjCCAm8CAQAwcTERMA8GA1UEAxMIcXV1eC5jb20xDzANBgNVBAsTBkJyYWlu
	/// czEWMBQGA1UEChMNRGV2ZWxvcE1lbnRvcjERMA8GA1UEBxMIVG9ycmFuY2UxEzAR
	/// BgNVBAgTCkNhbGlmb3JuaWExCzAJBgNVBAYTAlVTMIGfMA0GCSqGSIb3DQEBAQUA
	/// &lt;...&gt;
	/// -----END NEW CERTIFICATE REQUEST-----
	/// </code>
	/// </example>
	/// <example><strong>CRYPT_STRING_HEX</strong>
	/// <code>
	/// 3a 20 63 65 72 74 6c 69  62 5c 6c 64 61 70 2e 63
	/// 70 70 28 32 31 33 31 29  3a 20 6c 64 61 70 65 72
	/// &lt;...&gt;
	/// </code>
	/// </example>
	/// <example><strong>CRYPT_STRING_HEXASCII</strong>
	/// <code>
	/// 3a 20 63 65 72 74 6c 69  62 5c 6c 64 61 70 2e 63   : certlib\ldap.c
	/// 70 70 28 32 31 33 31 29  3a 20 6c 64 61 70 65 72   pp(2131): ldaper
	/// &lt;...&gt;
	/// </code>
	/// </example>
	/// <example><strong>CRYPT_STRING_BASE64X509CRLHEADER</strong>
	/// <code>
	/// -----BEGIN X509 CRL-----
	/// MIIDBjCCAm8CAQAwcTERMA8GA1UEAxMIcXV1eC5jb20xDzANBgNVBAsTBkJyYWlu
	/// czEWMBQGA1UEChMNRGV2ZWxvcE1lbnRvcjERMA8GA1UEBxMIVG9ycmFuY2UxEzAR
	/// BgNVBAgTCkNhbGlmb3JuaWExCzAJBgNVBAYTAlVTMIGfMA0GCSqGSIb3DQEBAQUA
	/// &lt;...&gt;
	/// -----END X509 CRL-----
	/// </code>
	/// </example>
	/// <example><strong>CRYPT_STRING_HEXADDR</strong>
	/// <code>
	/// 0000  3a 20 63 65 72 74 6c 69  62 5c 6c 64 61 70 2e 63
	/// 0010  70 70 28 32 31 33 31 29  3a 20 6c 64 61 70 65 72
	/// &lt;...&gt;
	/// </code>
	/// </example>
	/// <example><strong>CRYPT_STRING_HEXASCIIADDR</strong>
	/// <code>
	/// 0000  3a 20 63 65 72 74 6c 69  62 5c 6c 64 61 70 2e 63   : certlib\ldap.c
	/// 0010  70 70 28 32 31 33 31 29  3a 20 6c 64 61 70 65 72   pp(2131): ldaper
	/// &lt;...&gt;
	/// </code>
	/// </example>
	/// <example><strong>CRYPT_STRING_HEXRAW</strong>
	/// <code>
	/// 3a20636572746c69625c6c6461702e6370702832313331293a206c6461706572&lt;...&gt;
	/// </code>
	/// </example>
	/// </remarks>
	[Obsolete("Use Asn1Parser.EncodingType enum instead.", true)]
	public enum CryptEncoding : uint {
		/// <summary>
		/// Base64, with certificate beginning and ending headers.
		/// </summary>
		CRYPT_STRING_BASE64HEADER			= 0x00000000,
		/// <summary>
		/// Base64, without headers.
		/// </summary>
		CRYPT_STRING_BASE64					= 0x00000001,
		/// <summary>
		/// Pure binary copy.
		/// </summary>
		CRYPT_STRING_BINARY					= 0x00000002, //
		/// <summary>
		/// The string is base64 encoded with beginning and ending certificate request headers.
		/// </summary>
		CRYPT_STRING_BASE64REQUESTHEADER	= 0x00000003,
		/// <summary>
		/// Hexadecimal only format.
		/// </summary>
		CRYPT_STRING_HEX					= 0x00000004,
		/// <summary>
		/// Hexadecimal format with ASCII character display.
		/// </summary>
		CRYPT_STRING_HEXASCII				= 0x00000005,
		/// <summary>
		/// Tries the following, in order:
		/// <list type="bullet">
		/// <item>CRYPT_STRING_BASE64HEADER</item>
		/// <item>CRYPT_STRING_BASE64</item>
		/// </list>
		/// <strong><see>CryptBinaryToString<cref>Crypt32Managed.CryptBinaryToString</cref></see></strong> method do not support this flag.
		/// </summary>
		CRYPT_STRING_BASE64_ANY				= 0x00000006,
		/// <summary>
		/// Tries the following, in order:
		/// <list type="bullet">
		/// <item>CRYPT_STRING_BASE64HEADER</item>
		/// <item>CRYPT_STRING_BASE64</item>
		/// <item>CRYPT_STRING_BINARY</item>
		/// </list>
		/// <strong><see cref="Crypt32Managed.CryptBinaryToString">CryptBinaryToString</see></strong> method do not support this flag.
		/// </summary>
		CRYPT_STRING_ANY					= 0x00000007,
		/// <summary>
		/// <list type="bullet">
		/// Tries the following, in order:
		/// <item>CRYPT_STRING_HEXADDR</item>
		/// <item>CRYPT_STRING_HEXASCIIADDR</item>
		/// <item>CRYPT_STRING_HEX</item>
		/// <item>CRYPT_STRING_HEXRAW</item>
		/// <item>CRYPT_STRING_HEXASCII</item>
		/// </list>
		/// <strong><see cref="Crypt32Managed.CryptBinaryToString">CryptBinaryToString</see></strong> method do not support this flag.
		/// </summary>
		CRYPT_STRING_HEX_ANY				= 0x00000008,
		/// <summary>
		/// Base64, with X.509 certificate revocation list (CRL) beginning and ending headers.
		/// </summary>
		CRYPT_STRING_BASE64X509CRLHEADER	= 0x00000009,
		/// <summary>
		/// Hex, with address display.
		/// </summary>
		CRYPT_STRING_HEXADDR				= 0x0000000a,
		/// <summary>
		/// Hex, with ASCII character and address display.
		/// </summary>
		CRYPT_STRING_HEXASCIIADDR			= 0x0000000b,
		/// <summary>
		/// A raw hexadecimal string.
		/// <para><strong>Windows Server 2003 and Windows XP:</strong> This value is not supported.</para>
		/// </summary>
		CRYPT_STRING_HEXRAW					= 0x0000000c,
		/// <summary>
		/// Set this flag for Base64 data to specify that the end of the binary data contain only white space and at most
		/// three equals "=" signs.
		/// <para><strong>Windows Server 2008, Windows Vista, Windows Server 2003, and Windows XP:</strong>
		/// This value is not supported.</para>
		/// </summary>
		CRYPT_STRING_STRICT					= 0x20000000,
	}
}
