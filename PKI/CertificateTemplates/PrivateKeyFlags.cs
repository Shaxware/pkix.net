using System;

namespace PKI.CertificateTemplates {
	/// <summary>
	/// Defines private key configuration settings in certificate templates.
	/// <para>This enumeration has a <see cref="FlagsAttribute"/> attribute that allows a bitwise combination of its member values.</para>
	/// </summary>
	[Flags]
	public enum PrivateKeyFlags {
		/// <summary>
		/// None.
		/// </summary>
		None								= 0,
		/// <summary>
		/// This flag instructs the client to create a key archival certificate request.
		/// </summary>
		RequireKeyArchival					= 0x00000001, // 1
		/// <summary>
		/// This flag instructs the client to allow other applications to copy the private key to a .pfx file at a later time.
		/// </summary>
		AllowKeyExport						= 0x00000010, // 16
		/// <summary>
		/// This flag instructs the client to use additional protection for the private key.
		/// </summary>
		RequireStrongProtection				= 0x00000020, // 32
		/// <summary>
		/// This flag instructs the client to use an alternate signature format.
		/// </summary>
		RequireAlternateSignatureAlgorithm	= 0x00000040, // 64
		/// <summary>
		/// This flag instructs the client to use the same key when renewing the certificate.
		/// <para><strong>Windows Server 2003, Windows Server 2008, Windows Server 2008 R2</strong> - this flag is not supported.</para>
		/// </summary>
		ReuseKeysRenewal					= 0x00000080, // 128
		/// <summary>
		/// This flag instructs the client to process the msPKI-RA-Application-Policies attribute.
		/// <para><strong>Windows Server 2003, Windows Server 2008, Windows Server 2008 R2</strong> - this flag is not supported.</para>
		/// </summary>
		UseLegacyProvider					= 0x00000100  // 256
	}
}
