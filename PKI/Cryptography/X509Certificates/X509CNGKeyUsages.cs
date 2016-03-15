namespace System.Security.Cryptography.X509Certificates {
	/// <summary>
	/// Defines key usages for cryptography next generation (CNG) keys.
	/// <para>This enumeration has a <see cref="FlagsAttribute"/> attribute that allows a bitwise combination of its member values.</para>
	/// </summary>
	[Flags]
	public enum X509CNGKeyUsages {
		/// <summary>
		/// The permitted uses are not defined.
		/// </summary>
		None			= 0,
		/// <summary>
		/// The private key can be used to perform a decryption operation.
		/// </summary>
		DecryptOnly		= 0x00000001, // 1
		/// <summary>
		/// The private key can be used to perform a signature operation.
		/// </summary>
		SignatureOnly	= 0x00000002, // 2
		/// <summary>
		/// The private key can be used to perform a key-agreement operation.
		/// </summary>
		KeyAgreement	= 0x00000004, // 4
		/// <summary>
		/// The private key is not restricted to any specific cryptographic operations.
		/// </summary>
		AllUsages		= 0x00ffffff  // 16777215
	}
}
