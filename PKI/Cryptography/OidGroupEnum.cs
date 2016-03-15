namespace System.Security.Cryptography {
	/// <summary>
	/// This enumeration defines all possible Object Identifier (OID) registration groups. OID can be registered under
	/// multiple OID groups with unique friendly name.
	/// </summary>
	public enum OidGroupEnum {
		/// <summary>
		/// This member is used only when searching through all OID groups.
		/// </summary>
		AllGroups				= 0,
		/// <summary>
		/// Represents hash algorithm group.
		/// </summary>
		HashAlgorithm			= 1,
		/// <summary>
		/// Represents encryption group (symmetric algorithms only).
		/// </summary>
		EncryptionAlgorithm		= 2,
		/// <summary>
		/// Represents public/private key algorithm group (asymmetric algorithms only).
		/// </summary>
		PublicKeyAlgorithm		= 3,
		/// <summary>
		/// Represents signature algorithm group.
		/// </summary>
		SignatureAlgorithm		= 4,
		/// <summary>
		/// Represents X.500 Distinguished Name relative attributes.
		/// </summary>
		RDNAttribute			= 5,
		/// <summary>
		/// Represents certificate extension or certificate attribute group.
		/// </summary>
		ExtensionOrAttribute	= 6,
		/// <summary>
		/// Represents application policy group (the same as enhanced key usage).
		/// </summary>
		ApplicationPolicy		= 7,
		/// <summary>
		/// Represents certificate policy group.
		/// </summary>
		IssuancePolicy			= 8,
		/// <summary>
		/// Represents certificate template group.
		/// </summary>
		CertificateTemplate		= 9,
		/// <summary>
		/// N/A
		/// </summary>
		KeyDerivationFunction	= 10
	}
}
