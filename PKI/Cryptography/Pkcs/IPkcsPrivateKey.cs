using System;
using System.Security.Cryptography;

namespace PKI.Cryptography.Pkcs {
	/// <summary>
	/// Defines abstract 
	/// </summary>
	public interface IPkcsPrivateKey {
		/// <summary>
		/// Gets the private key algorithm. Examples are, 
		/// </summary>
		Oid2 KeyAlgorithm { get; }
		/// <summary>
		/// Gets the binary copy of the private key
		/// </summary>
		Byte[] RawData { get; }
	}
}