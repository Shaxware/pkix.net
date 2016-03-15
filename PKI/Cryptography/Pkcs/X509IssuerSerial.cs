using System.Security.Cryptography.X509Certificates;

namespace System.Security.Cryptography.Pkcs {
	/// <summary>
	/// Represents the <strong>X509IssuerSerial</strong> element of an XML digital signature.
	/// </summary>
	/// <remarks>
	/// This class is a replacement for a .NET native <see href="http://msdn.microsoft.com/en-us/library/system.security.cryptography.xml.x509issuerserial.aspx">X509IssuerSerial</see> structure.
	/// </remarks>
	public sealed class X509IssuerSerial {
		/// <param name="issuer">An <see cref="X500DistinguishedName"/> object that represents issuer name.</param>
		/// <param name="serialNumber">A string that contains issuer certificate's serial number.</param>
		/// <exception cref="ArgumentNullException">
		///		<strong>issuer</strong> and/or <strong>serialNumber</strong> parameters are null or empty.
		/// </exception>
		public X509IssuerSerial(X500DistinguishedName issuer, String serialNumber) {
			if (issuer == null || issuer.RawData == null) { throw new ArgumentNullException("issuer"); }
			if (String.IsNullOrEmpty(serialNumber)) { throw new ArgumentNullException("serialNumber"); }
			IssuerName = issuer;
			SerialNumber = serialNumber;
		}

		/// <summary>
		/// Gets or sets an X.509 certificate issuer's distinguished name.
		/// </summary>
		public X500DistinguishedName IssuerName { get; set; }
		/// <summary>
		/// Gets an X.509 certificate issuer's distinguished name in a string format.
		/// </summary>
		public String Issuer {
			get {
				return IssuerName == null
					? null
					: IssuerName.Name;
			}
		}
		/// <summary>
		/// Gets or sets an X.509 certificate issuer's serial number.
		/// </summary>
		public String SerialNumber { get; set; }
	}
}
