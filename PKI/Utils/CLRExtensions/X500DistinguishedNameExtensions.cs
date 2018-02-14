using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SysadminsLV.Asn1Parser;

namespace PKI.Utils.CLRExtensions {
	/// <summary>
	/// Contains extension methods for <see cref="X500DistinguishedName"/> class.
	/// </summary>
	public static class X500DistinguishedNameExtensions {
		/// <summary>
		/// Converts an <see cref="X500DistinguishedName"/> instance in to a collection of individual
		/// RDN attributes.
		/// </summary>
		/// <param name="name">Existing instance of <strong>X500DistinguishedName</strong>.</param>
		/// <returns>A collection of RDN attributes.</returns>
		public static X500RdnAttributeCollection GetRdnAttributes(this X500DistinguishedName name) {
			if (name == null) { throw new ArgumentNullException(nameof(name)); }
			if (name.RawData == null || name.RawData.Length == 0) { return null; }
			Asn1Reader asn = new Asn1Reader(name.RawData);
			if (!asn.MoveNext()) { return null; }
			if (asn.NextCurrentLevelOffset == 0) { return null; }
			var retValue = new X500RdnAttributeCollection();
			do {
				if (asn.Tag != 49) { throw new ArgumentException("The data is invalid"); }
				retValue.Add(new X500RdnAttribute(asn.GetPayload()));
			} while (asn.MoveNextCurrentLevel());
			return retValue;
		}
	}
}
