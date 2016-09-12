using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SysadminsLV.Asn1Parser;

namespace PKI.Utils.CLRExtensions {
	static class X500DistinguishedNameExtensions {
		public static X500RdnAttribute[] GetRdnAttributes(this X500DistinguishedName name) {
			if (name == null) { throw new ArgumentNullException(nameof(name)); }
			if (name.RawData == null || name.RawData.Length == 0) { return null; }
			Asn1Reader asn = new Asn1Reader(name.RawData);
			if (!asn.MoveNext()) { return null; }
			if (asn.NextCurrentLevelOffset == 0) { return null; }
			var retValue = new List<X500RdnAttribute>();
			do {
				Asn1Reader asn2 = new Asn1Reader(asn.GetPayload());
				asn2.MoveNext();
				Oid oid = Asn1Utils.DecodeObjectIdentifier(asn2.GetTagRawData());
				asn2.MoveNext();
				String value = Asn1Utils.DecodeAnyString(asn2.GetTagRawData(), null);
				retValue.Add(new X500RdnAttribute(oid, value));

			} while (asn.MoveNextCurrentLevel());
			return retValue.ToArray();
		}
	}
}
