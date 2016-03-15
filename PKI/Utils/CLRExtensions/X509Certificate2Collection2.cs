using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using SysadminsLV.Asn1Parser;

namespace PKI.Utils.CLRExtensions {
	static class X509Certificate2Collection2 {
		public static Byte[] Encode(this X509Certificate2Collection collection, Byte enclosingByte = 48) {
			if (collection.Count == 0) { return null; }
			List<Byte> rawData = new List<Byte>();
			foreach (X509Certificate2 cert in collection) {
				rawData.AddRange(cert.RawData);
			}
			return Asn1Utils.Encode(rawData.ToArray(), enclosingByte);
		}
	}
}
