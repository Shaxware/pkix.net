using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using SysadminsLV.Asn1Parser;

namespace PKI.Utils.CLRExtensions {
	static class X509Extension2 {
		public static Byte[] ExportBinaryData(this X509Extension extension) {
			if (String.IsNullOrEmpty(extension.Oid.Value)) { return null; }
			List<Byte> rawData = new List<Byte>(Asn1Utils.EncodeObjectIdentifier(extension.Oid));
			if (extension.Critical) {
				rawData.AddRange(Asn1Utils.EncodeBoolean(true));
			}
			rawData.AddRange(Asn1Utils.Encode(extension.RawData, (Byte)Asn1Type.OCTET_STRING));
			return Asn1Utils.Encode(rawData.ToArray(), 48);
		}
		public static void Import(this X509Extension extension, Byte[] rawData) {
			//extension.RawData = 
		}
	}
}
