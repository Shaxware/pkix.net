using System.Collections.Generic;
using SysadminsLV.Asn1Parser;

namespace System.Security.Cryptography.X509Certificates {
	sealed class X500RdnAttribute : AsnEncodedData {
		Asn1Type encodingTag;
		public X500RdnAttribute(Oid oid, String value) {
			Oid = oid;
			Value = value;
			encodingTag = Asn1Type.PrintableString;
		}
		public X500RdnAttribute(Oid oid, String value, Asn1Type encodingTag) {
			Oid = oid;
			Value = value;
		}
		public X500RdnAttribute(Byte[] rawData) {
			if (rawData == null) { throw new ArgumentNullException("rawData"); }
			m_decode(rawData);
		}

		public String Value { get; private set; }

		void m_initizlie(Oid oid, String value, Asn1Type tag) {
			// dc -- IA5 String only
			// E -- IA5String only
			switch (oid.Value) {

			}
		}
		void m_decode(Byte[] rawData) {
			Asn1Reader asn = new Asn1Reader(rawData);
			if (asn.Tag != 48) { throw new Exception(); }
			asn.MoveNext();
			if (asn.Tag != 6) { throw new Exception(); }
			Oid = Asn1Utils.DecodeObjectIdentifier(asn.GetTagRawData());
			asn.MoveNext();
			Value = Asn1Utils.DecodeAnyString(asn.GetTagRawData(), null);
			RawData = rawData;
		}
		void validateTag(Oid oid, Asn1Type tag) {
			List<Asn1Type> tags = new List<Asn1Type> {
				Asn1Type.TeletexString,
				Asn1Type.PrintableString,
				Asn1Type.UniversalString,
				Asn1Type.UTF8String,
				Asn1Type.BMPString,
				Asn1Type.IA5String,
			};
			if (!tags.Contains(tag)) { throw new ArgumentException("Specified ASN.1 tag is not supported."); }
			encodingTag = tag;
		}

		public override String Format(Boolean multiLine) {
			if (RawData == null || RawData.Length == 0) {
				return base.Format(multiLine);	
			}
			String retValue = String.IsNullOrEmpty(Oid.FriendlyName)
				? Oid.Value
				: Oid.FriendlyName;
			retValue += " = " + Value;
			retValue += multiLine
				? Environment.NewLine
				: ";";
			return retValue;
		}
	}
}
