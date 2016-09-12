using System;
using SysadminsLV.Asn1Parser;
using SysadminsLV.Asn1Parser.Universal;

namespace PKI.ManagedAPI.StructClasses {
	/// <summary>
	/// This class represents an encoded content to be signed and a BLOB to hold the signature.
	/// The <see cref="ToBeSignedData"/> member is an encoded X.509 certificate, certificate revocation list
	/// (<strong>CRL</strong>), certificate trust list (<strong>CTL</strong>) or certificate request.
	/// </summary>
	public class SignedContentBlob {

		/// <summary>
		/// Initializes a new instance of the <strong>SignedContentBlob</strong> class from a ASN.1-encoded byte array.
		/// </summary>
		/// <param name="rawData">
		///		ASN.1-encoded object that represents a <strong>SignedContentInfo</strong> structure.
		/// </param>
		public SignedContentBlob(Byte[] rawData) {
			if (rawData == null) {
				throw new ArgumentNullException(nameof(rawData));
			}
			m_decode(rawData);
		}

		/// <summary>
		/// A BLOB that has been encoded by using Distinguished Encoding Rules (DER) and that is to be signed.
		/// </summary>
		public Byte[] ToBeSignedData { get; set; }
		/// <summary>
		/// An <see cref="AlgorithmIdentifier"/> object that contains the signature algorithm type and
		/// any associated additional parameters.
		/// </summary>
		public AlgorithmIdentifier SignatureAlgorithm { get; private set; }
		/// <summary>
		/// BLOB containing a signed hash of the encoded data.
		/// </summary>
		public Asn1BitString Signature { get; set; }

		void m_decode(Byte[] rawData) {
			Asn1Reader asn = new Asn1Reader(rawData);
			if (asn.Tag != 48) {
				throw new ArgumentException("The data is invalid");
			}
			if (!asn.MoveNext()) {
				throw new ArgumentException("The data is invalid");
			}
			ToBeSignedData = asn.GetTagRawData();
			if (!asn.MoveNextCurrentLevel()) {
				throw new ArgumentException("The data is invalid");
			}
			SignatureAlgorithm = new AlgorithmIdentifier(asn.GetTagRawData());
			if (!asn.MoveNextCurrentLevel()) {
				throw new ArgumentException("The data is invalid");
			}
			Signature = new Asn1BitString(asn);
		}
	}
}
