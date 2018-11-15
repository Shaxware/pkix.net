using System;
using System.Collections.Generic;
using System.Linq;
using SysadminsLV.Asn1Parser;
using SysadminsLV.Asn1Parser.Universal;

namespace SysadminsLV.PKI.Cryptography {
    /// <summary>
    /// This class represents an encoded content to be signed and a BLOB to hold the signature.
    /// The <see cref="ToBeSignedData"/> member is an encoded X.509 certificate, certificate revocation list
    /// (<strong>CRL</strong>), certificate trust list (<strong>CTL</strong>) or certificate request.
    /// </summary>
    public class SignedContentBlob {
        ///  <summary>
        ///  Initializes a new instance of the <strong>SignedContentBlob</strong> class from a ASN.1-encoded byte array.
        ///  </summary>
        ///  <param name="rawData">
        /// 		ASN.1-encoded object that represents a <strong>SignedContentInfo</strong> structure.
        ///  </param>
        /// <param name="type">
        ///     Specifies the content type in the <strong>rawData</strong> parameter.
        /// </param>
        public SignedContentBlob(Byte[] rawData, ContentBlobType type) {
            if (rawData == null) {
                throw new ArgumentNullException(nameof(rawData));
            }

            BlobType = type;
            switch (type) {
                case ContentBlobType.SignedBlob:
                    m_decode(rawData);
                    break;
                case ContentBlobType.ToBeSignedBlob:
                    ToBeSignedData = rawData;
                    break;
                default:
                    throw new ArgumentOutOfRangeException(nameof(type), type, null);
            }
        }

        /// <summary>
        /// Gets the current blob type.
        /// </summary>
        public ContentBlobType BlobType { get; private set; }
        /// <summary>
        /// A BLOB that has been encoded by using Distinguished Encoding Rules (DER) and that is to be signed.
        /// </summary>
        public Byte[] ToBeSignedData { get; private set; }
        /// <summary>
        /// An <see cref="AlgorithmIdentifier"/> object that contains the signature algorithm type and
        /// any associated additional parameters.
        /// </summary>
        public AlgorithmIdentifier SignatureAlgorithm { get; private set; }
        /// <summary>
        /// BLOB containing a signed hash of the encoded data.
        /// </summary>
        public Asn1BitString Signature { get; set; }

        internal Byte[] GetRawSignature() {
            if (SignatureAlgorithm.AlgorithmId.FriendlyName.ToUpper().Contains("DSA")) {
                Asn1Reader asn = new Asn1Reader(Signature.Value);
                asn.MoveNext();
                List<Byte> r = asn.GetPayload().ToList();
                if (r[0] == 0) { r.RemoveAt(0); }
                asn.MoveNext();
                List<Byte> s = asn.GetPayload().ToList();
                if (s[0] == 0) { s.RemoveAt(0); }
                var signature = new List<Byte>(r);
                signature.AddRange(s);
                return signature.ToArray();
            }
            return Signature.Value;
        }

        void m_decode(Byte[] rawData) {
            Asn1Reader asn = new Asn1Reader(rawData);
            if (asn.Tag != 48) {
                throw new Asn1InvalidTagException(asn.Offset);
            }
            asn.MoveNextAndExpectTags(0x30);
            ToBeSignedData = asn.GetTagRawData();
            asn.MoveNextCurrentLevelAndExpectTags(0x30);
            SignatureAlgorithm = new AlgorithmIdentifier(asn.GetTagRawData());
            asn.MoveNextCurrentLevelAndExpectTags((Byte)Asn1Type.BIT_STRING);
            Signature = new Asn1BitString(asn);
        }
    }
}
