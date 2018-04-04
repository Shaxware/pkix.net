using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using PKI.Utils.CLRExtensions;
using SysadminsLV.Asn1Parser;

namespace SysadminsLV.PKI.Cryptography {
    /// <summary>
    /// Specifies an algorithm used to encrypt or sign data. This class includes the object identifier
    /// (<strong>OID</strong>) of the algorithm and any needed parameters for that algorithm. 
    /// </summary>
    /// <remarks>This class supports PKCS#2.1 signature format.</remarks>
    public class AlgorithmIdentifier {
        /// <summary>
        /// Initializes a new instance of the <strong>AlgorithmIdentifier</strong> class from a ASN.1-encoded
        /// byte array that represents an <strong>AlgorithmIdentifier</strong> structure.
        /// </summary>
        /// <param name="rawData">ASN.1-encoded byte array.</param>
        public AlgorithmIdentifier(Byte[] rawData) {
            if (rawData == null) {
                throw new ArgumentNullException(nameof(rawData));
            }
            m_decode(rawData);
        }
        /// <summary>
        /// Initializes a new instance of the <strong>AlgorithmIdentifier</strong> class from an algorithm
        /// object identifier without parameters.
        /// </summary>
        /// <param name="oid">Algorithm object identifier.</param>
        public AlgorithmIdentifier(Oid oid) : this(oid, null) { }
        /// <summary>
        /// Initializes a new instance of the <strong>AlgorithmIdentifier</strong> class from an algorithm
        /// object identifier and, optionally, algorithm parameters.
        /// </summary>
        /// <param name="oid">Algorithm object identifier.</param>
        /// <param name="parameters">
        ///		A ASN.1-encoded byte array that represents algorithm parameters.
        /// 
        ///		This parameter can be <strong>NULL</strong>.
        /// </param>
        public AlgorithmIdentifier(Oid oid, Byte[] parameters) {
            if (oid == null) { throw new ArgumentNullException(nameof(oid)); }
            if (String.IsNullOrEmpty(oid.Value)) { throw new ArgumentException("Object identifier is empty"); }
            m_encode(oid, parameters);
        }

        /// <summary>
        /// Gets an object identifier of an algorithm.
        /// </summary>
        public Oid AlgorithmId { get; private set; }
        /// <summary>
        /// Gets a byte array that provides encoded algorithm-specific parameters. In many cases, there are no
        /// parameters.
        /// </summary>
        public Byte[] Parameters { get; private set; }
        /// <summary>
        /// Gets algorithm identifier ASN.1-encoded byte array.
        /// </summary>
        public Byte[] RawData { get; private set; }

        void m_decode(Byte[] rawData) {
            Asn1Reader asn = new Asn1Reader(rawData);
            if (asn.Tag != 48) { throw new Asn1InvalidTagException(asn.Offset); }
            if (!asn.MoveNext()) { throw new Asn1InvalidTagException(asn.Offset); }
            if (asn.Tag != (Byte)Asn1Type.OBJECT_IDENTIFIER) { throw new Asn1InvalidTagException(asn.Offset); }
            AlgorithmId = Asn1Utils.DecodeObjectIdentifier(asn.GetTagRawData());
            //Oid2 oid2 = new Oid2(oid.Value, OidGroupEnum.SignatureAlgorithm, false);
            //AlgorithmId = String.IsNullOrEmpty(oid2.Value)
            //	? oid
            //	: new Oid(oid2.Value, oid2.FriendlyName);
            Parameters = asn.MoveNext() ? asn.GetTagRawData() : null;

            RawData = rawData;
        }
        void m_encode(Oid oid, Byte[] parameters) {
            Parameters = parameters;
            AlgorithmId = oid;
            List<Byte> rawBytes = new List<Byte>(Asn1Utils.EncodeObjectIdentifier(oid));
            rawBytes.AddRange(Parameters);
            RawData = Asn1Utils.Encode(rawBytes.ToArray(), 48);
        }

        /// <summary>
        /// Formats a current object to string.
        /// </summary>
        /// <returns>Formatted string.</returns>
        public override String ToString() {
            if (RawData == null) { return String.Empty; }
            StringBuilder sb = new StringBuilder();
            StringBuilder algParamString = new StringBuilder();
            if (Parameters == null) {
                algParamString.Append(" NULL");
            } else {
                algParamString.AppendLine("    ");
                EncodingType format = EncodingType.Hex;
                if (Parameters.Length > 16) {
                    format = EncodingType.HexAddress;
                }
                algParamString.Append(AsnFormatter.BinaryToString(Parameters, format).TrimEnd());
            }
            sb.Append(
                // TODO: algorithm identifier is more than signature algorithm identifier, it is commonly used
                // TODO: structure type in X.509 and PKCS world
                $@"Signature Algorithm:
    Algorithm ObjectId: {AlgorithmId.Format(true)}
    Algorithm Parameters:{algParamString}
");
            return sb.ToString();
        }
    }
}
