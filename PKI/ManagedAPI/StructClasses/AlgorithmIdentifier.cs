using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using SysadminsLV.Asn1Parser;

namespace PKI.ManagedAPI.StructClasses {
	/// <summary>
	/// Specifies an algorithm used to encrypt or sign data. This class includes the object identifier
	/// (<strong>OID</strong>) of the algorithm and any needed parameters for that algorithm. 
	/// </summary>
	/// <remarks>This class do not support PKCS#2.1 signature format.</remarks>
	public class AlgorithmIdentifier {
		/// <summary>
		/// Initializes a new instance of the <strong>AlgorithmIdentifier</strong> class from a ASN.1-encoded
		/// byte array that represents an <strong>AlgorithmIdentifier</strong> structure.
		/// </summary>
		/// <param name="rawData">ASN.1-encoded byte array.</param>
		public AlgorithmIdentifier(Byte[] rawData) {
			if (rawData == null) {
				throw new ArgumentNullException("rawData");
			}
			m_decode(rawData);
		}
		/// <summary>
		/// Initializes a new instance of the <strong>AlgorithmIdentifier</strong> class from an algorithm
		/// object identifier without parameters.
		/// </summary>
		/// <param name="oid">Algorithm object identifier.</param>
		public AlgorithmIdentifier(Oid oid) : this(oid, new Byte[] { }) { }
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
			if (oid == null) { throw new ArgumentNullException("oid"); }
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
			Parameters = asn.MoveNext() ? asn.GetTagRawData() : Asn1Utils.EncodeNull();
			
			RawData = rawData;
		}
		void m_encode(Oid oid, Byte[] parameters) {
			Parameters = parameters == null || parameters.Length == 0
				? Asn1Utils.EncodeNull()
				: parameters;
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
			String n = Environment.NewLine;
			if (RawData == null) { return String.Empty; }
			String retValue = "Algorithm Data:" + n + "    Algorithm Identifier: ";
			retValue += String.IsNullOrEmpty(AlgorithmId.FriendlyName)
				? AlgorithmId.Value + n + "    "
				: String.Format("{0} ({1}){2}    ", AlgorithmId.FriendlyName, AlgorithmId.Value, n);
			retValue += "Algorithm Parameters:" + n + "    ";
			retValue += AsnFormatter.BinaryToString(Parameters, EncodingType.Hex)
				.Replace("\r\n", "\r\n    ")
				.TrimEnd();
			return retValue;
		}
	}
}
