using PKI;
using PKI.ManagedAPI;
using PKI.Structs;
using PKI.Utils;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using SysadminsLV.Asn1Parser;

namespace System.Security.Cryptography.X509CertificateRequests {
	/// <summary>
	/// This class represents single PKCS#10 certificate request.
	/// </summary>
	public class X509CertificateRequest {
		Wincrypt.CERT_REQUEST_INFO reqData;
		Wincrypt.CERT_SIGNED_CONTENT_INFO signedData;
		readonly X509AttributeCollection attribs = new X509AttributeCollection();
		X509ExtensionCollection exts = new X509ExtensionCollection();
		Byte[] signature;
		UInt32 sigUnused;
		UInt32 pubKeyUnused;
		Int32 pubKeyLength;
		Oid curve;

		/// <summary>
		/// Initializes a new instance of the <strong>X509CertificateRequest</strong> class defined from a sequence of bytes
		/// representing certificate request.
		/// </summary>
		/// <param name="rawData">A byte array containing data from a certificate request.</param>
		public X509CertificateRequest(Byte[] rawData) {
			RawData = rawData;
			m_initialize();
		}
		/// <summary>
		/// Initializes a new instance of the <strong>X509CertificateRequest</strong> class defined from a file.
		/// </summary>
		/// <param name="path">The path to a certificate request file.</param>
		public X509CertificateRequest(String path) {
			getBinaryData(path);
			m_initialize();
		}
		
		/// <summary>
		/// Gets the X.509 format version of a certificate request.
		/// </summary>
		/// <remarks>
		/// Currently only version 1 is defined.
		/// </remarks>
		public Int32 Version { get; private set; }
		/// <summary>
		/// Gets request format. Can be either <strong>PKCS10</strong> or <strong>PKCS7</strong>.
		/// </summary>
		public X509CertificateRequestType RequestType { get; private set; }
		/// <summary>
		/// Gets textual form of the distinguished name of the request subject.
		/// </summary>
		public String Subject { get { return SubjectDN.Name; } }
		/// <summary>
		/// Gets the distinguished name of the request subject.
		/// </summary>
		public X500DistinguishedName SubjectDN { get; private set; }
		/// <summary>
		/// Gets a <see cref="PublicKey"/> object associated with a certificate
		/// </summary>
		/// <remarks>
		/// <para>
		/// This property returns a PublicKey object, which contains the object identifier (Oid) representing the public key
		/// algorithm, the ASN.1-encoded parameters, and the ASN.1-encoded key value.</para>
		/// <para>You can also obtain the key as an <see cref="AsymmetricAlgorithm"/> object by referencing the <strong>PublicKey</strong> property.
		/// This property supports only RSA or DSA keys, so it returns either an <see cref="RSACryptoServiceProvider"/> or a
		/// <see cref="DSACryptoServiceProvider"/> object that represents the public key.</para>
		/// </remarks>
		public PublicKey PublicKey { get; private set; }
		/// <summary>
		/// Gets <see cref="X509AttributeCollection"/> object that contains a collection of attributes associated with the
		/// certificate request.
		/// </summary>
		public X509AttributeCollection Attributes {
			get {
				return attribs.Count > 0 ? attribs : null;
			}
		}
		/// <summary>
		/// Gets a collection of <see cref="X509Extension">X509Extension</see> objects.
		/// </summary>
		public X509ExtensionCollection Extensions {
			get {
				return exts.Count > 0 ? exts : null;
			}
		}
		/// <summary>
		/// Gets external PKCS7 envelope. External envelope is aplicable only for PKCS7 requests.
		/// </summary>
		public PKCS7SignedMessage ExternalData { get; private set; }
		/// <summary>
		/// Gets request signature status. Returns <strong>True</strong> if signature is valid, <strong>False</strong> otherwise.
		/// </summary>
		public bool SignatureIsValid { get; private set; }
		/// <summary>
		/// Gets the algorithm used to create the signature of a certificate request.
		/// </summary>
		/// <remarks>The object identifier <see cref="Oid">(Oid)</see> identifies the type of signature
		/// algorithm used by the certificate request.</remarks>
		public Oid SignatureAlgorithm { get; private set; }
		/// <summary>
		/// Gets the raw data of a certificate request.
		/// </summary>
		public Byte[] RawData { get; private set; }

		void getBinaryData(String path) {
			RawData = Crypt32Managed.CryptFileToBinary(path);
		}
		void m_initialize() {
			// at this point RawData is not null
			RequestType = getRequestFormat(RawData);
			switch (RequestType) {
				case X509CertificateRequestType.PKCS10:
					decodePkcs10();
					break;
				case X509CertificateRequestType.PKCS7:
					decodePkcs7();
					break;
				default:
					throw new Win32Exception(Error.InvalidDataException);
			}
		}
		void decodePkcs10() {
			m_decode();
		}
		void decodePkcs7() {
			ExternalData = new PKCS7SignedMessage(RawData);
			Version = ((X509CertificateRequest[])ExternalData.Content)[0].Version;
			SubjectDN = ((X509CertificateRequest[])ExternalData.Content)[0].SubjectDN;
			PublicKey = ((X509CertificateRequest[])ExternalData.Content)[0].PublicKey;
			SignatureIsValid = ((X509CertificateRequest[])ExternalData.Content)[0].SignatureIsValid;
			SignatureAlgorithm = ((X509CertificateRequest[])ExternalData.Content)[0].SignatureAlgorithm;
			foreach (X509Attribute attrib in ((X509CertificateRequest[])ExternalData.Content)[0].Attributes) {
				attribs.Add(attrib);
			}
			foreach (X509Extension ext in ((X509CertificateRequest[])ExternalData.Content)[0].Extensions) {
				exts.Add(ext);
			}
		}
		void m_decode() {
			UInt32 pcbStructInfo = 0;
			if (Crypt32.CryptDecodeObject(65537, Wincrypt.X509_CERT_REQUEST_TO_BE_SIGNED, RawData, (UInt32)RawData.Length, 0, IntPtr.Zero, ref pcbStructInfo)) {
				IntPtr pvStructInfo = Marshal.AllocHGlobal((Int32)pcbStructInfo);
				Crypt32.CryptDecodeObject(65537, Wincrypt.X509_CERT_REQUEST_TO_BE_SIGNED, RawData, (UInt32)RawData.Length, 0, pvStructInfo, ref pcbStructInfo);
				reqData = (Wincrypt.CERT_REQUEST_INFO)Marshal.PtrToStructure(pvStructInfo, typeof(Wincrypt.CERT_REQUEST_INFO));
				Version = (Int32)reqData.dwVersion + 1;
				getSubject();
				getPublickey();
				getAttributes();
				getSignature();
				m_verifysignature();
				Marshal.FreeHGlobal(pvStructInfo);
			} else { throw new Win32Exception(Marshal.GetLastWin32Error()); }
		}
		void getSubject() {
			Byte[] RawBytes = new Byte[reqData.Subject.cbData];
			Marshal.Copy(reqData.Subject.pbData, RawBytes, 0, (Int32)reqData.Subject.cbData);
			SubjectDN = new X500DistinguishedName(RawBytes);
		}
		void getPublickey() {
			Oid keyoid = new Oid(reqData.SubjectPublicKeyInfo.Algorithm.pszObjId);
			pubKeyUnused = reqData.SubjectPublicKeyInfo.PublicKey.cUnusedBits;
			Byte[] param = new Byte[reqData.SubjectPublicKeyInfo.Algorithm.Parameters.cbData];
			Marshal.Copy(reqData.SubjectPublicKeyInfo.Algorithm.Parameters.pbData, param, 0, (Int32)reqData.SubjectPublicKeyInfo.Algorithm.Parameters.cbData);
			Oid paramOid = keyoid.Value == "1.2.840.10045.2.1"
				? Asn1Utils.DecodeObjectIdentifier(param)
				: new Oid("1.2.840.113549.1.1.1");
			AsnEncodedData asnpara = new AsnEncodedData(paramOid, param);
			Byte[] key = new Byte[reqData.SubjectPublicKeyInfo.PublicKey.cbData];
			Marshal.Copy(reqData.SubjectPublicKeyInfo.PublicKey.pbData, key, 0, (Int32)reqData.SubjectPublicKeyInfo.PublicKey.cbData);
			AsnEncodedData asnkey = new AsnEncodedData(keyoid, key);
			PublicKey = new PublicKey(keyoid, asnpara, asnkey);
			curve = PublicKey.EncodedParameters.Oid;
			if (PublicKey.Oid.Value == "1.2.840.10045.2.1") {
				getPublicKeyLength(asnpara.Oid.Value);
			} else {
				pubKeyLength = PublicKey.Key.KeySize;
			}
		}
		void getPublicKeyLength(String oid) {
			switch (oid) {
				case "1.2.840.10045.3.1.7":
					pubKeyLength = 256;
					break;
				case "1.3.132.0.34":
					pubKeyLength = 384;
					break;
				case "1.3.132.0.35":
					pubKeyLength = 521;
					break;
			}
		}
		void getAttributes() {
			if (reqData.cAttribute <= 0) { return; }
			IntPtr rgAttribute = reqData.rgAttribute;
			for (Int32 index = 0; index < reqData.cAttribute; index++) {
				Wincrypt.CRYPT_ATTRIBUTE attrib = (Wincrypt.CRYPT_ATTRIBUTE)Marshal.PtrToStructure(rgAttribute, typeof(Wincrypt.CRYPT_ATTRIBUTE));
				Oid attriboid = new Oid(attrib.pszObjId);
				Wincrypt.CRYPTOAPI_BLOB blob = (Wincrypt.CRYPTOAPI_BLOB)Marshal.PtrToStructure(attrib.rgValue, typeof(Wincrypt.CRYPTOAPI_BLOB));
				Byte[] bytes = new Byte[blob.cbData];
				Marshal.Copy(blob.pbData,bytes,0,(Int32)blob.cbData);
				if (attrib.pszObjId == "1.2.840.113549.1.9.14") {
					getExtensions(bytes);
				} else {
					attribs.Add(new X509Attribute(attriboid, bytes));
				}
				rgAttribute = (IntPtr)((UInt64)rgAttribute + (UInt32)Marshal.SizeOf(typeof(Wincrypt.CRYPT_ATTRIBUTE)));
			}
		}
		void getExtensions(Byte[] bytes) {
			exts = Crypt32Managed.DecodeX509Extensions(bytes);
		}
		void getSignature() {
			UInt32 pcbStructInfo = 0;
			if (!Crypt32.CryptDecodeObject(65537, Wincrypt.X509_CERT, RawData, (UInt32) RawData.Length, 8, IntPtr.Zero, ref pcbStructInfo)) {
				throw new Win32Exception(Marshal.GetLastWin32Error());
			}
			IntPtr pvStructInfo = Marshal.AllocHGlobal((Int32) pcbStructInfo);
			Crypt32.CryptDecodeObject(65537, Wincrypt.X509_CERT, RawData, (UInt32) RawData.Length, 8, pvStructInfo, ref pcbStructInfo);
			signedData = (Wincrypt.CERT_SIGNED_CONTENT_INFO)Marshal.PtrToStructure(pvStructInfo, typeof (Wincrypt.CERT_SIGNED_CONTENT_INFO));
			signature = new Byte[signedData.Signature.cbData];
			Marshal.Copy(signedData.Signature.pbData, signature, 0, (Int32) signedData.Signature.cbData);
			sigUnused = signedData.Signature.cUnusedBits;
			SignatureAlgorithm = new Oid(signedData.SignatureAlgorithm.pszObjId);
			Array.Reverse(signature);
			Marshal.FreeHGlobal(pvStructInfo);
		}
		void m_verifysignature() {
			SignatureIsValid = MessageSignature.VerifySignature(PublicKey, signedData);
		}
		// functions for ToString() method.
		void genPkcs10String(StringBuilder SB) {
			String n = Environment.NewLine;
			SB.Append("PKCS10 Certificate Request:" + n);
			SB.Append("Version: " + Version + n);
			SB.Append("Subject:" + n);
			SB.Append("    " + Subject + n + n);
			SB.Append("Public Key Algorithm: " + n);
			SB.Append("    Algorithm ObjectId: " + PublicKey.Oid.FriendlyName + " (" + PublicKey.Oid.Value + ")" + n);
			SB.Append("    Algorithm Parameters: " + n + "    ");
			String tempString = AsnFormatter.BinaryToString(PublicKey.EncodedParameters.RawData, EncodingType.Hex);
			SB.Append(tempString.Replace("\r\n","\r\n    ").TrimEnd() + n);
			if (PublicKey.Oid.Value == "1.2.840.10045.2.1") {
				SB.Append("        " + curve.FriendlyName + " (" + curve.Value + ")" + n);
			}
			SB.Append("Public Key Length: " + pubKeyLength + " bits" + n);
			SB.Append("Public Key: UnusedBits=" + pubKeyUnused + n + "    ");
			tempString = AsnFormatter.BinaryToString(PublicKey.EncodedKeyValue.RawData, EncodingType.HexAddress);
			SB.Append(tempString.Replace("\r\n", "\r\n    ").TrimEnd() + n);
			SB.Append("Request attributes (Count=" + attribs.Count + "):" + n);
			for (Int32 index = 0; index < attribs.Count; index++) {
				SB.Append("  Attribute[" + index + "], Length=" + attribs[index].RawData.Length + " (" + String.Format("{0:x2}", attribs[index].RawData.Length) + "):" + n);
				SB.Append("    " + attribs[index].Format(true).Replace("\r\n", "\r\n    ").TrimEnd() + n + n);
			}
			SB.Append("Request extensions (Count=" + exts.Count + "):" + n);
			foreach (X509Extension ext in exts) {
				if (String.IsNullOrEmpty(ext.Oid.FriendlyName)) {
					SB.Append("  " + ext.Oid.Value);
				} else {
					SB.Append("  OID=" + ext.Oid.FriendlyName + " (" + ext.Oid.Value + "), ");
				}
				SB.Append("Critical=" + ext.Critical + ", Length=" + ext.RawData.Length + " (" + String.Format("{0:x2}", ext.RawData.Length) + "):" + n);
				SB.Append("    " + ext.Format(true).Replace("\r\n", "\r\n    ").TrimEnd() + n + n);
			}
			SB.Append("Signature Algorithm:" + n);
			SB.Append("    Algorithm ObjectId: " + SignatureAlgorithm.Value + " (" + SignatureAlgorithm.FriendlyName + ")" + n);
			SB.Append("Signature: Unused bits=" + sigUnused + n + "    ");
			tempString = AsnFormatter.BinaryToString(signature, EncodingType.HexAddress);
			SB.Append(tempString.Replace("\r\n", "\r\n    ").TrimEnd() + n);
			SB.Append("Signature matches Public Key: " + SignatureIsValid + n);
		}
		void genPkcs7String(StringBuilder SB) {
			SB.Append(((X509CertificateRequest[])ExternalData.Content)[0]);
		}

		static X509CertificateRequestType getRequestFormat(Byte[] rawData) {
			UInt32 pcbStructInfo = 0;
			if (Crypt32.CryptDecodeObject(65537, Wincrypt.X509_CERT_REQUEST_TO_BE_SIGNED, rawData, (UInt32)rawData.Length, 8, IntPtr.Zero, ref pcbStructInfo)) {
				return X509CertificateRequestType.PKCS10;
			}
			try {
				PKCS7SignedMessage temp = new PKCS7SignedMessage(rawData);
				return temp.Content is X509CertificateRequest[]
					? X509CertificateRequestType.PKCS7
					: X509CertificateRequestType.Invalid;
			} catch {
				return X509CertificateRequestType.Invalid;
			}
		}

		/// <summary>
		/// Gets the textual representation of the certificate request.
		/// </summary>
		/// <returns>Formatted textual representation of the certificate request.</returns>
		/// <remarks>
		/// If the certificate request type is <strong>PKCS#7</strong>, this method returns textual
		/// representation only for embedded <strong>PKCS#10</strong> certificate request. For full
		/// PKCS#7 dump use the <see cref="PKCS7SignedMessage.ToString()">ToString</see> method of the
		/// <see cref="PKCS7SignedMessage"/> class.
		/// </remarks>
		public override string ToString() {
			StringBuilder SB = new StringBuilder();
			switch (RequestType) {
				case X509CertificateRequestType.PKCS10:
					genPkcs10String(SB);
					break;
				case X509CertificateRequestType.PKCS7:
					genPkcs7String(SB);
					break;
				default: return base.ToString();
			}
			return SB.ToString();
		}

		/// <summary>
		/// Gets the certificate request format in the specified file. This method allows to determine whether the
		/// certificate request is encoded in a PKCS#10 (native) or PKCS#7 (enveloped) format.
		/// </summary>
		/// <param name="path">Specifies the path to a file.</param>
		/// <returns>The type of the certificate request in the file.</returns>
		public static X509CertificateRequestType GetRequestFormat(String path) {
			return getRequestFormat(Crypt32Managed.CryptFileToBinary(path));
		}
		/// <summary>
		/// Gets the certificate request format. This method allows to determine whether the
		/// certificate request is encoded in a PKCS#10 (native) or PKCS#7 (enveloped) format.
		/// </summary>
		/// <param name="rawData">ASN.1-encoded byte array that represents certificate request.</param>
		/// <returns>The type of the certificate request in a byte array.</returns>
		public static X509CertificateRequestType GetRequestFormat(Byte[] rawData) {
			return getRequestFormat(rawData);
		}
	}
}
