using PKI;
using PKI.Structs;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace System.Security.Cryptography.Pkcs {
	/// <summary>
	/// The <strong>SignerInfo2</strong> class represents a signer associated with a SignedCms object that represents
	/// a CMS/PKCS #7 message.
	/// </summary>
	/// <remarks>This class is a replacement for a .NET <see cref="SignerInfo"/> class.</remarks>
	[SecurityCritical]
	public sealed class SignerInfo2 {
		///  <summary>
		/// 		Initializes a new instance of the <strong>SignerInfo2</strong> class from a ASN.1-encoded byte array.
		///  </summary>
		///  <param name="rawData">ASN.1-encoded byte array that represents current object.</param>
		/// <exception cref="ArgumentNullException"><strong>rawData</strong> is null or empty array.</exception>
		public SignerInfo2(Byte[] rawData) {
			if (rawData == null) { throw new ArgumentNullException("rawData"); }
			m_initialize(rawData);
		}
		///  <summary>
		/// 		Initializes a new instance of the <strong>SignerInfo2</strong> class from a ASN.1-encoded byte array
		/// 		and certificate collection (chain) associated with a signer.
		///  </summary>
		///  <param name="rawData">ASN.1-encoded byte array that represents current object.</param>
		///  <param name="certs">
		/// 		A collection of certificates that contains signer certificate and chain certificates.
		///  </param>
		/// <exception cref="ArgumentNullException"><strong>rawData</strong> is null or empty array.</exception>
		public SignerInfo2(Byte[] rawData, X509Certificate2Collection certs) {
			if (rawData == null) { throw new ArgumentNullException("rawData"); }
			m_initialize(rawData);
			if (certs == null || certs.Count == 0) { return; }
			X509Certificate2Collection finds;
			switch (Issuer.Type) {
				case SubjectIdentifierType.IssuerAndSerialNumber:
					finds = certs.Find(X509FindType.FindBySerialNumber, ((X509IssuerSerial)Issuer.Value).SerialNumber, false);
					if (finds.Count == 0) { return; }
					Certificate = finds[0];
					break;
				case SubjectIdentifierType.SubjectKeyIdentifier:
					finds = certs.Find(X509FindType.FindBySubjectKeyIdentifier, Issuer.Value, false);
					if (finds.Count == 0) { return; }
					Certificate = finds[0];
					break;
			}
		}

		/// <summary>
		///		Gets the signer information version.
		/// </summary>
		/// <remarks>
		///		The version determines whether the message is a PKCS #7 message or a Cryptographic Message Syntax (CMS)
		///		message. CMS is a newer superset of PKCS #7.
		/// </remarks>
		public Int32 Version { get; private set; }
		/// <summary>
		///		Gets the certificate identifier of the signer associated with the signer information.
		/// </summary>
		public SubjectIdentifier2 Issuer { get; private set; }
		/// <summary>
		///		Gets the signing certificate associated with the signer information.
		/// </summary>
		public X509Certificate2 Certificate { get; private set; }
		/// <summary>
		///		Gets the <see cref="Oid"/> object that represents the hash algorithm used in the computation of the signatures.
		/// </summary>
		public Oid HashAlgorithm { get; private set; }
		/// <summary>
		///		Gets the <see cref="Oid"/> object that represents the hash algorithm used in the computation of the
		///		encrypted hash.
		/// </summary>
		public Oid EncryptedHashAlgorithm { get; private set; }
		/// <summary>
		///		Gets the raw encrypted hash.
		/// </summary>
		public Byte[] EncryptedHash { get; private set; }
		/// <summary>
		///		Gets the <see cref="X509AttributeCollection"/> collection of signed attributes that is associated with
		///		the signer information. Signed attributes are signed along with the rest of the message content.
		/// </summary>
		public X509AttributeCollection AuthenticatedAttributes { get; private set; }
		/// <summary>
		///		Gets the <see cref="X509AttributeCollection"/> collection of unsigned attributes that is associated with
		///		the <see cref="SignerInfo2"/> content. Unsigned attributes can be modified without invalidating the
		///		signature.
		/// </summary>
		public X509AttributeCollection UnauthenticatedAttributes { get; private set; }


		void m_initialize(Byte[] rawData) {
			UInt32 pcbStructInfo = 0;
			if (!Crypt32.CryptDecodeObject(1, Wincrypt.CMS_SIGNER_INFO, rawData, (UInt32)rawData.Length, 0, IntPtr.Zero, ref pcbStructInfo)) {
				return;
			}
			IntPtr pvStructInfo = Marshal.AllocHGlobal((Int32)pcbStructInfo);
			Crypt32.CryptDecodeObject(1, Wincrypt.CMS_SIGNER_INFO, rawData, (UInt32)rawData.Length, 0, pvStructInfo, ref pcbStructInfo);
			try {
				Wincrypt.CMSG_CMS_SIGNER_INFO info = (Wincrypt.CMSG_CMS_SIGNER_INFO)Marshal.PtrToStructure(pvStructInfo, typeof(Wincrypt.CMSG_CMS_SIGNER_INFO));
				Version = (Int32)info.dwVersion;
				decodeSubject(info.SignerId);
				decodeHashAlg(info.HashAlgorithm);
				decodeEncryptedHashAlg(info.HashEncryptionAlgorithm);
				decodeEncryptedHash(info.EncryptedHash);
				decodeAuthAttr(info.AuthAttrs);
				decodeUnauthAttr(info.UnauthAttrs);
			} finally {
				Marshal.FreeHGlobal(pvStructInfo);
			}
		}

		void decodeSubject(Wincrypt.CERT_ID issuer) {
			Issuer = new SubjectIdentifier2(issuer);
		}
		void decodeHashAlg(Wincrypt.CRYPT_ALGORITHM_IDENTIFIER blob) {
			HashAlgorithm = new Oid(blob.pszObjId);
		}
		void decodeEncryptedHashAlg(Wincrypt.CRYPT_ALGORITHM_IDENTIFIER blob) {
			EncryptedHashAlgorithm = new Oid(blob.pszObjId);
		}
		void decodeEncryptedHash(Wincrypt.CRYPTOAPI_BLOB blob) {
			if (blob.cbData == 0) { return; }
			EncryptedHash = new Byte[blob.cbData];
			Marshal.Copy(blob.pbData, EncryptedHash, 0, EncryptedHash.Length);
		}
		void decodeAuthAttr(Wincrypt.CRYPT_ATTRIBUTES authAttrs) {
			if (authAttrs.cAttr == 0) { return; }
			IntPtr rgValue = authAttrs.rgAttr;
			Int32 size = Marshal.SizeOf(typeof(Wincrypt.CRYPT_ATTRIBUTE));
			AuthenticatedAttributes = new X509AttributeCollection();
			for (Int32 index = 0; index < authAttrs.cAttr; index++) {
				Wincrypt.CRYPT_ATTRIBUTE attr = (Wincrypt.CRYPT_ATTRIBUTE)Marshal.PtrToStructure(rgValue, typeof(Wincrypt.CRYPT_ATTRIBUTE));
				AuthenticatedAttributes.Add(new X509Attribute(attr));
				rgValue += size;
			}
		}
		void decodeUnauthAttr(Wincrypt.CRYPT_ATTRIBUTES unauthAttrs) {
			if (unauthAttrs.cAttr == 0) { return; }
			IntPtr rgValue = unauthAttrs.rgAttr;
			Int32 size = Marshal.SizeOf(typeof(Wincrypt.CRYPT_ATTRIBUTE));
			UnauthenticatedAttributes = new X509AttributeCollection();
			for (Int32 index = 0; index < unauthAttrs.cAttr; index++) {
				Wincrypt.CRYPT_ATTRIBUTE attr = (Wincrypt.CRYPT_ATTRIBUTE)Marshal.PtrToStructure(rgValue, typeof(Wincrypt.CRYPT_ATTRIBUTE));
				UnauthenticatedAttributes.Add(new X509Attribute(attr));
				rgValue += size;
			}
		}

		/// <summary>
		/// Returns a string that represents the current object.
		/// </summary>
		/// <returns>A string that represents the current object.</returns>
		public override String ToString() {
			StringBuilder SB = new StringBuilder();
			return base.ToString();
		}
	}
}
