using PKI.Structs;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;

namespace System.Security.Cryptography.Pkcs {
	/// <summary>
	/// The <strong>SubjectIdentifier2</strong> class defines the type of the identifier of a subject, such as
	/// a <see cref="SignerInfo2"/>. The subject can be identified by the certificate issuer and serial number
	/// or the subject key.
	/// </summary>
	/// <remarks>This class is a replacement for for a .NET native <see cref="SubjectIdentifier"/> class.</remarks>
	public sealed class SubjectIdentifier2 {

		internal SubjectIdentifier2(Wincrypt.CERT_ID blob) {
			m_initialize(blob);
		}

		/// <summary>
		/// Gets the type of the of subject identifier. The subject can be identified by the certificate issuer and
		/// serial number or the subject key.
		/// <para>
		/// The following table displays mappings between subject identifier type and object type stored in the
		/// <see cref="Value"/> property:
		/// <list type="table">
		///		<listheader>
		///			<term>Identifier type</term>
		///			<description>Object type</description>
		///		</listheader>
		///		<item>
		///			<term><strong>IssuerAndSerialNumber</strong></term>
		///			<description>An instance of <see cref="X509IssuerSerial"/> class.</description>
		///		</item>
		///		<item>
		///			<term><strong>SubjectKeyIdentifier</strong></term>
		///			<description>
		///				A string that represents subject key identifier value (cryptographic hash calculated
		///				over a public key).
		///			</description>
		///		</item>
		///		<item>
		///			<term><strong>NoSignature</strong></term>
		///			<description>A string that contains hash value of external message.</description>
		///		</item>
		///		<item>
		///			<term><strong>Unknown</strong></term>
		///			<description>NULL.</description>
		///		</item>
		/// </list>
		/// </para>
		/// </summary>
		public SubjectIdentifierType Type { get; private set; }
		/// <summary>
		/// Contains the value of the subject identifier. Object type and it's description depends on <see cref="Type"/>
		/// property value.
		/// <para>
		/// The following table displays mappings between subject identifier type and object type stored in the
		/// property:
		/// <list type="table">
		///		<listheader>
		///			<term>Identifier type</term>
		///			<description>Object type</description>
		///		</listheader>
		///		<item>
		///			<term><strong>IssuerAndSerialNumber</strong></term>
		///			<description>An instance of <see cref="X509IssuerSerial"/> class.</description>
		///		</item>
		///		<item>
		///			<term><strong>SubjectKeyIdentifier</strong></term>
		///			<description>
		///				A string that represents subject key identifier value (cryptographic hash calculated
		///				over a public key).
		///			</description>
		///		</item>
		///		<item>
		///			<term><strong>NoSignature</strong></term>
		///			<description>A string that contains hash value of external message.</description>
		///		</item>
		///		<item>
		///			<term><strong>Unknown</strong></term>
		///			<description>NULL.</description>
		///		</item>
		/// </list>
		/// </para>
		/// </summary>
		public Object Value { get; private set; }

		void m_initialize(Wincrypt.CERT_ID blob) {
			switch (blob.dwIdChoice) {
				case 1:
					Type = SubjectIdentifierType.IssuerAndSerialNumber;
					decodeIssuerSerialNumber(blob.pIdChoice.IssuerSerialNumber);
					break;
				case 2:
					Type = SubjectIdentifierType.SubjectKeyIdentifier;
					decodeKeyId(blob.pIdChoice.KeyId);
					break;
				case 3:
					Type = SubjectIdentifierType.NoSignature;
					decodeHashId(blob.pIdChoice.HashId);
					break;
				default:
					Type = SubjectIdentifierType.Unknown;
					return;
			}
		}
		void decodeIssuerSerialNumber(Wincrypt.CERT_ISSUER_SERIAL_NUMBER blob) {
			if (blob.Issuer.cbData == 0) { return; }
			Byte[] rawBytes = new Byte[blob.Issuer.cbData];
			Marshal.Copy(blob.Issuer.pbData, rawBytes, 0, rawBytes.Length);
			X500DistinguishedName name = new X500DistinguishedName(rawBytes);
			if (blob.SerialNumber.cbData == 0) { return; }
			rawBytes = new Byte[blob.SerialNumber.cbData];
			Marshal.Copy(blob.SerialNumber.pbData, rawBytes, 0, rawBytes.Length);
			Array.Reverse(rawBytes);
			String serial = String.Concat(rawBytes.Select(x => x.ToString("x2")).ToArray());
			Value = new X509IssuerSerial(name, serial);
		}
		void decodeKeyId(Wincrypt.CRYPTOAPI_BLOB blob) {
			if (blob.cbData == 0) { return; }
			Byte[] rawBytes = new Byte[blob.cbData];
			Marshal.Copy(blob.pbData, rawBytes, 0, rawBytes.Length);
			Value = String.Concat(rawBytes.Select(x => x.ToString("X2")).ToArray());
		}
		void decodeHashId(Wincrypt.CRYPTOAPI_BLOB blob) {
			if (blob.cbData == 0) { return; }
			Byte[] rawBytes = new Byte[blob.cbData];
			Marshal.Copy(blob.pbData, rawBytes, 0, rawBytes.Length);
			Value = String.Concat(rawBytes.Select(x => x.ToString("X2")).ToArray());
		}
	}
}
