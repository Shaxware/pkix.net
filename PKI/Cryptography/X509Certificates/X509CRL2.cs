using System.Numerics;
using PKI;
using PKI.Exceptions;
using PKI.ManagedAPI;
using PKI.ManagedAPI.StructClasses;
using PKI.Utils;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Permissions;
using System.Text;
using PKI.Structs;
using PKI.Utils.CLRExtensions;
using SysadminsLV.Asn1Parser;
using SysadminsLV.Asn1Parser.Universal;

namespace System.Security.Cryptography.X509Certificates {
	/// <summary>
	/// Provides methods that help you use X.509 certificate revocation lists (CRL).
	/// </summary>
	//[SerializableAttribute]
	public class X509CRL2 : IDisposable {
		Int32 sigUnused;
		Byte[] signature;
		Boolean isReadOnly;
		const String BaseCRL = "Base CRL";
		const String DeltaCRL = "Delta CRL";
		//readonly List<X509Extension> _listExtensions = new List<X509Extension>();
		//readonly List<X509CRLEntry> _listEntries = new List<X509CRLEntry>();

		/// <summary>
		/// Initializes a new instance of the <see cref="X509CRL2"/> class. 
		/// </summary>
		public X509CRL2() {
			Version = 1;
			Type = BaseCRL;
			ThisUpdate = DateTime.Now;
			isReadOnly = false;
		}
		/// <summary>
		/// Initializes a new instance of the <see cref="X509CRL2"/> class using the path to a CRL file. 
		/// </summary>
		/// <param name="path">The path to a CRL file.</param>
		public X509CRL2(String path) {
			m_import(Crypt32Managed.CryptFileToBinary(path));
			isReadOnly = true;
		}
		/// <summary>
		/// Initializes a new instance of the <see cref="X509CRL2"/> class defined from a sequence of bytes representing
		/// an X.509 certificate revocation list.
		/// </summary>
		/// <param name="rawData">A byte array containing data from an X.509 CRL.</param>
		/// <exception cref="ArgumentNullException"></exception>
		public X509CRL2(Byte[] rawData) {
			if (rawData == null) { throw new ArgumentNullException(nameof(rawData)); }
			m_import(rawData);
			isReadOnly = true;
		}

		/// <summary>
		/// Gets the X.509 format version of a certificate revocation list.
		/// </summary>
		/// <remarks>There are several versions of X.509 CRLs. This property identifies which format the certificate
		/// revocation list uses. For example, "2" is returned for a version 2 certificate revocation list.
		/// <p>RFC5280 defines only 2 versions: v1 and v2.</p></remarks>
		public Int32 Version { get; private set; }
		/// <summary>
		/// Gets the type of a certificate revocation list. Value can be either <strong>Base CRL</strong> or <strong>Delta CRL</strong>.
		/// </summary>
		/// <remarks><p><strong>Base CRL</strong> includes revocation information about all certificates revoked during entire CA lifetime.</p>
		/// <p><strong>Delta CRL</strong> includes revocation information about certificates revoked only since the last Base CRL was issued.</p></remarks>
		public String Type { get; private set; }
		/// <summary>
		/// Gets the distinguished name of the CRL issuer.
		/// </summary>
		/// <remarks>This property contains the name of the certificate authority (CA) that issued the CRL. To obtain the
		/// name of the issuer, use the GetNameInfo method. The distinguished name for the CRL is a textual
		/// representation of the CRL issuer. This representation consists of name attributes (for example,
		/// "CN=MyName, OU=MyOrgUnit, C=US").</remarks>
		public X500DistinguishedName IssuerName { get; private set; }
		/// <summary>
		/// Gets the textual representation of the CRL issuer (in X.500 name format).
		/// </summary>
		/// <remarks>This property contains the name of the certificate authority (CA) that issued the CRL.
		/// The distinguished name for the certificate is a textual representation of the CRL issuer. This representation
		/// consists of name attributes (for example, "CN=MyName, OU=MyOrgUnit, C=US").</remarks>
		public String Issuer => IssuerName.Name;

		/// <summary>
		/// Gets the issue date of this CRL.
		/// </summary>
		public DateTime ThisUpdate { get; private set; }
		/// <summary>
		/// Gets the date by which the next CRL will be issued. The next CRL could be issued before the indicated date, but it will
		/// not be issued any later than the indicated date.
		/// </summary>
		/// <remarks>CRL issuers SHOULD issue CRLs with a NextUpdate time equal to or later than all previous CRLs.</remarks>
		public DateTime? NextUpdate { get; private set; }
		/// <summary>
		/// Gets the algorithm used to create the signature of a CRL.
		/// </summary>
		/// <remarks>The object identifier <see cref="Oid">(Oid)</see> identifies the type of signature
		/// algorithm used by the CRL.</remarks>
		public Oid SignatureAlgorithm { get; private set; }
		/// <summary>
		/// Gets a collection of <see cref="X509Extension">X509Extension</see> objects.
		/// </summary>
		/// <remarks><p>Version 1 CRLs do not support extensions and this property is always empty for them.</p>
		/// <p>The extensions defined in the X.509 v2 CRL format allow additional data to be included 
		/// in the CRL. A number of extensions are defined by ISO in the X.509 v3 definition as well 
		/// as by PKIX in RFC 5280, "Certificate and Certificate Revocation List (CRL) Profile." 
		/// Common extensions include information regarding key identifiers (X509AuthorityKeyIdentifierExtension),
		/// CRL sequence numbers, additional revocation information (Delta CRL Locations), and other uses.</p>
		/// </remarks>
		public X509ExtensionCollection Extensions { get; private set; }
		/// <summary>
		/// Gets a collection of <see cref="X509CRLEntry">X509CRLEntry</see> objects.
		/// </summary>
		/// <remarks><see cref="X509CRLEntry"/> object represents a CRL entry.
		/// Each entry contains at least the following information: <see cref="X509CRLEntry.SerialNumber">SerialNumber</see>
		/// of revoked certificate and <see cref="X509CRLEntry.RevocationDate">RevocationDate</see> that represents a date
		/// and time at which certificate was revoked. Additionaly, revocation entry may contain additional information,
		/// such revocation reason.</remarks>
		public X509CRLEntryCollection RevokedCertificates { get; private set; }
		/// <summary>
		/// Gets the raw data of a certificate revocation list.
		/// </summary>
		public Byte[] RawData { get; private set; }
		/// <summary>
		/// Gets a handle to a Microsoft Cryptographic API CRL context described by an unmanaged
		/// <strong>CRL_CONTEXT</strong> structure.
		/// </summary>
		/// <remarks>
		///	This member is zero by default. In order, to retrieve unmanaged handle a <see cref="GetSafeContext"/>
		/// method must be called. When this handle is no longer necessary, it must be freed by calling
		/// <see cref="ReleaseContext"/> method.
		/// </remarks>
		public IntPtr Handle { get; private set; }

		void m_decode(Byte[] rawData) {
			try {
				Type = BaseCRL;
				var signedInfo = new SignedContentBlob(rawData);
				// signature and alg
				signature = signedInfo.Signature.Value;
				sigUnused = signedInfo.Signature.UnusedBits;
				SignatureAlgorithm = signedInfo.SignatureAlgorithm.AlgorithmId;
				// tbs
				Asn1Reader asn = new Asn1Reader(signedInfo.ToBeSignedData);
				if (!asn.MoveNext()) { throw new Asn1InvalidTagException(); }
				// version
				if (asn.Tag == (Byte)Asn1Type.INTEGER) {
					Version = (Int32)Asn1Utils.DecodeInteger(asn.GetTagRawData()) + 1;
					asn.MoveNextCurrentLevel();
				} else {
					Version = 1;
				}
				// hash algorithm
				var h = new AlgorithmIdentifier(asn.GetTagRawData());
				if (h.AlgorithmId.Value != SignatureAlgorithm.Value) {
					throw new CryptographicException("Algorithm mismatch.");
				}
				if (!asn.MoveNextCurrentLevel()) { throw new Asn1InvalidTagException(); }
				// issuer
				IssuerName = new X500DistinguishedName(asn.GetTagRawData());
				// NextUpdate, RevokedCerts and Extensions are optional. Ref: RFC5280, p.118
				if (!asn.MoveNextCurrentLevel()) { throw new Asn1InvalidTagException(); }
				switch (asn.Tag) {
					case (Byte)Asn1Type.UTCTime:
						ThisUpdate = Asn1Utils.DecodeUTCTime(asn.GetTagRawData());
						break;
					case (Byte)Asn1Type.Generalizedtime:
						ThisUpdate = Asn1Utils.DecodeGeneralizedTime(asn.GetTagRawData());
						break;
					default:
						throw new Asn1InvalidTagException();
				}
				if (!asn.MoveNextCurrentLevel()) { return; }
				switch (asn.Tag) {
					case (Byte)Asn1Type.UTCTime:
					case (Byte)Asn1Type.Generalizedtime:
						switch (asn.Tag) {
							case (Byte)Asn1Type.UTCTime:
								NextUpdate = Asn1Utils.DecodeUTCTime(asn.GetTagRawData());
								break;
							case (Byte)Asn1Type.Generalizedtime:
								NextUpdate = Asn1Utils.DecodeGeneralizedTime(asn.GetTagRawData());
								break;
							default:
								throw new Asn1InvalidTagException();
						}
						if (!asn.MoveNextCurrentLevel()) { return; }
						if (asn.Tag == 48) {
							getRevCerts(asn);
							if (!asn.MoveNextCurrentLevel()) { return; }
							getExts(asn);
						} else {
							getExts(asn);
						}
						break;
					case 48:
						if (asn.Tag == 48) {
							getRevCerts(asn);
							if (!asn.MoveNextCurrentLevel()) { return; }
							getExts(asn);
						} else {
							getExts(asn);
						}
						break;
					default:
						getExts(asn);
						break;
				}
			} catch (Exception e) {
				throw new CryptographicException("Cannot find the requested object.", e);
			}
		}
		void getRevCerts(Asn1Reader asn) {
			RevokedCertificates = new X509CRLEntryCollection();
			RevokedCertificates.Decode(asn.GetTagRawData());
			RevokedCertificates.Close();
		}
		void getExts(Asn1Reader asn) {
			Extensions = Crypt32Managed.DecodeX509Extensions(asn.GetPayload());
			foreach (X509Extension ext in Extensions.Cast<X509Extension>().Where(ext => ext.Oid.Value == "2.5.29.27")) {
				Type = DeltaCRL;
			}
		}
		void getHandle() {
			if (RawData == null) { return; }
			Handle = Crypt32.CertCreateCRLContext(65537, RawData, (UInt32)RawData.Length);
			if (IntPtr.Zero.Equals(Handle)) {
				throw new CryptographicException(Marshal.GetLastWin32Error());
			}
		}
		void m_import(Byte[] rawData) {
			Reset();
			m_decode(rawData);
			RawData = rawData;
		}
		void genExts(X509Certificate2 issuer) {
			if (Extensions == null) { Extensions = new X509ExtensionCollection();}
			Extensions.Remove(X509CertExtensions.X509AuthorityKeyIdentifier);
			Extensions.Remove(X509CertExtensions.X509CAVersion);
			// AKI generation
			Extensions.Add(new X509AuthorityKeyIdentifierExtension(issuer, AuthorityKeyIdentifierFlags.KeyIdentifier, false));
			// CA Version copy
			X509Extension e = issuer.Extensions[X509CertExtensions.X509CAVersion];
			if (e != null) {
				Extensions.Add(e);
			}
		}
		void genBriefString(StringBuilder SB) {
			String n = Environment.NewLine;
			SB.Append($"[Type]{n}  {Type}{n}{n}");
			SB.Append($"[Issuer]{n}  {Issuer}{n}{n}");
			SB.Append($"[This Update]{n}  {ThisUpdate}{n}{n}");
			SB.Append($"[Next Update]{n}  ");
			if (NextUpdate == null) {
				SB.Append("Infinity");
			} else {
				SB.Append(NextUpdate);
			}
			SB.Append($"{n}{n}[Revoked Certificate Count]{n}  ");
			if (RevokedCertificates == null) {
				SB.Append("0");
			} else {
				SB.Append(RevokedCertificates.Count);	
			}
			SB.Append(n + n);
		}
		void genVerboseString(StringBuilder SB) {
			String n = Environment.NewLine;
			SB.Append($"X509 Certificate Revocation List:{n}");
			SB.Append($"Version: {Version}{n}");
			SB.Append($"Issuer: {n}");
			String[] tokens = Issuer.Split(new[] { ',' }, StringSplitOptions.RemoveEmptyEntries);
			for (Int32 index = 0; index < tokens.Length; index++) {
				tokens[index] = "    " + tokens[index].Trim();
			}
			SB.Append(String.Join(n, tokens) + n);
			SB.Append($"This Update: {ThisUpdate}{n}");
			if (NextUpdate == null) {
				SB.Append($"Next Update: Infinity{n}");
			} else {
				SB.Append($"Next Update: {NextUpdate}{n}");
			}
			if (RevokedCertificates == null) {
				SB.Append($"CRL Entries: 0{n}");
			} else {
				SB.Append($"CRL Entries: {RevokedCertificates.Count}{n}");
				foreach (X509CRLEntry revcert in RevokedCertificates) {
					SB.Append($"    Serial Number: {revcert.SerialNumber}{n}");
					SB.Append($"    Revocation Date: {revcert.RevocationDate}{n}");
					if (revcert.ReasonCode != 0) {
						SB.Append($"    Revocation Reason: {revcert.ReasonMessage} ({revcert.ReasonCode}){n}");
					}
					SB.Append(n);
				}
			}
			if (Extensions == null) {
				SB.Append($"CRL Extensions: 0{n}");
			} else {
				SB.Append($"CRL Extensions: {Extensions.Count}{n}");
				foreach (X509Extension ext in Extensions) {
					SB.Append($"  OID={ext.Oid.Format(true)}");
					SB.Append($"Critical={ext.Critical}, Length={ext.RawData.Length} ({ext.RawData.Length:x2}):{n}");
					SB.Append($"    {ext.Format(true).Replace(n, $"{n}    ").TrimEnd()}{n}{n}");
				}
			}
			SB.Append("Signature Algorithm:" + n);
			SB.Append($"    Algorithm ObjectId: {SignatureAlgorithm.Format(true)}{n}");
			SB.Append($"Signature: Unused bits={sigUnused}{n}    ");
			String tempString = AsnFormatter.BinaryToString(signature, EncodingType.HexAddress);
			SB.Append($"{tempString.Replace(n, $"{n}    ").TrimEnd()}{n}");
		}
		internal static X509CRL2 CreateLocalRevocationInformation(X509Certificate2 issuer) {
			if (issuer == null) { throw new ArgumentNullException(nameof(issuer)); }
			if (issuer.Handle.Equals(IntPtr.Zero)) { throw new UninitializedObjectException(); }
			Oid hashAlgorithm = new Oid(issuer.SignatureAlgorithm.FriendlyName.Replace("RSA", null));
			String[] algs = {
				                "1.2.840.113549.2.5", "1.3.14.3.2.26", "2.16.840.1.101.3.4.2.1",
				                "2.16.840.1.101.3.4.2.2", "2.16.840.1.101.3.4.2.1"
			                };
			Boolean found = Array.Exists(algs, s => s.ToLower().Contains(hashAlgorithm.Value));
			if (!found) {
				throw new ArgumentException("Invalid hash algorithm. The valid algorithms are: md5, sha1, sha256, sha384, sha512.");
			}
			List<Byte> tbsData = new List<Byte>();
			List<Byte> algid = new List<Byte>();
			algid.AddRange(Asn1Utils.EncodeObjectIdentifier(hashAlgorithm));
			algid.AddRange(Asn1Utils.EncodeNull());
			tbsData.AddRange(Asn1Utils.Encode(algid.ToArray(), 48));
			tbsData.AddRange(issuer.SubjectName.RawData);
			// dates prior to 2050 year are encoded as UTC Time and after 2050 are encoded as Generalized Time. See RFC5280.
			tbsData.AddRange(issuer.NotBefore.Year <= 2049
				? new Asn1UtcTime(issuer.NotBefore, false).RawData
				: new Asn1GeneralizedTime(issuer.NotBefore, false).RawData);
			tbsData.AddRange(issuer.NotAfter.Year <= 2049
				? new Asn1UtcTime(issuer.NotAfter, false).RawData
				: new Asn1GeneralizedTime(issuer.NotAfter, false).RawData);
			tbsData = new List<Byte>(Asn1Utils.Encode(tbsData.ToArray(), 48));
			HashAlgorithm hasher = HashAlgorithm.Create(hashAlgorithm.FriendlyName);
			List<Byte> sig = new List<Byte> { 0 };
			sig.AddRange(hasher.ComputeHash(tbsData.ToArray()));
			tbsData.AddRange(Asn1Utils.Encode(algid.ToArray(), 48));
			tbsData.AddRange(Asn1Utils.Encode(sig.ToArray(), (Byte)Asn1Type.BIT_STRING));
			return new X509CRL2(Asn1Utils.Encode(tbsData.ToArray(), 48));
		}

		/// <summary>
		/// Populates an <see cref="X509CRL2"/> object with the CRL information from a file.
		/// </summary>
		/// <remarks>This method uses a CRL file, such as a file with a .crl extension, that represents
		/// an X.509 certificate revocation list and populates the <see cref="X509CRL2"/> object with
		/// the CRL the file contains. The method suppoers Base64-encoded or DER-encoded X.509 CRLs.
		/// </remarks>
		/// <param name="path">The path to a CRL file.</param>
		public void Import(String path) {
			m_import(Crypt32Managed.CryptFileToBinary(path));
			isReadOnly = true;
		}
		/// <summary>
		/// Populates an <see cref="X509CRL2"/> object with the CRL information from a DER-encoded byte array.
		/// </summary>
		/// <param name="rawData">A byte array containing data from an X.509 CRL.</param>
		public void Import(Byte[] rawData) {
			m_import(rawData);
			isReadOnly = true;
		}
		/// <summary>
		/// Exports the current X509CRL2 object to a file.
		/// </summary>
		/// <param name="path">The path to a CRL file.</param>
		/// <param name="encoding">Encoding of the exported file.</param>
		/// <exception cref="ArgumentException">Specified encoding type is not supported.</exception>
		/// <exception cref="UninitializedObjectException">An object is not initialized.</exception>
		public void Export(String path, X509EncodingType encoding) {
			if (RawData == null) { throw new UninitializedObjectException(); }
			String Base64;
			switch (encoding) {
				case X509EncodingType.Base64:
					Base64 = AsnFormatter.BinaryToString(RawData, EncodingType.Base64);
					File.WriteAllText(path, Base64);
					break;
				case X509EncodingType.Base64Header:
					Base64 = AsnFormatter.BinaryToString(RawData, EncodingType.Base64CrlHeader);
					File.WriteAllText(path, Base64);
					break;
				case X509EncodingType.Binary:
					File.WriteAllBytes(path, RawData);
					break;
				default:
					throw new ArgumentException("Specified encoding is not supported.");
			}
		}
		/// <summary>
		/// Encodes the current X509CRL2 object to a form specified in the <strong>encoding</strong> parameter.
		/// </summary>
		/// <param name="encoding">Encoding type. Default is <strong>CRYPT_STRING_BASE64X509CRLHEADER</strong>.</param>
		/// <returns>Encoded text.</returns>
		/// <remarks>
		///		The following encoding types are not supported:
		///		<list type="bullet">
		///			<item>Binary</item>
		///			<item>Base64Any</item>
		///			<item>StringAny</item>
		///			<item>HexAny</item>
		///		</list>
		/// </remarks>
		/// <exception cref="ArgumentException">Specified encoding type is not supported.</exception>
		/// <exception cref="UninitializedObjectException">An object is not initialized.</exception>
		public String Encode(EncodingType encoding = EncodingType.Base64CrlHeader) {
			if (RawData == null) { throw new UninitializedObjectException(); }
			if (encoding == EncodingType.Binary) { throw new ArgumentException("Specified encoding is not supported."); }
			return AsnFormatter.BinaryToString(RawData, encoding);
		}
		/// <summary>
		/// Encodes the current X509CRL2 object and sends result to the output.
		/// </summary>
		/// <param name="encoding">Encding type. Can be either Base64Header or Base64 (with no headers).</param>
		/// <returns>The Base64-encoded string.</returns>
		/// <remarks>This method is obsolete. A new overload is preferred.</remarks>
		/// <exception cref="UninitializedObjectException">An object is not initialized.</exception>
		public String Encode(X509EncodingType encoding) {
			if (RawData == null) { throw new UninitializedObjectException(); }
			switch (encoding) {
				case X509EncodingType.Base64:
					return Convert.ToBase64String(RawData, Base64FormattingOptions.InsertLineBreaks);
				case X509EncodingType.Base64Header:
					return AsnFormatter.BinaryToString(RawData, EncodingType.Base64CrlHeader);
				default: throw new ArgumentException("Binary encoding is not supported.");
			}
		}
		/// <summary>
		/// Resets the state of an X509CRL2.
		/// </summary>
		/// <remarks>This method can be used to reset the state of the CRL. It also frees any resources associated with the CRL.</remarks>
		public void Reset() {
			if (!IntPtr.Zero.Equals(Handle)) {
				ReleaseContext();
			}
			Version = 0;
			Type = null;
			IssuerName = null;
			ThisUpdate = new DateTime();
			NextUpdate = null;
			SignatureAlgorithm = null;
			RawData = null;
			Handle = IntPtr.Zero;
		}
		/// <summary>
		/// Displays an X.509 certificate revocation list in text format.
		/// </summary>
		/// <param name="verbose">
		///		Specifies whether the simple or enhanced/verbose output is necessary.
		///		If this parameter is set to <strong>False</strong> (default value), the method returns a brief information about the
		///		current object. If this parameter is set to <strong>True</strong>, the method will return a full dump of the
		///		current object.
		/// </param>
		/// <returns>The CRL information.</returns>
		/// <remarks>If the object is not initialized, the method returns class name.</remarks>
		public String ToString(Boolean verbose = false) {
			if (RawData == null) { return base.ToString(); }
			StringBuilder SB = new StringBuilder();
			if (verbose) {
				genVerboseString(SB);
			} else {
				genBriefString(SB);
			}
			return SB.ToString();
		}
		///  <summary>
		///		Verifies whether the specified certificate is an issuer of this CRL by verifying CRL signature
		///		against specified certificate's public key.
		///  </summary>
		///  <param name="issuer">
		///		A potential issuer's certificate.
		/// </param>
		/// <param name="strict">
		///		Specifies whether to perform CRL issuer and certificate's subject name binary comparison.
		/// </param>
		/// <exception cref="CryptographicException">
		/// 		The data is invalid.
		///  </exception>
		/// <exception cref="UninitializedObjectException">An object is not initialized.</exception>
		///  <returns>
		/// 		<strong>True</strong> if the specified certificate is signed this CRL. Otherwise <strong>False</strong>.
		///  </returns>
		public Boolean VerifySignature(X509Certificate2 issuer, Boolean strict = false) {
			if (RawData == null) { throw new UninitializedObjectException(); }
			var signedInfo = new SignedContentBlob(RawData);
			return MessageSignature.VerifySignature(issuer, signedInfo.ToBeSignedData, signature, SignatureAlgorithm);
		}
		/// <summary>
		/// Verifies whether the specified certificate is in the current revocation list.
		/// </summary>
		/// <param name="cert">Certificate to verify.</param>
		/// <returns><strong>True</strong> if the specified certificate is presented in the CRL. Otherwise <strong>False</strong>.</returns>
		/// <remarks>This method do not check, whether the certificate was issued by the same issuer, as this CRL.</remarks>
		/// <exception cref="UninitializedObjectException">An object is not initialized.</exception>
		public Boolean CertificateInCrl(X509Certificate2 cert) {
			if (RawData == null) { throw new UninitializedObjectException(); }
			if (RevokedCertificates == null || RevokedCertificates.Count < 1) { return false; }
			//if (!GenericArray.CompareArray(IssuerName.RawData, cert.IssuerName.RawData)) { return false; }
			return RevokedCertificates[cert.SerialNumber] == null;
		}
		/// <summary>
		///     Gets a <see cref="SafeCRLHandleContext" /> for the X509 certificate revocation list. The caller of this
		///     method owns the returned safe handle, and should dispose of it when they no longer need it. 
		///     This handle can be used independently of the lifetime of the original X509 certificate revocation list.
		/// </summary>
		/// <returns>Handle to a <strong>CRL_CONTEXT</strong> structure.</returns>
		/// <permission cref="SecurityPermission">
		///     The immediate caller must have SecurityPermission/UnmanagedCode to use this method
		/// </permission>
		/// <exception cref="UninitializedObjectException">An object is not initialized.</exception>
		public SafeCRLHandleContext GetSafeContext() {
			if (RawData == null) { throw new UninitializedObjectException(); }
			if (IntPtr.Zero.Equals(Handle)) {
				getHandle();
			}
			SafeCRLHandleContext safeContext = Crypt32.CertDuplicateCRLContext(Handle);
			GC.KeepAlive(this);
			return safeContext;
		}
		/// <summary>
		/// Gets certificate revocation list sequence number.
		/// </summary>
		/// <returns>Certificate revocation list sequence number.</returns>
		/// <remarks>If CRL is X.509 CRL Version 1, or CRL does not contains 'CRL Number' extension, a zero is returned.</remarks>
		/// <exception cref="UninitializedObjectException">An object is not initialized.</exception>
		public BigInteger GetCRLNumber() {
			if (RawData == null) { throw new UninitializedObjectException(); }
			X509Extension e = Extensions[X509CertExtensions.X509CRLNumber];
			return ((X509CRLNumberExtension) e)?.CRLNumber ?? 0;
		}
		/// <summary>
		/// Gets the date and time when the next CRL is planned to be published. The method uses either <strong>Next CRL Publish</strong> extension
		/// or <strong>NextUpdate</strong> field to determine when a newer version should be issued.
		/// </summary>
		/// <returns>A <see cref="DateTime"/> object, or <strong>NULL</strong>, if CRL is valid infinitly and no updates are expected.</returns>
		/// <exception cref="UninitializedObjectException">An object is not initialized.</exception>
		public DateTime? GetNextPublish() {
			if (RawData == null) { throw new UninitializedObjectException(); }
			if (Extensions == null) { return NextUpdate; }
			X509Extension e = Extensions[X509CertExtensions.X509NextCRLPublish];
			return e == null ? NextUpdate : Asn1Utils.DecodeDateTime(e.RawData);
		}
		/// <summary>
		/// Indiciates whether the current Base CRL has configured to use Delta CRLs too.
		/// </summary>
		/// <returns><strong>True</strong> is the current CRL is configured to use Delta CRLs, otherwise <strong>False</strong>.</returns>
		/// <remarks>If the current CRL type already is Delta CRL, the method returns <strong>False</strong>.</remarks>
		/// <exception cref="UninitializedObjectException">An object is not initialized.</exception>
		public Boolean HasDelta() {
			if (RawData == null) { throw new UninitializedObjectException(); }
			return Type != DeltaCRL && Extensions[X509CertExtensions.X509FreshestCRL] != null;
		}
		/// <summary>
		/// Releases the handle of the current object.
		/// </summary>
		/// <exception cref="Win32Exception">Handle cannot be released.</exception>
		/// <exception cref="UninitializedObjectException">An object is not initialized.</exception>
		public void ReleaseContext() {
			if (RawData == null) { throw new UninitializedObjectException(); }
			if (Handle.Equals(IntPtr.Zero)) { return; }
			if (!Crypt32.CertFreeCRLContext(Handle)) {
				throw new Win32Exception(Marshal.GetLastWin32Error());
			}
			Handle = IntPtr.Zero;
		}
		/// <summary>
		/// Disposes current object and releases unmanaged resources if necessary.
		/// </summary>
		public void Dispose() {
			try {
				ReleaseContext();
			} catch { }
		}
		// generation functions
		///  <summary>
		///  Adds information about revoked certificates to a CRL. This method is a generator method, for more details
		///  see <strong>Remarks</strong> section.
		///  </summary>
		///  <param name="entries">A collection of CRL entries.</param>
		/// <exception cref="ArgumentNullException"><strong>entries</strong> parameter is null reference.</exception>
		/// <exception cref="InvalidOperationException">Current object is already initialized.</exception>
		///  <remarks>
		///  The following method call sequence should be used:
		///  <list type="number">
		///  <item><description>
		/// 		Instantiate the <strong>X509CRL2</strong> object from a default (parameterless) constructor.
		///  </description></item>
		///  <item><description>
		/// 		If necessary, set <see cref="ThisUpdate"/> and <see cref="NextUpdate"/> properties by calling
		/// 		a <see cref="SetThisUpdate"/> and <see cref="SetNextUpdate"/> methods.
		/// 		<para>If these methods are not called, then <see cref="ThisUpdate"/> property is set to a current time
		/// 		and <see cref="NextUpdate"/> is set a 7 days ahead current time.</para>		
		///  </description></item>
		///  <item><description>
		/// 		If necessary, set hashing/signing algorithm by calling <see cref="SetHashingAlgorithm"/>.
		/// 		Default is <strong>SHA1</strong>.
		///  </description></item>
		///  <item><description>
		/// 	Sign/hash and encode CRL by calling <see cref="Build"/> method.
		///  </description></item>
		///  </list>
		///  </remarks>
		public void ImportCRLEntries(X509CRLEntryCollection entries) {
			if (isReadOnly) { throw new InvalidOperationException(); }
			RevokedCertificates = entries ?? throw new ArgumentNullException(nameof(entries));
			RevokedCertificates.Close();
		}
		/// <summary>
		/// 
		/// </summary>
		/// <param name="extensions">A collection of extensions to add.</param>
		/// <exception cref="ArgumentNullException"><strong>extensions</strong> parameter is null reference.</exception>
		/// <exception cref="InvalidOperationException">Current object is already initialized.</exception>
		/// <remarks>
		/// <para>The following rules apply to this method:</para>
		/// <list type="number">
		/// <item><description>
		///		If this method is called, a version 2 CRL will be produced.
		/// </description></item>
		/// <item><description>
		///		If extension list contans <strong>Delta CRL Indicator</strong> extension, CRL type is changed to <strong>Delta CRL</strong>.
		/// </description></item>
		/// <item><description>
		///		<strong>Authority Key Identifier</strong> extension will be added
		/// </description></item>
		/// <item><description>
		///		If extension list contans <strong>Authority Key Identifier</strong> extension, it will be ignored and replaced with
		///		new value retrieved from issuer certificate.
		/// </description></item>
		/// </list>
		///  The following method call sequence should be used:
		///  <list type="number">
		///  <item><description>
		/// 		Instantiate the <strong>X509CRL2</strong> object from a default (parameterless) constructor.
		///  </description></item>
		///  <item><description>
		/// 		If necessary, set <see cref="ThisUpdate"/> and <see cref="NextUpdate"/> properties by calling
		/// 		a <see cref="SetThisUpdate"/> and <see cref="SetNextUpdate"/> methods.
		/// 		<para>If these methods are not called, then <see cref="ThisUpdate"/> property is set to a current time
		/// 		and <see cref="NextUpdate"/> is set a 7 days ahead current time.</para>		
		///  </description></item>
		///  <item><description>
		/// 		If necessary, set hashing/signing algorithm by calling <see cref="SetHashingAlgorithm"/>.
		/// 		Default is <strong>SHA1</strong>.
		///  </description></item>
		///  <item><description>
		/// 	Sign/hash and encode CRL by calling <see cref="Build"/> method.
		///  </description></item>
		///  </list>
		///  </remarks>
		public void ImportExtensions(X509ExtensionCollection extensions) {
			if (isReadOnly) { throw new InvalidOperationException(); }
			if (extensions == null) { throw new ArgumentNullException(nameof(extensions)); }
			if (extensions.Count < 1) { return; }
			Version = 2;
			Extensions = extensions;
			if (Extensions[X509CertExtensions.X509DeltaCRLIndicator] != null) {
				Type = DeltaCRL;
			}
		}
		/// <summary>
		/// Sets the start validity for the CRL object. This method is a generator method, for more details
		/// see <strong>Remarks</strong> section.
		/// </summary>
		/// <param name="thisUpdate"></param>
		/// <exception cref="InvalidOperationException">Current object is already initialized.</exception>
		/// <remarks>
		/// The following method call sequence should be used:
		/// <list type="number">
		/// <item><description>
		///		Instantiate the <strong>X509CRL2</strong> object from a default (parameterless) constructor.
		/// </description></item>
		/// <item><description>
		///		If necessary, set <see cref="ThisUpdate"/> and <see cref="NextUpdate"/> properties by calling
		///		this and <see cref="SetNextUpdate"/> methods.
		///		<para>If these methods are not called, then <see cref="ThisUpdate"/> property is set to a current time
		///		and <see cref="NextUpdate"/> is set a 7 days ahead current time.</para>		
		/// </description></item>
		/// <item><description>
		///		If necessary, set hashing/signing algorithm by calling <see cref="SetHashingAlgorithm"/>.
		///		Default is <strong>SHA1</strong>.
		/// </description></item>
		/// <item><description>
		///	Sign/hash and encode CRL by calling <see cref="Build"/> method.
		/// </description></item>
		/// </list>
		/// </remarks>
		public void SetThisUpdate(DateTime thisUpdate) {
			if (isReadOnly) { throw new InvalidOperationException(); }
			ThisUpdate = thisUpdate;
		}
		/// <summary>
		/// Sets the end validity for the CRL object. This method is a generator method, for more details
		/// see <strong>Remarks</strong> section.
		/// </summary>
		/// <param name="nextUpdate"></param>
		/// <exception cref="InvalidOperationException">Current object is already initialized.</exception>
		/// <remarks>
		/// The following method call sequence should be used:
		/// <list type="number">
		/// <item><description>
		///		Instantiate the <strong>X509CRL2</strong> object from a default (parameterless) constructor.
		/// </description></item>
		/// <item><description>
		///		If necessary, set <see cref="ThisUpdate"/> and <see cref="NextUpdate"/> properties by calling
		///		a <see cref="SetThisUpdate"/> and this methods.
		///		<para>If these methods are not called, then <see cref="ThisUpdate"/> property is set to a current time
		///		and <see cref="NextUpdate"/> is set a 7 days ahead current time.</para>		
		/// </description></item>
		/// <item><description>
		///		If necessary, set hashing/signing algorithm by calling <see cref="SetHashingAlgorithm"/>.
		///		Default is <strong>SHA1</strong>.
		/// </description></item>
		/// <item><description>
		///	Sign/hash and encode CRL by calling <see cref="Build"/> method.
		/// </description></item>
		/// </list>
		/// </remarks>
		public void SetNextUpdate(DateTime nextUpdate) {
			if (isReadOnly) { throw new InvalidOperationException(); }
			NextUpdate = nextUpdate;
		}
		///   <summary>
		///   Encodes and signs CRL. After this method call, no CRL generation method calls are permitted.
		///   This method is a generator method, for more details see <strong>Remarks</strong> section.
		///   </summary>
		///   <param name="signerInfo">Specifies the CRL issuer certificate.</param>
		///  <param name="hashOnly">
		/// 		Specifies whether the CRL should not be digitally signed and hash value should be calculated instead.
		///  </param>
		/// <param name="versionTwo">
		/// Specifies whether X.509 Version 2 CRL should be generated. See Remarks for this parameter behavior.
		/// </param>
		/// <exception cref="InvalidOperationException">Current object is already initialized.</exception>
		///   <remarks>
		///   The following method call sequence should be used:
		///   <list type="number">
		///   <item><description>
		///  		Instantiate the <strong>X509CRL2</strong> object from a default (parameterless) constructor.
		///   </description></item>
		///   <item><description>
		///  		If necessary, set <see cref="ThisUpdate"/> and <see cref="NextUpdate"/> properties by calling
		///  		a <see cref="SetThisUpdate"/> and <see cref="SetNextUpdate"/> methods.
		///  		<para>If these methods are not called, then <see cref="ThisUpdate"/> property is set to a current time
		///  		and <see cref="NextUpdate"/> is set a 7 days ahead current time.</para>		
		///   </description></item>
		///   <item><description>
		///  		If necessary, set hashing/signing algorithm by calling <see cref="SetHashingAlgorithm"/>.
		///  		Default is <strong>SHA1</strong>.
		///   </description></item>
		///   <item><description>
		///  	Sign/hash and encode CRL by calling this method.
		///   </description></item>
		///   </list>
		///   <para>
		///  	If certificate in the <strong>signerInfo</strong> parameter has associated private key and
		/// 		<strong>hashOnly</strong> parameter is set to <strong>False</strong> the method will attempt to sign
		/// 		the CRL. Otherwise (if certificate do not have associated private key, or <strong>hashOnly</strong>
		/// 		parameter is set to <strong>True</strong>), CRL content is hashed and hash value is placed in the signature
		/// 		field. In this case, <see cref="SignatureAlgorithm"/> property will contain a signing algorithm with
		/// 		a <strong>NoSign</strong> suffix. For example, <strong>sha1NoSign</strong>.
		///   </para>
		///  <para>
		/// 		This method creates an X.509 v1 Base CRL by default. X.509 v2 CRL is generated in the following cases:
		/// <list type="number">
		/// <item><description>
		/// <strong>versionTwo</strong> parameter is set to <strong>True</strong>, or
		/// </description></item>
		/// <item><description>
		/// <see cref="ImportExtensions"/> method was called.
		/// </description></item>
		/// </list>
		///  </para>
		/// <para>
		/// If <see cref="ImportExtensions"/> method was called, then <strong>versionTwo</strong> parameter is ignored. All extensions
		/// from an <see cref="Extensions"/> property are populatted in the CRL. If <strong>CA Version</strong> and
		/// <strong>Authority Key Identifier</strong> extensions are presented in the extension list, they are replaced with actual
		/// values from a signer certificate.
		/// </para>
		/// <para>
		/// If <see cref="ImportExtensions"/> method was not called and <strong>versionTwo</strong> parameter is set to <strong>True</strong> and
		/// then, only basic extensions are added:
		///  <list type="number">
		/// <item><description>
		/// <strong>Authority Key Identifier</strong>
		/// </description></item>
		/// <item><description>
		/// <strong>CA Version</strong> (if presented in the signer certificate).
		/// </description></item>
		/// </list>
		/// </para>
		///   </remarks>
		public void Build(X509Certificate2 signerInfo, Boolean hashOnly, Boolean versionTwo = false) {
			if (isReadOnly) { throw new InvalidOperationException(); }
			if (signerInfo == null) { throw new ArgumentNullException(nameof(signerInfo)); }
			if (signerInfo.RawData == null) { throw new UninitializedObjectException(); }
			if (versionTwo) { Version = 2; }

			if (SignatureAlgorithm == null) {
				SignatureAlgorithm = new Oid("1.3.14.3.2.26", "sha1NoSign");
			}
			if (String.IsNullOrEmpty(signerInfo.SubjectName.Name)) {
				throw new ArgumentException("Subject name is empty.");
			}
			List<Byte> algId = new List<Byte>(Asn1Utils.EncodeObjectIdentifier(SignatureAlgorithm));
			algId.AddRange(new Byte[] { 5, 0 });
			algId = new List<Byte>(Asn1Utils.Encode(algId.ToArray(), 48));
			if (NextUpdate <= ThisUpdate) {
				NextUpdate = signerInfo.NotAfter;
			}
			IssuerName = signerInfo.SubjectName;
			List<Byte> rawBytes = new List<Byte>();
			// version
			if (versionTwo) {
				rawBytes.AddRange(new Asn1Integer(Version - 1).RawData);//TODO ???
			}
			// algorithm
			rawBytes.AddRange(algId);
			// issuer
			rawBytes.AddRange(IssuerName.RawData);
			// thisUpdate
			rawBytes.AddRange(Asn1Utils.EncodeDateTime(ThisUpdate));
			// nextUpdate
			rawBytes.AddRange(NextUpdate != null
				? Asn1Utils.EncodeDateTime((DateTime) NextUpdate)
				: Asn1Utils.EncodeDateTime(ThisUpdate.AddDays(7)));
			// revokedCerts
			if (RevokedCertificates != null && RevokedCertificates.Count > 0) {
				rawBytes.AddRange(RevokedCertificates.Encode());
				RevokedCertificates.Close();
			}
			// extensions
			if (Extensions != null || versionTwo) {
				genExts(signerInfo);
				rawBytes.AddRange(Asn1Utils.Encode(Crypt32Managed.EncodeX509Extensions(Extensions), 160));
			}
			// generate tbs
			rawBytes = new List<Byte>(Asn1Utils.Encode(rawBytes.ToArray(), 48));
			// calculate signature
			sigUnused = 0;
			if (signerInfo.HasPrivateKey && !hashOnly) {
				signature = MessageSignature.SignMessage(signerInfo, rawBytes.ToArray(), SignatureAlgorithm);
			} else {
				HashAlgorithm hasher = HashAlgorithm.Create(SignatureAlgorithm.FriendlyName.Replace("NoSign", null));
				signature = hasher.ComputeHash(rawBytes.ToArray());
			}
			// signature algorithm
			rawBytes.AddRange(algId);
			List<Byte> pure = new List<Byte> { 0 };
			pure.AddRange(signature);
			rawBytes.AddRange(Asn1Utils.Encode(pure.ToArray(), (Byte)Asn1Type.BIT_STRING));
			RawData = Asn1Utils.Encode(rawBytes.ToArray(), 48);
			//m_decode(RawData);
			isReadOnly = true;
		}
		/// <summary>
		/// Specifies the signing/hashing algorithm to use for CRL object signing. This method is a generator method,
		/// for more details see <strong>Remarks</strong> section.
		/// </summary>
		/// <param name="algorithmIdentifier">Specifies the signing/hashing algorithm.</param>
		/// <exception cref="InvalidOperationException">Current object is already initialized.</exception>
		/// <remarks>
		/// The following method call sequence should be used:
		/// <list type="number">
		/// <item><description>
		///		Instantiate the <strong>X509CRL2</strong> object from a default (parameterless) constructor.
		/// </description></item>
		/// <item><description>
		///		If necessary, set <see cref="ThisUpdate"/> and <see cref="NextUpdate"/> properties by calling
		///		a <see cref="SetThisUpdate"/> and this methods.
		///		<para>If these methods are not called, then <see cref="ThisUpdate"/> property is set to a current time
		///		and <see cref="NextUpdate"/> is set a 7 days ahead current time.</para>		
		/// </description></item>
		/// <item><description>
		///		If necessary, set hashing/signing algorithm by calling this method.
		///		Default is <strong>SHA1</strong>.
		/// </description></item>
		/// <item><description>
		///	Sign/hash and encode CRL by calling <see cref="Build"/> method.
		/// </description></item>
		/// </list>
		/// </remarks>
		public void SetHashingAlgorithm(Oid2 algorithmIdentifier) {
			if (isReadOnly) { throw new InvalidOperationException(); }
			if (algorithmIdentifier.OidGroup != OidGroupEnum.SignatureAlgorithm) {
				throw new ArgumentException("The specified algorithm is not valid for requested purpose.");
			}
			SignatureAlgorithm = algorithmIdentifier.ToOid();
		}
	}
}