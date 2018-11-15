﻿using System;
using System.IO;
using System.Numerics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using SysadminsLV.Asn1Parser;
using SysadminsLV.Asn1Parser.Universal;
using SysadminsLV.PKI.Exceptions;
using SysadminsLV.PKI.Helpers;
using SysadminsLV.PKI.Helpers.CLRExtensions;

namespace SysadminsLV.PKI.Cryptography.X509Certificates {
    /// <summary>
    /// Provides methods that help you use X.509 certificate revocation lists (CRL).
    /// </summary>
    public class X509CRL2 {
        Int32 sigUnused;
        Byte[] signature;
        /// <summary>
        /// Initializes a new instance of the <see cref="X509CRL2"/> class using the path to a CRL file. 
        /// </summary>
        /// <param name="path">The path to a CRL file.</param>
        public X509CRL2(String path) {
            m_import(BinaryConverter.CryptFileToBinary(path));
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
        public X509CrlType Type { get; private set; }
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
        /// Gets the CRL sequential number.
        /// </summary>
        public BigInteger CRLNumber { get; private set; }
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
        public X509ExtensionCollection Extensions { get; private set; } = new X509ExtensionCollection();
        /// <summary>
        /// Gets a collection of <see cref="X509CRLEntry">X509CRLEntry</see> objects.
        /// </summary>
        /// <remarks><see cref="X509CRLEntry"/> object represents a CRL entry.
        /// Each entry contains at least the following information: <see cref="X509CRLEntry.SerialNumber">SerialNumber</see>
        /// of revoked certificate and <see cref="X509CRLEntry.RevocationDate">RevocationDate</see> that represents a date
        /// and time at which certificate was revoked. Additionaly, revocation entry may contain additional information,
        /// such revocation reason.</remarks>
        public X509CRLEntryCollection RevokedCertificates { get; } = new X509CRLEntryCollection();
        /// <summary>
        /// Gets the raw data of a certificate revocation list.
        /// </summary>
        public Byte[] RawData { get; private set; }
        /// <summary>
        /// Gets a thumbprint of the current CRL object. Default thumbprint algorithm is SHA256.
        /// </summary>
        /// <remarks>
        /// The thumbprint is dynamically generated using the SHA256 algorithm and does not physically exist
        /// in the certificate revocation list. Since the thumbprint is a unique value for the certificate,
        /// it is commonly used to find a particular certificate revocation list in a certificate store.</remarks>
        public String Thumbprint { get; private set; }

        void m_decode(Byte[] rawData) {
            try {
                Type = X509CrlType.BaseCrl;
                var signedInfo = new SignedContentBlob(rawData, ContentBlobType.SignedBlob);
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
                        ThisUpdate = new Asn1UtcTime(asn.GetTagRawData()).Value;
                        break;
                    case (Byte)Asn1Type.GeneralizedTime:
                        ThisUpdate = Asn1Utils.DecodeGeneralizedTime(asn.GetTagRawData());
                        break;
                    default:
                        throw new Asn1InvalidTagException();
                }
                if (!asn.MoveNextCurrentLevel()) { return; }
                switch (asn.Tag) {
                    case (Byte)Asn1Type.UTCTime:
                    case (Byte)Asn1Type.GeneralizedTime:
                        switch (asn.Tag) {
                            case (Byte)Asn1Type.UTCTime:
                                NextUpdate = new Asn1UtcTime(asn.GetTagRawData()).Value;
                                break;
                            case (Byte)Asn1Type.GeneralizedTime:
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
            RevokedCertificates.Decode(asn.GetTagRawData());
            RevokedCertificates.Close();
        }
        void getExts(Asn1Reader asn) {
            Extensions.Decode(asn.GetPayload());
            if (Extensions[X509ExtensionOidMap.X509DeltaCRLIndicator] != null) {
                Type = X509CrlType.DeltaCrl;
            }
            var crlNumExt = (X509CRLNumberExtension)Extensions[X509ExtensionOidMap.X509CRLNumber];
            CRLNumber = crlNumExt?.CRLNumber ?? 0;
        }
        void m_import(Byte[] rawData) {
            Reset();
            m_decode(rawData);
            RawData = rawData;
            var sb = new StringBuilder();
            using (SHA256 hasher = SHA256.Create()) {
                foreach (Byte b in hasher.ComputeHash(RawData)) {
                    sb.AppendFormat("{0:X2}", b);
                }
            }
            Thumbprint = sb.ToString();
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

        /// <summary>
        /// Exports the current X509CRL2 object to a file.
        /// </summary>
        /// <param name="path">The path to a CRL file.</param>
        /// <param name="encoding">Encoding of the exported file.</param>
        /// <exception cref="ArgumentException">Specified encoding type is not supported.</exception>
        /// <exception cref="UninitializedObjectException">An object is not initialized.</exception>
        public void Export(String path, EncodingType encoding) {
            if (RawData == null) { throw new UninitializedObjectException(); }
            String Base64;
            switch (encoding) {
                case EncodingType.Base64:
                case EncodingType.Base64Header:
                    Base64 = AsnFormatter.BinaryToString(RawData, encoding);
                    File.WriteAllText(path, Base64);
                    break;
                case EncodingType.Binary:
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
        public String Encode() {
            if (RawData == null) {
                throw new UninitializedObjectException();
            }
            return AsnFormatter.BinaryToString(RawData, EncodingType.Base64CrlHeader);
        }
        /// <summary>
        /// Encodes the current X509CRL2 object and sends result to the output.
        /// </summary>
        /// <param name="encoding">Encding type. Can be either Base64Header or Base64 (with no headers).</param>
        /// <returns>The Base64-encoded string.</returns>
        /// <remarks>This method is obsolete. A new overload is preferred.</remarks>
        /// <exception cref="UninitializedObjectException">An object is not initialized.</exception>
        public String Encode(EncodingType encoding) {
            if (RawData == null) { throw new UninitializedObjectException(); }
            switch (encoding) {
                case EncodingType.Base64:
                case EncodingType.Base64CrlHeader:
                    return AsnFormatter.BinaryToString(RawData, encoding);
                default:
                    throw new ArgumentException("Binary encoding is not supported.");
            }
        }
        /// <summary>
        /// Resets the state of an X509CRL2.
        /// </summary>
        /// <remarks>This method can be used to reset the state of the CRL. It also frees any resources associated with the CRL.</remarks>
        public void Reset() {
            Extensions = new X509ExtensionCollection();
            RevokedCertificates.Clear();
            Version = 0;
            Type = X509CrlType.BaseCrl;
            IssuerName = null;
            ThisUpdate = new DateTime();
            NextUpdate = null;
            SignatureAlgorithm = null;
            RawData = null;
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
        /// Gets certificate revocation list sequence number.
        /// </summary>
        /// <returns>Certificate revocation list sequence number.</returns>
        /// <remarks>If CRL is X.509 CRL Version 1, or CRL does not contains 'CRL Number' extension, a zero is returned.</remarks>
        /// <exception cref="UninitializedObjectException">An object is not initialized.</exception>
        public BigInteger GetCRLNumber() {
            if (RawData == null) { throw new UninitializedObjectException(); }
            X509Extension e = Extensions[X509ExtensionOidMap.X509CRLNumber];
            return ((X509CRLNumberExtension)e)?.CRLNumber ?? 0;
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
            X509Extension e = Extensions[X509ExtensionOidMap.X509NextCRLPublish];
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
            return Type != X509CrlType.DeltaCrl && Extensions[X509ExtensionOidMap.X509FreshestCRL] != null;
        }
        /// <summary>
        /// Determines whether the specified object is equal to the current object. Two CRLs are equal when
        /// they have same version, type, issuer, CRL number and <see cref="ThisUpdate"/> values.
        /// </summary>
        /// <inheritdoc cref="Object.ToString" select="param|returns"/>
        public override Boolean Equals(Object obj) {
            return !(obj is null) &&
                   (ReferenceEquals(this, obj)
                    || obj.GetType() == GetType()
                    && Equals((X509CRL2) obj));
        }
        Boolean Equals(X509CRL2 other) {
            return Version == other.Version
                   && Type == other.Type
                   && IssuerName.Equals(other.IssuerName)
                   && ThisUpdate.Equals(other.ThisUpdate)
                   && CRLNumber.Equals(other.CRLNumber);
        }
        /// <inheritdoc />
        public override Int32 GetHashCode() {
            unchecked {
                Int32 hashCode = Version;
                hashCode = (hashCode * 397) ^ (Int32)Type;
                hashCode = (hashCode * 397) ^ IssuerName.GetHashCode();
                hashCode = (hashCode * 397) ^ ThisUpdate.GetHashCode();
                hashCode = (hashCode * 397) ^ CRLNumber.GetHashCode();
                return hashCode;
            }
        }
    }
}