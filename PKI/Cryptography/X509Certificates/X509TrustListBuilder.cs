using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using PKI.Structs;
using SysadminsLV.Asn1Parser;
using SysadminsLV.Asn1Parser.Universal;
using SysadminsLV.PKI.Cryptography.Pkcs;
using SysadminsLV.PKI.Tools.MessageOperations;

namespace SysadminsLV.PKI.Cryptography.X509Certificates {
    /// <summary>
    /// Contains properties and methods used to create and sign X.509 certificate trust list.
    /// </summary>
    public class X509TrustListBuilder {
        readonly Oid oid = new Oid("1.3.6.1.4.1.311.10.1");

        /// <summary>
        /// Gets or sets the trust list identifier. Often, it is a friendly name of the list.
        /// </summary>
        public String ListIdentifier { get; set; }
        /// <summary>
        /// Gets or sets the monotonically increasing number for each update of the CTL.
        /// </summary>
        public BigInteger? SequenceNumber { get; set; }
        /// <summary>
        /// Gets a list that identifies the intended usage of the list as a sequence of object identifiers. This is the same as in
        /// the Enhanced Key Usage extension.
        /// </summary>
        public OidCollection ListUsages { get; } = new OidCollection();
        /// <summary>
        /// Gets a collection of trust list entries associated with trust list.
        /// </summary>
        public X509TrustListEntryCollection Entries { get; } = new X509TrustListEntryCollection();
        /// <summary>
        /// Gets or sets the hashing algorithm used to create trust list entries. Default algorithm is SHA1.
        /// </summary>
        public Oid HashAlgorithm { get; set; } = new Oid(AlgorithmOids.SHA1);
        /// <summary>
        /// Gets or sets the expiration date and time for trust list. If not set, trust list is valid indefinitely.
        /// </summary>
        public DateTime? NextUpdate { get; set; }

        Byte[] encodeCTL() {
            var rawData = new List<Byte>(new X509EnhancedKeyUsageExtension(ListUsages, false).RawData);
            if (!String.IsNullOrEmpty(ListIdentifier)) {
                rawData.AddRange(Asn1Utils.Encode(Encoding.Unicode.GetBytes(ListIdentifier + "\0"), (Byte)Asn1Type.OCTET_STRING));
            }
            if (SequenceNumber != null) {
                rawData.AddRange(new Asn1Integer((BigInteger)SequenceNumber).RawData);
            }
            rawData.AddRange(Asn1Utils.EncodeDateTime(DateTime.UtcNow));
            if (NextUpdate != null) {
                rawData.AddRange(Asn1Utils.EncodeDateTime((DateTime)NextUpdate));
            }
            rawData.AddRange(new AlgorithmIdentifier(HashAlgorithm).RawData);
            rawData.AddRange(Entries.Encode());
            return rawData.ToArray();
        }


        /// <summary>
        ///     Encodes and signs current trust list using signer certificate and optional certificate chain to include in CTL.
        /// </summary>
        /// <param name="signer">signing object that contains public certificate, private key and signing configuration.</param>
        /// <param name="chain">
        ///     Signing certificate chain to add to CMS. This parameter is optional. If not specified, only leaf (signing) certificate
        ///     is added to certificate list.
        /// </param>
        /// <returns>
        ///     An instance of <see cref="X509CertificateTrustList"/> class that represents signed certificate trust list.
        /// </returns>
        public X509CertificateTrustList Sign(MessageSigner signer, X509Certificate2Collection chain) {
            var cmsBuilder = new SignedCmsBuilder(oid, encodeCTL());
            cmsBuilder.DigestAlgorithms.Add(new AlgorithmIdentifier(signer.HashingAlgorithm.ToOid()));
            foreach (X509TrustListEntry entry in Entries.Where(x => x.Certificate != null)) {
                cmsBuilder.Certificates.Add(entry.Certificate);
            }
            var signedCms = cmsBuilder.Sign(signer, chain);
            return new X509CertificateTrustList(signedCms.RawData);
        }
    }
}