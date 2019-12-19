using System;
using System.Security.Cryptography;
using SysadminsLV.Asn1Parser;

namespace SysadminsLV.PKI.Cryptography.Pkcs {
    /// <summary>
    /// Represents general/common implementation of signed PKCS #7 with arbitrary content type. The type of
    /// <see cref="SignedPkcs7{T}.Content">Content</see> is <strong>Byte[]</strong>.
    /// </summary>
    public sealed class DefaultSignedPkcs7 : SignedPkcs7<Byte[]> {
        /// <inheritdoc />
        public DefaultSignedPkcs7(Byte[] rawData) : base(rawData) { }
        /// <inheritdoc />
        protected override void DecodeContent(Byte[] rawData) {
            Content = rawData;
        }

        /// <summary>
        /// Timestamps the specified signature using external Time-Stamp Authority.
        /// </summary>
        /// <param name="tsaUrl">
        ///     An URL to a Time-Stamp Authority.
        /// </param>
        /// <param name="hashAlgorithm">
        ///     Hash algorithm to use by TSA to sign response.
        /// </param>
        /// <param name="signerInfoIndex">
        ///     A zero-based index of signature to timestamp. Default value is 0.
        /// </param>
        /// <remarks>This method adds an RFC3161 Counter Signature.</remarks>
        public void AddTimestamp(String tsaUrl, Oid hashAlgorithm, Int32 signerInfoIndex = 0) {
            var tspReq = new TspRfc3161Request(hashAlgorithm, SignerInfos[signerInfoIndex].EncryptedHash) {
                TsaUrl = new Uri(tsaUrl)
            };
            TspResponse rsp = tspReq.SendRequest();

            var builder = new SignedCmsBuilder(this);
            builder.AddTimestamp(rsp, 0);
            DecodeCms(new Asn1Reader(builder.Encode().RawData));
        }
    }
}
