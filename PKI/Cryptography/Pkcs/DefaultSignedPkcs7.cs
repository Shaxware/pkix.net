using System;

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
    }
}
