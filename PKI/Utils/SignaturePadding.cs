namespace PKI.Utils {
    /// <summary>
    /// Represents supported digital signature schemes.
    /// </summary>
    public enum SignaturePadding {
        /// <summary>
        /// The PKCS1 padding scheme is used to create or verify signature.
        /// </summary>
        PKCS1,
        /// <summary>
        /// The Probabilistic Signature Scheme (PSS) padding scheme padding scheme is used to create or
        /// verify signature
        /// </summary>
        PSS
    }
}