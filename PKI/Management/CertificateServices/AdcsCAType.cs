namespace SysadminsLV.PKI.Management.CertificateServices {
    /// <summary>
    /// Represents an ADCS Certification Authority installation type.
    /// </summary>
    public enum AdcsCAType {
        /// <summary>
        /// Installation type is invalid or unknown.
        /// </summary>
        Invalid               = -1,
        /// <summary>
        /// Installation type is Enterprise Root CA.
        /// </summary>
        EnterpriseRoot        = 0,
        /// <summary>
        /// Installation type is Enterprise Subordinate CA.
        /// </summary>
        EnterpriseSubordinate = 1,
        /// <summary>
        /// Installation type is Standalone Root CA.
        /// </summary>
        StandaloneRoot        = 3,
        /// <summary>
        /// Installation type is Standalone Subordinate CA.
        /// </summary>
        StandaloneSubordinate = 4
    }
}