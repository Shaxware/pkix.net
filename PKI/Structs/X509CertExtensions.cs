using System;

namespace PKI.Structs {
    /// <summary>
    /// Contains OIDs for most commonly used X.509 certificate and certificate revocation list
    /// extensions.
    /// </summary>
    public static class X509CertExtensions {
        public const String X509CertificateExtensions           = "1.2.840.113549.1.9.14";
        public const String X509CertTemplateInfoV2              = "1.3.6.1.4.1.311.20.2";
        public const String X509CAVersion                       = "1.3.6.1.4.1.311.21.1";
        public const String X509PreviousCaHash                  = "1.3.6.1.4.1.311.21.2";
        public const String X509VirtualBaseCRL                  = "1.3.6.1.4.1.311.21.3";
        public const String X509NextCRLPublish                  = "1.3.6.1.4.1.311.21.4";
        public const String X509CertificateTemplate             = "1.3.6.1.4.1.311.21.7";
        public const String X509ApplicationPolicies             = "1.3.6.1.4.1.311.21.10";
        public const String X509ApplicationPolicyMappings       = "1.3.6.1.4.1.311.21.11";
        public const String X509ApplicationPolicyConstraints    = "1.3.6.1.4.1.311.21.12";
        public const String X509AuthorityInformationAccess      = "1.3.6.1.5.5.7.1.1";
        public const String X509OcspNonce                       = "1.3.6.1.5.5.7.48.1.2";
        public const String X509OcspCRLReference                = "1.3.6.1.5.5.7.48.1.3";
        public const String X509OcspRevNoCheck                  = "1.3.6.1.5.5.7.48.1.5";
        public const String X509ArchiveCutoff                   = "1.3.6.1.5.5.7.48.1.6";
        public const String X509ServiceLocator                  = "1.3.6.1.5.5.7.48.1.7";
        public const String X509SubjectKeyIdentifier            = "2.5.29.14";
        public const String X509KeyUsage                        = "2.5.29.15";
        public const String X509SubjectAlternativeNames         = "2.5.29.17";
        public const String X509IssuerAlternativeNames          = "2.5.29.18";
        public const String X509BasicConstraints                = "2.5.29.19";
        public const String X509CRLNumber                       = "2.5.29.20";
        public const String X509CRLReasonCode                   = "2.5.29.21";
        public const String X509DeltaCRLIndicator               = "2.5.29.27";
        public const String X509NameConstraints                 = "2.5.29.30";
        public const String X509CRLDistributionPoints           = "2.5.29.31";
        public const String X509CertificatePolicies             = "2.5.29.32";
        public const String X509CertificatePolicyMappings       = "2.5.29.33";
        public const String X509AuthorityKeyIdentifier          = "2.5.29.35";
        public const String X509CertificatePolicyConstraints    = "2.5.29.36";
        public const String X509EnhancedKeyUsage                = "2.5.29.37";
        public const String X509FreshestCRL                     = "2.5.29.46";
    }
}