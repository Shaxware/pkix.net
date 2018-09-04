using System;

namespace SysadminsLV.PKI.Management.CertificateServices {
    /// <summary>
    /// Defines the ADCS server registration information source.
    /// </summary>
    [Flags]
    public enum AdcsRegistrationSource {
        /// <summary>
        /// ADCS is registered in Active Directory.
        /// </summary>
        ActiveDirectory = 0x1,
        /// <summary>
        /// ADCS is registered in shared folder (not used).
        /// </summary>
        SharedFolder    = 0x2,
        /// <summary>
        /// ADCS is registered in local registry.
        /// </summary>
        Registry        = 0x4,
        /// <summary>
        /// ADCS is registered in local registry and it is default ADCS instance.
        /// </summary>
        Local           = 0x8,
        /// <summary>
        /// ADCS is registered in local registry as parent CA.
        /// </summary>
        RegistryParent  = 0x10
    }
}