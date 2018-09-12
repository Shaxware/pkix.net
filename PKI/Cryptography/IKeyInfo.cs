using System;
using System.Security.Cryptography;

namespace SysadminsLV.PKI.Cryptography {
    /// <summary>
    /// Represents abstractions of asymmetric key pair container.
    /// </summary>
    public interface IKeyStorageInfo {
        /// <summary>
        /// Gets cryptographic service provider (CSP or KSP, key storage provider) that holds the key pair.
        /// </summary>
        String ProviderName { get; }
        /// <summary>
        /// Gets Microsoft-specific provider type.
        /// </summary>
        Int32 ProviderType { get; }
        /// <summary>
        /// Gets key container name within CSP or KSP.
        /// </summary>
        String KeyContainerName { get; }
        /// <summary>
        /// Gets value that indicates whether the key is stored in local machine or current user context.
        /// </summary>
        Boolean MachineContext { get; }
        /// <summary>
        /// Gets key pair's asymmetric algorithm.
        /// </summary>
        Oid PublicKeyAlgorithm { get; }
    }
}