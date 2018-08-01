using System;
using System.Security.Cryptography;

namespace SysadminsLV.PKI.Cryptography {
    public interface IKeyStorageInfo {
        String ProviderName { get; }
        Int32 ProviderType { get; }
        String KeyContainerName { get; }
        Oid PublicKeyAlgorithm { get; }
    }
}