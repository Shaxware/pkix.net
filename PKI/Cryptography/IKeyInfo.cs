using System;
using System.Security.Cryptography;

namespace SysadminsLV.PKI.Cryptography {
    public interface IKeyStorageInfo {
        String ProviderName { get; }
        Int32 ProviderType { get; }
        String KeyContainerName { get; }
        Boolean MachineContext { get; }
        Oid PublicKeyAlgorithm { get; }
    }
}