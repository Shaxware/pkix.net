using System;
using System.Runtime.InteropServices;

namespace PKI.Structs {
    /// <summary>
    /// <strong>nCrypt</strong> class represents a set of unmanaged structures that are translated to .NET Framework compatible
    /// structures.
    /// <p>This class do not provide any constructors and static methods.</p>
    /// </summary>
    /// <remarks>Most of these structures are related to <strong>CryptoAPI</strong> and are defined in <strong>ncrypt.h</strong>
    /// header file.</remarks>
    static class nCrypt2 {
        #region enums
        internal const UInt32 NCRYPT_CIPHER_OPERATION                   = 0x00000001;
        internal const UInt32 NCRYPT_HASH_OPERATION                     = 0x00000002;
        internal const UInt32 NCRYPT_ASYMMETRIC_ENCRYPTION_OPERATION    = 0x00000004;
        internal const UInt32 NCRYPT_SECRET_AGREEMENT_OPERATION         = 0x00000008;
        internal const UInt32 NCRYPT_SIGNATURE_OPERATION                = 0x00000010;
        #endregion
        [StructLayout(LayoutKind.Sequential)]
        public struct NCryptProviderName {
            [MarshalAs(UnmanagedType.LPWStr)]
            public String pszName;
            [MarshalAs(UnmanagedType.LPWStr)]
            public String pszComment;
        }
        [StructLayout(LayoutKind.Sequential)]
        public struct NCryptAlgorithmName {
            [MarshalAs(UnmanagedType.LPWStr)]
            public String pszName;
            public UInt32 dwClass;
            public UInt32 dwAlgOperations;
            public UInt32 dwFlags;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct BCRYPT_PKCS1_PADDING_INFO {
            [MarshalAs(UnmanagedType.LPWStr)]
            public String pszAlgId;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct BCRYPT_PSS_PADDING_INFO {
            [MarshalAs(UnmanagedType.LPWStr)]
            public String pszAlgId;
            public Int32 cbSalt;
        }

    }
}
