using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace PKI {
    static class nCrypt {
        [DllImport("ncrypt.dll", SetLastError = true)]
        public static extern Int32 NCryptEnumStorageProviders(
            ref UInt32 pImplCount,
            ref IntPtr ppImplList,
            UInt32 dwFlags
        );
        [DllImport("ncrypt.dll", SetLastError = true)]
        public static extern Int32 NCryptOpenStorageProvider(
            out IntPtr phProvider,
            [MarshalAs(UnmanagedType.LPWStr)]
            String pszProviderName,
            UInt32 dwFlags
        );
        [DllImport("ncrypt.dll", SetLastError = true)]
        public static extern Int32 NCryptEnumAlgorithms(
            IntPtr hProvider,
            UInt32 dwAlgOperations,
            ref Int32 pdwAlgCount,
            ref IntPtr ppAlgList,
            UInt32 dwFlags
        );
        [DllImport("ncrypt.dll", SetLastError = true)]
        public static extern Int32 NCryptFreeBuffer(
            [In]            IntPtr pvInput
        );
        [DllImport("ncrypt.dll", SetLastError = true)]
        public static extern Int32 NCryptFreeObject(
            [In]            IntPtr phProvider
        );
        [DllImport("ncrypt.dll", SetLastError = true)]
        public static extern Int32 NCryptEnumKeys(
            IntPtr hProvider,
            [MarshalAs(UnmanagedType.LPWStr)]
            String pszScope,
            ref IntPtr ppKeyName,
            ref IntPtr ppEnumState,
            UInt32 dwFlags
        );
        [DllImport("ncrypt.dll", SetLastError = true)]
        public static extern Int32 NCryptImportKey(
            [In] IntPtr hProvider,
            [In, Optional] IntPtr hImportKey,
            [In] String pszBlobType,
            [In, Optional] IntPtr pParameterList,
            [Out] out SafeNCryptKeyHandle phKey,
            [In] Byte[] pbData,
            [In] Int32 cbData,
            [In] UInt32 dwFlags
        );

        [DllImport("ncrypt.dll", SetLastError = true)]
        public static extern Int32 NCryptOpenKey(
            [In]            IntPtr hProvider,
            [In, Out] ref IntPtr phKey,
            [MarshalAs(UnmanagedType.LPWStr)]
            [In]            String pszKeyName,
            [In]            UInt32 dwLegacyKeySpec,
            [In]            UInt32 dwFlags
        );
        [DllImport("ncrypt.dll", SetLastError = true)]
        public static extern Int32 NCryptExportKey(
            [In]            IntPtr hKey,
            [In, Optional]  IntPtr hExportKey,
            [MarshalAs(UnmanagedType.LPWStr)]
            [In]            String pszBlobType,
            [In, Optional]  IntPtr pParameterList,
            [In, Out]   ref Byte[] pbOutput,
            [In]            UInt32 cbOutput,
            [In]            UInt32 pcbResult,
            [In]            UInt32 dwFlags
        );
        [DllImport("ncrypt.dll", SetLastError = true)]
        public static extern Int32 NCryptSignHash(
            [In]            IntPtr hKey,
            [In, Optional]  IntPtr pPaddingInfo,
            [MarshalAs(UnmanagedType.LPArray)]
            Byte[]          pbHashValue,
            UInt32 cbHashValue,
            [MarshalAs(UnmanagedType.LPArray)]
            Byte[]          pbSignature,
            UInt32 cbSignature,
            [Out]out UInt32 pcbResult,
            UInt32 dwFlags
        );
        [DllImport("ncrypt.dll", SetLastError = true)]
        public static extern Int32 NCryptVerifySignature(
            [In] SafeNCryptKeyHandle hKey,
            [In, Optional] IntPtr pPaddingInfo,
            [MarshalAs(UnmanagedType.LPArray)]
            [In] Byte[] pbHashValue,
            [In] Int32 cbHashValue,
            [MarshalAs(UnmanagedType.LPArray)]
            [In] Byte[] pbSignature,
            [In] Int32 cbSignature,
            [In] UInt32 dwFlags
        );
    }
}
