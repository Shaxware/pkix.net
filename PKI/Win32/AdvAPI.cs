using System;
using System.Runtime.InteropServices;
using System.Text;
using PKI.Structs;

namespace SysadminsLV.PKI.Win32 {
    /// <summary>
    /// Contains only unmanaged function p/invoke definitions which are defined in <strong>AdvAPI.dll</strong> library.
    /// </summary>
    static class AdvAPI {
        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        internal static extern Boolean CryptEnumProviders(
            UInt32 dwIndex,
            UInt32 pdwReserved,
            UInt32 dwFlags,
            ref UInt32 pdwProvType,
            StringBuilder pszProvName,
            ref UInt32 pcbProvName
        );
        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        internal static extern Boolean CryptEnumProviderTypes(
            UInt32 dwIndex,
            UInt32 pdwReserved,
            UInt32 dwFlags,
            ref UInt32 pdwProvType,
            StringBuilder pszTypeName,
            ref UInt32 pcbTypeName
        );
        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern Boolean CryptAcquireContext(
           ref IntPtr phProv,
           String pszContainer,
           String pszProvider,
           UInt32 dwProvType,
           Int64 dwFlags
        );
        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        internal static extern Boolean CryptGetProvParam(
            IntPtr hProv,
            UInt32 dwParam,
            Byte[] pbData,
            ref Int32 pdwDataLen,
            UInt32 dwFlags
        );
        [DllImport("advapi32.dll", SetLastError = true)]
        internal static extern Boolean CryptGetProvParam(
            IntPtr hProv,
            UInt32 dwParam,
            Wincrypt.PROV_ENUMALGS_EX pbData,
            ref UInt32 pdwDataLen,
            UInt32 dwFlags
        );
        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern Boolean CryptReleaseContext(
           IntPtr hProv,
           UInt32 dwFlags
        );
        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern Boolean CryptCreateHash(
            IntPtr hProv,
            UInt32 Algid,
            IntPtr hKey,
            UInt32 dwFlags,
            ref IntPtr phHash
        );
        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern Boolean CryptSignHash(
            IntPtr hHash,
            UInt32 dwKeySpec,
            String sDescription,
            UInt32 dwFlags,
            Byte[] pbSignature,
            UInt32 pdwSigLen
        );
        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern Boolean CryptGetUserKey(
            IntPtr hProv,
            UInt32 dwKeySpec,
            ref IntPtr phUserKey
        );
        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern Boolean CryptExportKey(
            IntPtr hKey,
            IntPtr hExpKey,
            UInt32 dwBlobType,
            UInt32 dwFlags,
            Byte[] pbData,
            ref UInt32 pdwDataLen
        );
        /// <summary>
        /// No topic.
        /// </summary>
        /// <param name="hKey">No topic.</param>
        /// <returns>No topic.</returns>
        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern Boolean CryptDestroyKey(
            IntPtr hKey
        );
    }
}
