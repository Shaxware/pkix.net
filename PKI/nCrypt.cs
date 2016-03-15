using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace PKI {
	static class nCrypt {
		[DllImport("ncrypt.dll", SetLastError = true)]
		public static extern UInt32 NCryptEnumStorageProviders(
			ref UInt32 pImplCount,
			ref IntPtr ppImplList,
			UInt32 dwFlags
		);
		[DllImport("ncrypt.dll", SetLastError = true)]
		public static extern UInt32 NCryptOpenStorageProvider(
			ref IntPtr phProvider,
			[MarshalAs(UnmanagedType.LPWStr)]
			String pszProviderName,
			UInt32 dwFlags
		);
		[DllImport("ncrypt.dll", SetLastError = true)]
		public static extern UInt32 NCryptEnumAlgorithms(
			IntPtr hProvider,
			UInt32 dwAlgOperations,
			ref Int32 pdwAlgCount,
			ref IntPtr ppAlgList,
			UInt32 dwFlags
		);
		[DllImport("ncrypt.dll", SetLastError = true)]
		public static extern UInt32 NCryptFreeBuffer(
			[In]			IntPtr pvInput
		);
		[DllImport("ncrypt.dll", SetLastError = true)]
		public static extern UInt32 NCryptFreeObject(
			[In]			IntPtr phProvider
		);
		[DllImport("ncrypt.dll", SetLastError = true)]
		public static extern int NCryptEnumKeys(
			IntPtr hProvider,
			[MarshalAs(UnmanagedType.LPWStr)]
			String pszScope,
			ref IntPtr ppKeyName,
			ref IntPtr ppEnumState,
			UInt32 dwFlags
		);
		[DllImport("ncrypt.dll", SetLastError = true)]
		public static extern Int32 NCryptOpenKey(
			[In]			IntPtr hProvider,
			[In, Out] ref	IntPtr phKey,
			[MarshalAs(UnmanagedType.LPWStr)]
			[In]			String pszKeyName,
			[In]			UInt32 dwLegacyKeySpec,
			[In]			UInt32 dwFlags
		);
		[DllImport("ncrypt.dll", SetLastError = true)]
		public static extern Int32 NCryptExportKey(
			[In]			IntPtr hKey,
			[In, Optional]	IntPtr hExportKey,
			[MarshalAs(UnmanagedType.LPWStr)]
			[In]			String pszBlobType,
			[In, Optional]	IntPtr pParameterList,
			[In, Out] ref	Byte[] pbOutput,
			[In]			UInt32 cbOutput,
			[In]			UInt32 pcbResult,
			[In]			UInt32 dwFlags
		);
		[DllImport("ncrypt.dll", SetLastError = true)]
		public static extern int NCryptSignHash(
			[In]			IntPtr hKey,
			[In, Optional]	IntPtr pPaddingInfo,
			[MarshalAs(UnmanagedType.LPArray)]
			Byte[]			pbHashValue,
			UInt32			cbHashValue,
			[MarshalAs(UnmanagedType.LPArray)]
			Byte[]			pbSignature,
			UInt32			cbSignature,
			[Out]out uint	pcbResult,
			UInt32			dwFlags
		);
	}
}
