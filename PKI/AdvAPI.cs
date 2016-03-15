using System;
using System.Runtime.InteropServices;
using System.Text;
using PKI.Structs;

namespace PKI {
	/// <summary>
	/// Contains only unmanaged function p/invoke definitions which are defined in <strong>AdvAPI.dll</strong> library.
	/// </summary>
	public static class AdvAPI {
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
		/// <summary>
		/// This method is a p/invoke version of <see href="http://msdn.microsoft.com/en-us/library/aa379886(VS.85).aspx">CryptAcquireContext</see> function.
		/// </summary>
		/// <param name="phProv">This parameter is a p/invoke version of <see href="http://msdn.microsoft.com/en-us/library/aa379886(VS.85).aspx">CryptAcquireContext</see> function.</param>
		/// <param name="pszContainer">This parameter is a p/invoke version of <see href="http://msdn.microsoft.com/en-us/library/aa379886(VS.85).aspx">CryptAcquireContext</see> function.</param>
		/// <param name="pszProvider">This parameter is a p/invoke version of <see href="http://msdn.microsoft.com/en-us/library/aa379886(VS.85).aspx">CryptAcquireContext</see> function.</param>
		/// <param name="dwProvType">This parameter is a p/invoke version of <see href="http://msdn.microsoft.com/en-us/library/aa379886(VS.85).aspx">CryptAcquireContext</see> function.</param>
		/// <param name="dwFlags">This parameter is a p/invoke version of <see href="http://msdn.microsoft.com/en-us/library/aa379886(VS.85).aspx">CryptAcquireContext</see> function.</param>
		/// <returns>If the function succeeds, the return value is nonzero (<strong>TRUE</strong>). If the function fails, the return value is zero (<strong>FALSE</strong>).</returns>
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
		/// <summary>
		/// This method is a p/invoke version of <see href="http://msdn.microsoft.com/en-us/library/aa380268(VS.85).aspx">CryptReleaseContext</see> function.
		/// </summary>
		/// <param name="hProv">This method is a p/invoke version of <see href="http://msdn.microsoft.com/en-us/library/aa380268(VS.85).aspx">CryptReleaseContext</see> function.</param>
		/// <param name="dwFlags">This method is a p/invoke version of <see href="http://msdn.microsoft.com/en-us/library/aa380268(VS.85).aspx">CryptReleaseContext</see> function.</param>
		/// <returns></returns>
		[DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
		public static extern Boolean CryptReleaseContext(
		   IntPtr hProv,
		   UInt32 dwFlags
		);
		/// <summary>
		/// This method is a p/invoke version of <see href="http://msdn.microsoft.com/en-us/library/aa379908(VS.85).aspx">CryptCreateHash</see> function.
		/// </summary>
		/// <param name="hProv">This method is a p/invoke version of <see href="http://msdn.microsoft.com/en-us/library/aa379908(VS.85).aspx">CryptCreateHash</see> function.</param>
		/// <param name="Algid">This method is a p/invoke version of <see href="http://msdn.microsoft.com/en-us/library/aa379908(VS.85).aspx">CryptCreateHash</see> function.</param>
		/// <param name="hKey">This method is a p/invoke version of <see href="http://msdn.microsoft.com/en-us/library/aa379908(VS.85).aspx">CryptCreateHash</see> function.</param>
		/// <param name="dwFlags">This method is a p/invoke version of <see href="http://msdn.microsoft.com/en-us/library/aa379908(VS.85).aspx">CryptCreateHash</see> function.</param>
		/// <param name="phHash">This method is a p/invoke version of <see href="http://msdn.microsoft.com/en-us/library/aa379908(VS.85).aspx">CryptCreateHash</see> function.</param>
		/// <returns></returns>
		[DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
		public static extern Boolean CryptCreateHash(
			IntPtr hProv,
			UInt32 Algid,
			IntPtr hKey,
			UInt32 dwFlags,
			ref IntPtr phHash
		);
		/// <summary>
		/// This method is a p/invoke version of <see href="http://msdn.microsoft.com/en-us/library/aa380280(VS.85).aspx">CryptSignHash</see> function.
		/// </summary>
		/// <param name="hHash">This method is a p/invoke version of <see href="http://msdn.microsoft.com/en-us/library/aa380280(VS.85).aspx">CryptSignHash</see> function.</param>
		/// <param name="dwKeySpec">This method is a p/invoke version of <see href="http://msdn.microsoft.com/en-us/library/aa380280(VS.85).aspx">CryptSignHash</see> function.</param>
		/// <param name="sDescription">This method is a p/invoke version of <see href="http://msdn.microsoft.com/en-us/library/aa380280(VS.85).aspx">CryptSignHash</see> function.</param>
		/// <param name="dwFlags">This method is a p/invoke version of <see href="http://msdn.microsoft.com/en-us/library/aa380280(VS.85).aspx">CryptSignHash</see> function.</param>
		/// <param name="pbSignature">This method is a p/invoke version of <see href="http://msdn.microsoft.com/en-us/library/aa380280(VS.85).aspx">CryptSignHash</see> function.</param>
		/// <param name="pdwSigLen">This method is a p/invoke version of <see href="http://msdn.microsoft.com/en-us/library/aa380280(VS.85).aspx">CryptSignHash</see> function.</param>
		/// <returns></returns>
		[DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
		public static extern Boolean CryptSignHash(
			IntPtr hHash,
			UInt32 dwKeySpec,
			String sDescription,
			UInt32 dwFlags,
			Byte[] pbSignature,
			UInt32 pdwSigLen
		);
		/// <summary>
		/// No topic.
		/// </summary>
		/// <param name="hProv">No topic.</param>
		/// <param name="dwKeySpec">No topic.</param>
		/// <param name="phUserKey">No topic.</param>
		/// <returns>No topic.</returns>
		[DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
		public static extern Boolean CryptGetUserKey(
			IntPtr hProv,
			UInt32 dwKeySpec,
			ref IntPtr phUserKey
		);
		/// <summary>
		/// No topic.
		/// </summary>
		/// <param name="hKey">No topic.</param>
		/// <param name="hExpKey">No topic.</param>
		/// <param name="dwBlobType">No topic.</param>
		/// <param name="dwFlags">No topic.</param>
		/// <param name="pbData">No topic.</param>
		/// <param name="pdwDataLen">No topic.</param>
		/// <returns>No topic.</returns>
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
