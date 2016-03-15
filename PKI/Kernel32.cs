using System;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;
using System.Security;

namespace PKI {
	/// <summary>
	/// Contains only unmanaged function p/invoke definitions which are defined in <strong>Kernel32.dll</strong> library.
	/// </summary>
	public static class Kernel32 {
		/// <summary>
		/// This method is a p/invoke version of <see href="http://msdn.microsoft.com/en-us/library/ms679351(VS.85).aspx">FormatMessage</see> function.
		/// </summary>
		/// <param name="dwFlags">This method is a p/invoke version of <see href="http://msdn.microsoft.com/en-us/library/ms679351(VS.85).aspx">FormatMessage</see> function.</param>
		/// <param name="lpSource">This method is a p/invoke version of <see href="http://msdn.microsoft.com/en-us/library/ms679351(VS.85).aspx">FormatMessage</see> function.</param>
		/// <param name="dwMessageId">This method is a p/invoke version of <see href="http://msdn.microsoft.com/en-us/library/ms679351(VS.85).aspx">FormatMessage</see> function.</param>
		/// <param name="dwLanguageId">This method is a p/invoke version of <see href="http://msdn.microsoft.com/en-us/library/ms679351(VS.85).aspx">FormatMessage</see> function.</param>
		/// <param name="lpBuffer">This method is a p/invoke version of <see href="http://msdn.microsoft.com/en-us/library/ms679351(VS.85).aspx">FormatMessage</see> function.</param>
		/// <param name="nSize">This method is a p/invoke version of <see href="http://msdn.microsoft.com/en-us/library/ms679351(VS.85).aspx">FormatMessage</see> function.</param>
		/// <param name="Arguments">This method is a p/invoke version of <see href="http://msdn.microsoft.com/en-us/library/ms679351(VS.85).aspx">FormatMessage</see> function.</param>
		/// <returns></returns>
		[DllImport("kernel32.dll", SetLastError = true)]
		public static extern uint FormatMessage(
			uint dwFlags,
			IntPtr lpSource,
			int dwMessageId,
			uint dwLanguageId,
			ref IntPtr lpBuffer,
			uint nSize,
			IntPtr Arguments
		);
		/// <summary>
		/// This method is a p/invoke version of <see href="http://msdn.microsoft.com/en-us/library/ms684175(VS.85).aspx">LoadLibrary</see> function.
		/// </summary>
		/// <param name="lpFileName">This method is a p/invoke version of <see href="http://msdn.microsoft.com/en-us/library/ms684175(VS.85).aspx">LoadLibrary</see> function.</param>
		/// <returns></returns>
		[DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
		public static extern IntPtr LoadLibrary(
			[In] String lpFileName
		);
		/// <summary>
		/// This method is a p/invoke version of <see href="http://msdn.microsoft.com/en-us/library/ms683152(VS.85).aspx">FreeLibrary</see> function.
		/// </summary>
		/// <param name="hModule">This method is a p/invoke version of <see href="http://msdn.microsoft.com/en-us/library/ms683152(VS.85).aspx">FreeLibrary</see> function.</param>
		/// <returns></returns>
		[DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
		public static extern bool FreeLibrary(
			[In] IntPtr hModule
		);
		/// <summary>
		/// This method is a p/invoke version of <see href="http://msdn.microsoft.com/en-us/library/ms684179(VS.85).aspx">LoadLibraryEx</see> function.
		/// </summary>
		/// <param name="lpFileName">This method is a p/invoke version of <see href="http://msdn.microsoft.com/en-us/library/ms684179(VS.85).aspx">LoadLibraryEx</see> function.</param>
		/// <param name="hFile">This method is a p/invoke version of <see href="http://msdn.microsoft.com/en-us/library/ms684179(VS.85).aspx">LoadLibraryEx</see> function.</param>
		/// <param name="dwFlags">This method is a p/invoke version of <see href="http://msdn.microsoft.com/en-us/library/ms684179(VS.85).aspx">LoadLibraryEx</see> function.</param>
		/// <returns></returns>
		[DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
		public static extern IntPtr LoadLibraryEx(
			[In] String lpFileName,
			[In] IntPtr hFile,
			[In] UInt32 dwFlags
		);
		/// <summary>
		/// This method is a p/invoke version of <see href="http://msdn.microsoft.com/en-us/library/aa366730(VS.85).aspx">LocalFree</see> function.
		/// </summary>
		/// <param name="hMem">This method is a p/invoke version of <see href="http://msdn.microsoft.com/en-us/library/aa366730(VS.85).aspx">LocalFree</see> function.</param>
		/// <returns></returns>
		[DllImport("kernel32.dll")]
		[ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
		[SuppressUnmanagedCodeSecurity]
		[SuppressMessage("Microsoft.Design", "CA1060:MovePInvokesToNativeMethodsClass", Justification = "SafeHandle release method")]
		public static extern IntPtr LocalFree(
			IntPtr hMem
		);
	}
}
