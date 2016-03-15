using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using PKI;

namespace System.Security.Cryptography {
	internal sealed class SafeLocalAllocHandle : SafeHandleZeroOrMinusOneIsInvalid {
		
		SafeLocalAllocHandle()	: base(true) {	}

		[SuppressMessage(
			"Microsoft.Security",
			"CA2122:DoNotIndirectlyExposeMethodsWithLinkDemands",
			Justification = "Protected as a SecurityCritical method"
		)]
		internal T Read<T>(int Offset) where T : struct {
			bool addedRef = false;
			RuntimeHelpers.PrepareConstrainedRegions();
			try {
				DangerousAddRef(ref addedRef);

				unsafe {
					IntPtr pBase = new IntPtr((byte*)handle.ToPointer() + Offset);
					return (T)Marshal.PtrToStructure(pBase, typeof(T));
				}
			} finally { if (addedRef) { DangerousRelease(); } }

		}

		protected override bool ReleaseHandle() {
			return Kernel32.LocalFree(handle) == IntPtr.Zero;
		}
	}
}
