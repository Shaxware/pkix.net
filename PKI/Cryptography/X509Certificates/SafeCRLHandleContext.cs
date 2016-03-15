using System.Security.Permissions;
using Microsoft.Win32.SafeHandles;
using PKI;
using PKI.Exceptions;

namespace System.Security.Cryptography.X509Certificates {
	/// <summary>
	/// <para>
	/// SafeCRLHandleContext provides a SafeHandle class for an X509Certificate's certificate context
	/// as stored in its <see cref="System.Security.Cryptography.X509Certificates.X509CRL2.Handle" />
	/// property.  This can be used instead of the raw IntPtr to avoid races with the garbage
	/// collector, ensuring that the X509Certificate object is not cleaned up from underneath you
	/// while you are still using the handle pointer.
	/// </para>
	/// <para>
	/// This safe handle type represents a native CRL_CONTEXT.
	/// </para>
	/// <para>
	/// A SafeCRLHandleContext for an X509CRL2 can be obtained by calling the <see
	/// cref="System.Security.Cryptography.X509Certificates.X509CRL2.GetSafeContext" /> extension method.
	/// </para>
	/// </summary>
	/// <permission cref="SecurityPermission">
	///     The immediate caller must have SecurityPermission/UnmanagedCode to use this type.
	/// </permission>
	[SecurityPermission(SecurityAction.LinkDemand, UnmanagedCode = true)]
	public sealed class SafeCRLHandleContext : SafeHandleZeroOrMinusOneIsInvalid {
		SafeCRLHandleContext() : base(true) { }
		/// <summary>
		/// Releases persistent handle and frees allocated resources.
		/// </summary>
		/// <exception cref="UninitializedObjectException">If <see cref="X509CRL2"/> object is not initialized.</exception>
		/// <returns><strong>True</strong> if the operation succeeds, otherwise <strong>False</strong>.</returns>
		protected override Boolean ReleaseHandle() {
			if (!handle.Equals(IntPtr.Zero)) {
				return Crypt32.CertFreeCRLContext(handle);
			}
			throw new UninitializedObjectException();
		}
	}
}
