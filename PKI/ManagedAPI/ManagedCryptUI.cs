using System;
using System.Security.Cryptography.X509Certificates;

namespace PKI.ManagedAPI {
	/// <summary>
	/// Contains safe implementations of unmanaged functions.
	/// </summary>
	public class ManagedCryptUI {
		/// <summary>
		/// Displays a X.509 Certificate Revocation List UI dialog.
		/// </summary>
		/// <param name="crl">An object to display.</param>
		public static void DisplayCRL(X509CRL2 crl) {
			if (IntPtr.Zero.Equals(crl.Handle)) { return; }
			CryptUI.CryptUIDlgViewContext(2, crl.Handle, IntPtr.Zero, "Certificate Revocation List", 0, 0);
		}
		/// <summary>
		/// Displays a X.509 Certificate Trust List UI dialog.
		/// </summary>
		/// <param name="ctl">An object to display.</param>
		public static void DisplayCTL(X509CTL ctl) {
			if (IntPtr.Zero.Equals(ctl.Handle)) { return; }
			CryptUI.CryptUIDlgViewContext(3, ctl.Handle, IntPtr.Zero, "Certificate Trust List", 0, 0);
		}
	}
}
