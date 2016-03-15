
namespace System.Security.Cryptography.X509Certificates {
	/// <summary>
	/// Represents a X.509 certificate trust list (<strong>CTL</strong>) entry element. Generally, this elements describes the
	/// certificate in the trust list.
	/// </summary>
	public class X509CTLEntry {

		internal X509CTLEntry(String thumprint, X509AttributeCollection attributes) {
			m_initialize(thumprint, attributes);
		}

		/// <summary>
		/// Gets certificate's thumbprint value.
		/// </summary>
		public String Thumbprint { get; private set; }
		/// <summary>
		/// Gets a collection of attributes associated with the current certificate.
		/// </summary>
		public X509AttributeCollection Attributes { get; private set; }
		/// <summary>
		/// Gets a pointer to a X509Certificate2 object which is described by this object. If the certificate is not installed
		/// on the current system, the property returns <see cref="IntPtr.Zero">Zero</see>.
		/// </summary>
		public IntPtr Certificate { get; private set; }

		void m_initialize(String thumprint, X509AttributeCollection attributes) {
			Thumbprint = thumprint;
			Attributes = attributes;
			get_cert();
		}
		void get_cert() {
			Certificate = IntPtr.Zero;
		}

		/// <summary>
		/// Gets a textual representation of the <see cref="X509CTLEntry"/> object.
		/// </summary>
		/// <returns>The <strong>X509CTLEntry</strong> information.</returns>
		public override String ToString() {
			return Thumbprint;
		}
	}
}
