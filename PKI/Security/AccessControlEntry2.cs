using System.Security.AccessControl;
using System.Security.Principal;

namespace PKI.Security {
	/// <summary>
	/// Represents a simplified version of access control entry (ACE).
	/// </summary>
	/// <remarks>This class is marked for deletion. A new constructions will be available.</remarks>
	public class AccessControlEntry2 {
		/// <summary>
		/// Specifies a reference to an identity in the subject.
		/// </summary>
		public NTAccount IdentityReference { get; set; }
		/// <summary>
		/// Specifies whether an AccessRule object is used to allow or deny access. These values are not flags, and they cannot be combined.
		/// </summary>
		public AccessControlType AccessType { get; set; }
		/// <summary>
		/// Gets permissions granted to an account specified in <see cref="IdentityReference"/> property.
		/// </summary>
		public TemplateRight[] Permissions { get; set; }
	}
}
