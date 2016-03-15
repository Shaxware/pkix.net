using System;
using System.Security.AccessControl;
using System.Security.Principal;

namespace PKI.Security.AccessControl {
	/// <summary>
	/// Represents an abstraction of an access control entry (ACE) that defines an access rule for a Certification
	/// Authority. This class cannot be inherited.
	/// </summary>
	public sealed class CertificationAuthorityAccessRule : AccessRule {

		/// <param name="identity">
		///		An IdentityReference object that encapsulates a reference to a user account.
		/// </param>
		/// <param name="accessMask">
		///		One of the <see cref="CertificationAuthorityRights"/> values that specifies the type of operation
		///		associated with the access rule.
		/// </param>
		/// <param name="type">
		///		One of the <see cref="AccessControlType"/> values that specifies whether to allow or deny the operation.
		/// </param>
		public CertificationAuthorityAccessRule(
			IdentityReference identity,
			CertificationAuthorityRights accessMask,
			AccessControlType type)
			: base(identity, AccessMaskFromRights(accessMask), false, InheritanceFlags.None, PropagationFlags.None, type) { }

		/// <summary>
		/// Gets the <see cref="CertificationAuthorityRights"/> flags associated with the current
		/// <see cref="CertificationAuthorityAccessRule"/> object.
		/// </summary>
		public CertificationAuthorityRights CertificationAuthorityRights {
			get {
				return RightsFromAccessMask(AccessMask);
			}
		}
		static CertificationAuthorityRights RightsFromAccessMask(int accessMask) {
			return (CertificationAuthorityRights)accessMask;
		}
		static Int32 AccessMaskFromRights(CertificationAuthorityRights rights) {
			return (Int32)rights;
		}
	}
}
