using System;
using System.Security.AccessControl;
using System.Security.Principal;

namespace SysadminsLV.PKI.Security.AccessControl {
    /// <summary>
    /// Represents an abstraction of an access control entry (ACE) that defines an access rule for a Microsoft Online Responder.
    /// This class cannot be inherited.
    /// </summary>
    public sealed class OcspResponderAccessRule : AccessRule {

        /// <param name="identity">
        ///		An IdentityReference object that encapsulates a reference to a user account.
        /// </param>
        /// <param name="accessMask">
        ///		One of the <see cref="OnlineResponderRights"/> values that specifies the type of operation
        ///		associated with the access rule.
        /// </param>
        /// <param name="type">
        ///		One of the <see cref="AccessControlType"/> values that specifies whether to allow or deny the operation.
        /// </param>
        public OcspResponderAccessRule(
            IdentityReference identity,
            OcspResponderRights accessMask,
            AccessControlType type)
            : base(identity, AccessMaskFromRights(accessMask), false, InheritanceFlags.None, PropagationFlags.None, type) { }

        /// <summary>
        /// Gets the <see cref="OnlineResponderRights"/> flags associated with the current
        /// <see cref="OcspResponderAccessRule"/> object.
        /// </summary>
        public OcspResponderRights OnlineResponderRights => RightsFromAccessMask(AccessMask);

        static OcspResponderRights RightsFromAccessMask(Int32 accessMask) {
            return (OcspResponderRights)accessMask;
        }
        static Int32 AccessMaskFromRights(OcspResponderRights rights) {
            return (Int32)rights;
        }
    }
}