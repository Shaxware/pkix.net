using System;
using System.Security.AccessControl;
using System.Security.Principal;

namespace SysadminsLV.PKI.Security.AccessControl {
    sealed class OcspResponderAuditRule : AuditRule {
        public OcspResponderAuditRule(
            IdentityReference identity,
            OcspResponderRights accessMask,
            AuditFlags flags)
            : base(identity, AccessMaskFromRights(accessMask), false, InheritanceFlags.None, PropagationFlags.None, flags) { }

        public OcspResponderRights OnlineResponderRights => RightsFromAccessMask(AccessMask);

        static OcspResponderRights RightsFromAccessMask(Int32 accessMask) {
            return (OcspResponderRights)accessMask;
        }
        static Int32 AccessMaskFromRights(OcspResponderRights rights) {
            return (Int32)rights;
        }
    }
}
