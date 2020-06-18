using System;
using System.Security.AccessControl;
using System.Security.Principal;

namespace SysadminsLV.PKI.Security.AccessControl {
    /// <summary>
    /// Reserved.
    /// </summary>
    sealed class CertSrvAuditRule : AuditRule {

        public CertSrvAuditRule(
            IdentityReference identity,
            CertSrvRights accessMask,
            AuditFlags flags)
            : base(identity, AccessMaskFromRights(accessMask), false, InheritanceFlags.None, PropagationFlags.None, flags) { }

        public CertSrvRights CertificationAuthorityRights => RightsFromAccessMask(AccessMask);

        static CertSrvRights RightsFromAccessMask(Int32 accessMask) {
            return (CertSrvRights)accessMask;
        }
        static Int32 AccessMaskFromRights(CertSrvRights rights) {
            return (Int32)rights;
        }
    }
}
