using System;
using System.Security.AccessControl;
using System.Security.Principal;

namespace SysadminsLV.PKI.Management.CertificateServices {
    /// <summary>
    /// Reserved.
    /// </summary>
    sealed class AdcsCAAuditRule : AuditRule {

        public AdcsCAAuditRule(
            IdentityReference identity,
            AdcsCertificationAuthorityRights accessMask,
            AuditFlags flags)
            : base(identity, AccessMaskFromRights(accessMask), false, InheritanceFlags.None, PropagationFlags.None, flags) { }

        public AdcsCertificationAuthorityRights CertificationAuthorityRights => RightsFromAccessMask(AccessMask);

        static AdcsCertificationAuthorityRights RightsFromAccessMask(int accessMask) {
            return (AdcsCertificationAuthorityRights)accessMask;
        }
        static Int32 AccessMaskFromRights(AdcsCertificationAuthorityRights rights) {
            return (Int32)rights;
        }
    }
}
