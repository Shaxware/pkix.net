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
            : base(identity, (Int32)accessMask, false, InheritanceFlags.None, PropagationFlags.None, flags) { }

        public CertSrvRights CertificationAuthorityRights => (CertSrvRights)AccessMask;
    }
}
