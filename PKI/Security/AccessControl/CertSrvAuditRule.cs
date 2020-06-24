using System.Security.AccessControl;
using System.Security.Principal;

namespace SysadminsLV.PKI.Security.AccessControl {
    /// <summary>
    /// Represents certification authority audit rule object.
    /// </summary>
    public sealed class CertSrvAuditRule : AuditRule<CertSrvRights> {

        public CertSrvAuditRule(
            IdentityReference identity,
            CertSrvRights accessMask,
            AuditFlags flags)
            : base(identity, accessMask, InheritanceFlags.None, PropagationFlags.None, flags) { }

        /// <summary>
        /// Gets the access mask enabled for audit in the current audit control entry.
        /// </summary>
        public CertSrvRights CertificationAuthorityRights => (CertSrvRights)AccessMask;
    }
}
