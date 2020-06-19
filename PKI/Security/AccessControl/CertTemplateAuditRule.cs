using System.Security.AccessControl;
using System.Security.Principal;

namespace SysadminsLV.PKI.Security.AccessControl {
    sealed class CertTemplateAuditRule : AuditRule <CertTemplateRights> {
        public CertTemplateAuditRule(
            IdentityReference identity,
            CertTemplateRights accessMask,
            AuditFlags flags)
            : base(identity, accessMask, InheritanceFlags.None, PropagationFlags.None, flags) { }

        public CertTemplateRights CertificationTemplateRights => (CertTemplateRights)AccessMask;
    }
}