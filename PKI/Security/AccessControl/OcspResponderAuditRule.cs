using System.Security.AccessControl;
using System.Security.Principal;

namespace SysadminsLV.PKI.Security.AccessControl {
    public sealed class OcspResponderAuditRule : AuditRule<OcspResponderRights> {
        public OcspResponderAuditRule(
            IdentityReference identity,
            OcspResponderRights accessMask,
            AuditFlags flags)
            : base(identity, accessMask, InheritanceFlags.None, PropagationFlags.None, flags) { }

        public OcspResponderRights OnlineResponderRights => (OcspResponderRights)AccessMask;
    }
}
