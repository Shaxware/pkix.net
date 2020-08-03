using System.Security.AccessControl;
using System.Security.Principal;

namespace SysadminsLV.PKI.Security.AccessControl {
    /// <summary>
    /// Represents an audit rule object used in Online Responder ACL.
    /// </summary>
    public sealed class OcspResponderAuditRule : AuditRule<OcspResponderRights> {
        /// <inheritdoc />
        public OcspResponderAuditRule(
            IdentityReference identity,
            OcspResponderRights accessMask,
            AuditFlags flags)
            : base(identity, accessMask, InheritanceFlags.None, PropagationFlags.None, flags) { }

        /// <summary>
        /// Gets a combination of access types audited by this audit rule.
        /// </summary>
        public OcspResponderRights OnlineResponderRights => (OcspResponderRights)AccessMask;
    }
}
