using System.Security.AccessControl;
using System.Security.Principal;

namespace SysadminsLV.PKI.Security.AccessControl {
    /// <summary>
    /// Represents an abstraction of an access control entry (ACE) that defines an access rule for certificate template.
    /// This class cannot be inherited.
    /// </summary>
    public sealed class CertTemplateAccessRule : AccessRule<CertTemplateRights> {
        public CertTemplateAccessRule(
            IdentityReference identity,
            CertTemplateRights accessMask,
            AccessControlType type) : base(identity, accessMask, InheritanceFlags.None, PropagationFlags.None, type) { }

        /// <summary>
        /// Gets the <see cref="CertTemplateRights"/> flags associated with the current
        /// <see cref="CertTemplateAccessRule"/> object.
        /// </summary>
        public CertTemplateRights CertificateTemplateRights => (CertTemplateRights)AccessMask;
    }
}