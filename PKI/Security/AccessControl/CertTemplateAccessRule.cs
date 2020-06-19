using System;
using System.Security.AccessControl;
using System.Security.Principal;

namespace SysadminsLV.PKI.Security.AccessControl {
    public class CertTemplateAccessRule : AccessRule {
        public CertTemplateAccessRule(
            IdentityReference identity,
            CertTemplateRights accessMask,
            AccessControlType type) : base(identity, (Int32)accessMask, false, InheritanceFlags.None, PropagationFlags.None, type) { }

        public CertTemplateRights CertificateTemplateRights => (CertTemplateRights)AccessMask;
    }
}