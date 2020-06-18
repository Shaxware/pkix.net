using System;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Principal;
using PKI.CertificateServices;
using PKI.Exceptions;
using PKI.Utils;

namespace SysadminsLV.PKI.Security.AccessControl {
    /// <summary>
    /// Represents the access control for a Certification Authority.
    /// </summary>
    /// <remarks>This class has no public constructors.</remarks>
    public sealed class CertSrvSecurityDescriptor : CommonObjectSecurity {
        readonly String _name;
        readonly String _config;

        internal CertSrvSecurityDescriptor(CertificateAuthority certificationAuthority) : base(false) {
            DisplayName = certificationAuthority.DisplayName;
            ComputerName = certificationAuthority.ComputerName;
            _name = certificationAuthority.Name;
            _config = certificationAuthority.ConfigString;
        }
        /// <summary>
        /// Gets the display name of the Certification Authority (sanitized characters are decoded to textual characters)
        /// associated with the current instance of the object.
        /// </summary>
        public String DisplayName { get; }
        /// <summary>
        /// Gets the host fully qualified domain name (FQDN) of the server where Certification Authority is installed.
        /// </summary>
        public String ComputerName { get; }

        /// <summary>
        /// Initializes a new instance of the <see cref="CertSrvAccessRule"/> class that represents a new access
        /// control rule for the specified user, with the specified access rights, access control, and flags.
        /// </summary>
        /// <param name="identityReference">
        ///		An <see cref="IdentityReference"/> object that represents a user account.
        /// </param>
        /// <param name="accessMask">
        ///		An integer that specifies an access type.
        /// </param>
        /// <param name="isInherited">
        ///		<strong>True</strong> if the access rule is inherited; otherwise, <strong>False</strong>. This parameter
        ///		is not used and is always set to <strong>False</strong>.
        /// </param>
        /// <param name="inheritanceFlags">
        ///		One of the <see cref="InheritanceFlags"/> values that specifies how to propagate access masks to child
        ///		objects. This parameter is not used and is always set to <strong>None</strong>.
        /// </param>
        /// <param name="propagationFlags">
        ///		One of the <see cref="PropagationFlags"/> values that specifies how to propagate Access Control Entries
        ///		(ACEs) to child objects. This parameter is not used and is always set to <strong>None</strong>.
        /// </param>
        /// <param name="type">
        ///		One of the <see cref="AccessControlType"/> values that specifies whether access is allowed or denied.
        /// </param>
        /// <returns>
        ///		A new <see cref="CertSrvAccessRule"/> object that represents a new access control rule
        ///		for the specified user, with the specified access rights, access control, and flags.
        /// </returns>
        public override AccessRule AccessRuleFactory(IdentityReference identityReference, Int32 accessMask, Boolean isInherited,
            InheritanceFlags inheritanceFlags, PropagationFlags propagationFlags, AccessControlType type) {
            return new CertSrvAccessRule(identityReference, (CertSrvRights)accessMask, type);
        }
        ///  <summary>
        ///  This member is not implemented.
        ///  </summary>
        ///  <param name="identityReference">
        /// 		An <see cref="IdentityReference"/> object that represents a user account.
        ///  </param>
        ///  <param name="accessMask">
        /// 		An integer that specifies an access type.
        ///  </param>
        ///  <param name="isInherited">
        /// 		<strong>True</strong> if the access rule is inherited; otherwise, <strong>False</strong>. This parameter
        /// 		is not used and is always set to <strong>False</strong>.
        ///  </param>
        ///  <param name="inheritanceFlags">
        /// 		One of the <see cref="InheritanceFlags"/> values that specifies how to propagate access masks to child
        /// 		objects. This parameter is not used and is always set to <strong>None</strong>.
        ///  </param>
        ///  <param name="propagationFlags">
        /// 		One of the <see cref="PropagationFlags"/> values that specifies how to propagate Access Control Entries
        /// 		(ACEs) to child objects. This parameter is not used and is always set to <strong>None</strong>.
        ///  </param>
        ///  <param name="flags">
        /// 		One of the <see cref="AuditFlags"/> values that specifies the type of auditing to perform.
        ///  </param>
        /// <exception cref="NotSupportedException">The exception is thrown when the method is invoked.</exception>
        /// <returns>This method always throws exception.</returns>
        /// <remarks>This member is not implemented.</remarks>
        public override AuditRule AuditRuleFactory(IdentityReference identityReference, Int32 accessMask, Boolean isInherited,
            InheritanceFlags inheritanceFlags, PropagationFlags propagationFlags, AuditFlags flags) {
            //return new CertificationAuthorityAuditRule(identityReference, (CertificationAuthorityRights)accessMask, flags);
            throw new NotSupportedException(Error.E_AUDITNOTSUPPOERTED);
        }
        /// <summary>
        ///		Adds the specified access rule to the Discretionary Access Control List (DACL) associated with this
        ///		<see cref="CommonObjectSecurity"/> object.
        /// </summary>
        /// <param name="rule">The access rule to add.</param>
        /// <returns><strong>True</strong> if the access rule was added, otherwise <strong>False</strong>.</returns>
        /// <remarks>
        ///		The method does nothing if current DACL already contains identity specified in the <strong>rule</strong>
        ///		parameter. DACL merging is not supported.
        /// </remarks>
        public Boolean AddAccessRule(CertSrvAccessRule rule) {
            AuthorizationRuleCollection rules = GetAccessRules(true, false, typeof(NTAccount));
            if (rules.Cast<AuthorizationRule>().Any(x => x.IdentityReference.Value == rule.IdentityReference.Value)) {
                return false;
            }
            base.AddAccessRule(rule);
            return true;
        }
        ///  <summary>
        ///  This member is not implemented.
        ///  </summary>
        ///  <param name="modification">
        /// 		The modification to apply to the SACL.
        ///  </param>
        ///  <param name="rule">
        /// 		The audit rule to modify.
        ///  </param>
        ///  <param name="modified">
        /// 		<strong>True</strong> if the SACL is successfully modified; otherwise, <strong>False</strong>.
        ///  </param>
        /// <exception cref="NotSupportedException">The exception is thrown when the method is invoked.</exception>
        /// <returns>This method always throws exception.</returns>
        ///  <remarks>This member is not implemented.</remarks>
        public override Boolean ModifyAuditRule(AccessControlModification modification, AuditRule rule, out Boolean modified) {
            throw new NotSupportedException("Audit rules are not supported for this object");
        }
        /// <summary>
        /// This member is not implemented.
        /// </summary>
        /// <param name="identity">
        ///		An <see cref="IdentityReference"/> object that represents a user account.
        /// </param>
        /// <exception cref="NotSupportedException">The exception is thrown when the method is invoked.</exception>
        public override void PurgeAuditRules(IdentityReference identity) {
            throw new NotSupportedException("Audit rules are not supported for this object");
        }
        /// <summary>
        /// Gets the <see cref="Type"/> of the securable object associated with this <see cref="ObjectSecurity"/> object.
        /// </summary>
        public override Type AccessRightType => typeof(CertSrvRights);

        /// <summary>
        /// Gets the <see cref="Type"/> of the object associated with the access rules of this <see cref="ObjectSecurity"/>
        /// object. The <see cref="Type"/> object must be an object that can be cast as a <see cref="SecurityIdentifier"/> object
        /// </summary>
        public override Type AccessRuleType => typeof(CertSrvAccessRule);

        /// <summary>
        /// This member is not implemented.
        /// </summary>
        public override Type AuditRuleType => throw new NotSupportedException(Error.E_AUDITNOTSUPPOERTED);
        /// <summary>
        /// Writes this object to a securable object's Access Control List.
        /// </summary>
        /// <param name="restart">
        ///		Indicates whether to restart certificate services to immediately apply changes. Updated settings has
        ///		no effect until CA service is restarted.
        /// </param>
        /// <exception cref="ServerUnavailableException">
        ///		The target CA server could not be contacted via remote registry and RPC protocol.
        /// </exception>
        public void SetObjectSecurity(Boolean restart) {
            if (CryptoRegistry.Ping(ComputerName)) {
                CryptoRegistry.SetRReg(GetSecurityDescriptorBinaryForm(), "Security", _name, ComputerName);
                if (restart) { CertificateAuthority.Restart(ComputerName); }
                return;
            }
            if (CertificateAuthority.Ping(ComputerName)) {
                CryptoRegistry.SetRegFallback(_config, String.Empty, "Security", GetSecurityDescriptorBinaryForm());
                if (restart) { CertificateAuthority.Restart(ComputerName); }
                return;
            }
            ServerUnavailableException e = new ServerUnavailableException(DisplayName);
            e.Data.Add(nameof(e.Source), (OfflineSource)3);
            throw e;
        }
    }
}
