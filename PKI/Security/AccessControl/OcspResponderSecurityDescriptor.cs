using System;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using CERTADMINLib;
using PKI.Exceptions;
using PKI.Utils;
using SysadminsLV.PKI.Management.CertificateServices;

namespace SysadminsLV.PKI.Security.AccessControl {
    /// <summary>
    /// Represents the access control for a Microsoft OCSP Online Responder.
    /// </summary>
    /// <remarks>This class has no public constructors.</remarks>
    public sealed class OcspResponderSecurityDescriptor : CommonObjectSecurity {

        internal OcspResponderSecurityDescriptor(OcspResponder onlineResponder) : base(false) {
            ComputerName = onlineResponder.ComputerName;
        }
        /// <summary>
        /// Gets the host fully qualified domain name (FQDN) of the server where online responder is installed.
        /// </summary>
        public String ComputerName { get; }

        /// <summary>
        /// Initializes a new instance of the <see cref="OcspResponderAccessRule"/> class that represents a new access
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
        ///		A new <see cref="OcspResponderAccessRule"/> object that represents a new access control rule
        ///		for the specified user, with the specified access rights, access control, and flags.
        /// </returns>
        public override AccessRule AccessRuleFactory(IdentityReference identityReference, Int32 accessMask, Boolean isInherited,
            InheritanceFlags inheritanceFlags, PropagationFlags propagationFlags, AccessControlType type) {
            return new OcspResponderAccessRule(identityReference, (OcspResponderRights)accessMask, type);
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
        public Boolean AddAccessRule(OcspResponderAccessRule rule) {
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
        /// <remarks>This member is not implemented.</remarks>
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
        public override Type AccessRightType => typeof(OcspResponderRights);

        /// <summary>
        /// Gets the <see cref="Type"/> of the object associated with the access rules of this <see cref="ObjectSecurity"/>
        /// object. The <see cref="Type"/> object must be an object that can be cast as a <see cref="SecurityIdentifier"/> object
        /// </summary>
        public override Type AccessRuleType => typeof(OcspResponderAccessRule);

        /// <summary>
        /// This member is not implemented.
        /// </summary>
        public override Type AuditRuleType => throw new NotSupportedException(Error.E_AUDITNOTSUPPOERTED);
        ///  <summary>
        ///  Writes this object to a securable object's Access Control List.
        ///  </summary>
        ///  <exception cref="ServerUnavailableException">
        /// 		The target Online Responder server could not be contacted via remote registry and RPC protocol.
        ///  </exception>
        public void SetObjectSecurity() {
            var ocspAdmin = new OCSPAdminClass();
            try {
                ocspAdmin.SetSecurity(ComputerName, GetSecurityDescriptorSddlForm(AccessControlSections.All));
            } catch(COMException cex) {
                if (cex.ErrorCode == Error.RpcUnavailableException) {
                    var e = new ServerUnavailableException(ComputerName);
                    e.Data.Add(nameof(e.Source), OfflineSource.DCOM);
                    throw e;
                }
            } finally {
                CryptographyUtils.ReleaseCom(ocspAdmin);
            }
        }
    }
}
