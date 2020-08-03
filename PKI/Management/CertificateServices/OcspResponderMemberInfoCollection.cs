using System.Collections.Generic;
using SysadminsLV.PKI;
using SysadminsLV.PKI.Management.CertificateServices;

namespace PKI.Management.CertificateServices {
    /// <summary>
    /// Represents a collection of Online Responder Array members.
    /// </summary>
    public class OcspResponderMemberInfoCollection : BasicCollection<OcspResponderMemberInfo> {
        /// <inheritdoc />
        public OcspResponderMemberInfoCollection() { }
        /// <inheritdoc />
        public OcspResponderMemberInfoCollection(IEnumerable<OcspResponderMemberInfo> collection) : base(collection) { }
    }
}
