using System.Collections.Generic;
using SysadminsLV.PKI;
using SysadminsLV.PKI.Management.CertificateServices;

namespace PKI.Management.CertificateServices {
    // Represents a collection of Online Responder Array members.
    public class OcspResponderMemberInfoCollection : BasicCollection<OcspResponderMemberInfo> {
        /// <inheritdoc />
        public OcspResponderMemberInfoCollection() { }
        /// <inheritdoc />
        public OcspResponderMemberInfoCollection(IEnumerable<OcspResponderMemberInfo> collection) : base(collection) { }
    }
}
