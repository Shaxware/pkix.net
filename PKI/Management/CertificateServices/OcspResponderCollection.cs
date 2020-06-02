using System.Collections.Generic;

namespace SysadminsLV.PKI.Management.CertificateServices {
    public class OcspResponderCollection : BasicCollection<OcspResponder> {
        public OcspResponderCollection() { }
        public OcspResponderCollection(IEnumerable<OcspResponder> collection) : base(collection) { }
    }
}