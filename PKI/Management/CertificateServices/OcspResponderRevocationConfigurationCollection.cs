using System.Collections.Generic;

namespace SysadminsLV.PKI.Management.CertificateServices {
    public class OcspResponderRevocationConfigurationCollection : BasicCollection<OcspResponderRevocationConfiguration> {
        /// <inheritdoc />
        public OcspResponderRevocationConfigurationCollection() { }
        /// <inheritdoc />
        public OcspResponderRevocationConfigurationCollection(IEnumerable<OcspResponderRevocationConfiguration> collection) : base(collection) {
            
        }
    }
}
