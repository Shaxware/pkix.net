using System.Collections.Generic;

namespace SysadminsLV.PKI.Management.CertificateServices {
    /// <summary>
    /// Represents a collection of Online Responder revocation configurations.
    /// </summary>
    public class OcspResponderRevocationConfigurationCollection : BasicCollection<OcspResponderRevocationConfiguration> {
        /// <inheritdoc />
        public OcspResponderRevocationConfigurationCollection() { }
        /// <inheritdoc />
        public OcspResponderRevocationConfigurationCollection(IEnumerable<OcspResponderRevocationConfiguration> collection) : base(collection) {
            
        }
    }
}
