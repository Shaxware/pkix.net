using System;
using System.Collections.Generic;
using System.Linq;

namespace SysadminsLV.PKI.Management.CertificateServices {
    /// <summary>
    /// Represents a collection of Online Responder revocation configurations.
    /// </summary>
    public class OcspResponderRevocationConfigurationCollection : BasicCollection<OcspResponderRevocationConfiguration> {
        /// <inheritdoc />
        public OcspResponderRevocationConfigurationCollection() { }
        /// <inheritdoc />
        public OcspResponderRevocationConfigurationCollection(IEnumerable<OcspResponderRevocationConfiguration> collection) : base(collection) { }

        public OcspResponderRevocationConfiguration this[String name] => InternalList.FirstOrDefault(x => x.Name.Equals(name, StringComparison.InvariantCultureIgnoreCase));
    }
}
