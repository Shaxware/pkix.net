using System;
using System.Collections.Generic;

namespace SysadminsLV.PKI.Management.CertificateServices.Configuration {
    public class AiaUriCollection : BasicCollection<AiaConfigUri> {
        public AiaUriCollection(Boolean isNotifying = false) : base(isNotifying) { }
        public AiaUriCollection(IEnumerable<AiaConfigUri> collection, Boolean isNotifying = false)
            : base(collection, isNotifying) { }
    }
}
