using System;
using System.Collections.Generic;

namespace SysadminsLV.PKI.Management.CertificateServices.Configuration {
    public class CdpUriCollection : BasicCollection<CrlDistributionPointConfigUri> {
        public CdpUriCollection(Boolean isNotifying = false) : base(isNotifying) { }
        public CdpUriCollection(IEnumerable<CrlDistributionPointConfigUri> collection, Boolean isNotifying = false)
            : base(collection, isNotifying) { }
    }
}
