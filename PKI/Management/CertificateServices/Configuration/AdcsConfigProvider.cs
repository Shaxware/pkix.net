using System;
using PKI.CertificateServices;
using SysadminsLV.PKI.Management.CertificateServices.Configuration;

namespace PKI.Management.CertificateServices.Configuration {
    class AdcsConfigProvider {
        readonly CertificateAuthority _ca;

        public AdcsConfigProvider(CertificateAuthority certificateAuthority) {
            _ca = certificateAuthority ?? throw new ArgumentNullException(nameof(certificateAuthority));
        }

        public AdcsConfigurationEntry GetConfigEntry() {
            return null;
        }
        public Boolean SetConfigEntry(AdcsConfigurationEntry configEntry) {
            return false;
        }
        public Boolean DeleteConfigEntry(AdcsConfigurationEntry configEntry) {
            return false;
        }
    }
}
