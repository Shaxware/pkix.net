using System;
using System.Linq;
using CERTENROLLLib;
using PKI.Utils;

namespace SysadminsLV.PKI.Cryptography {
    /// <summary>
    /// Represents a collection of <see cref="CspProviderInfo"/> objects.
    /// </summary>
    public class CspProviderInfoCollection : BasicCollection<CspProviderInfo> {
        public static CspProviderInfoCollection GetProviderInfo() {
            if (!CryptographyUtils.TestCNGCompat()) {
                throw new PlatformNotSupportedException();
            }

            var csps = new CCspInformations();
            csps.AddAvailableCsps();
            var retValue = new CspProviderInfoCollection();
            retValue.AddRange((from ICspInformation csp in csps select new CspProviderInfo(csp)).ToArray());
            CryptographyUtils.ReleaseCom(csps);
            return retValue;
        }
        public static CspProviderInfoCollection GetProviderInfo(String name) {
            if (!CryptographyUtils.TestCNGCompat()) {
                throw new PlatformNotSupportedException();
            }

            var csps = new CCspInformations();
            csps.AddAvailableCsps();
            var retValue = new CspProviderInfoCollection {
                new CspProviderInfo(csps.ItemByName[name])
            };
            CryptographyUtils.ReleaseCom(csps);
            return retValue;
        }
    }
}
