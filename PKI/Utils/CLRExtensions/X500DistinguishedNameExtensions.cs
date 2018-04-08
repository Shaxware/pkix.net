using System;
using System.Security.Cryptography.X509Certificates;

namespace SysadminsLV.PKI.Utils.CLRExtensions {
    /// <summary>
    /// Contains extension methods for <see cref="X500DistinguishedName"/> class.
    /// </summary>
    public static class X500DistinguishedNameExtensions {
        /// <summary>
        /// Converts an <see cref="X500DistinguishedName"/> instance in to a collection of individual
        /// RDN attributes.
        /// </summary>
        /// <param name="name">Existing instance of <strong>X500DistinguishedName</strong>.</param>
        /// <returns>A collection of RDN attributes.</returns>
        public static X500RdnAttributeCollection GetRdnAttributes(this X500DistinguishedName name) {
            if (name == null) { throw new ArgumentNullException(nameof(name)); }
            if (name.RawData == null || name.RawData.Length == 0) { return null; }
            var retValue = new X500RdnAttributeCollection();
            retValue.Decode(name.RawData);
            return retValue;
        }
    }
}
