using SysadminsLV.PKI;

namespace System.Security.Cryptography.X509Certificates {
    /// <summary>
    /// Represents a collection of <see cref="X509CertificateContextProperty"/> objects.
    /// </summary>
    public class X509CertificateContextPropertyCollection : BasicCollection<X509CertificateContextProperty> {
        /// <summary>
        /// Closes current collection state and makes it read-only. The collection cannot be modified further.
        /// </summary>
        public void Close() {
            IsReadOnly = true;
        }
    }
}