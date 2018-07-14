using System;
using System.Security.Cryptography.X509Certificates;

namespace SysadminsLV.PKI.Management.ActiveDirectory {
    /// <summary>
    /// Represents a certificate object in Active Directory.
    /// </summary>
    public class DsCertificateEntry {
        internal DsCertificateEntry(String name, X509Certificate2 certificate, DsCertificateType type) {
            Name = name;
            Certificate = certificate;
            CertificateType = type;
        }

        /// <summary>
        /// Gets the Active Directory entry name that holds current certificate object.
        /// </summary>
        public String Name { get; }
        /// <summary>
        /// Gets the certificate associated with the current Active Directory entry.
        /// </summary>
        public X509Certificate2 Certificate { get; }
        /// <summary>
        /// Gets the type of certificate store in Active Directory.
        /// </summary>
        public DsCertificateType CertificateType { get; }

        /// <inheritdoc />
        public override Boolean Equals(Object other) {
            return !(other is null)
                   && (ReferenceEquals(this, other)
                       || other.GetType() == GetType()
                       && Equals((DsCertificateEntry)other));
        }
        protected Boolean Equals(DsCertificateEntry other) {
            return String.Equals(Name, other.Name, StringComparison.OrdinalIgnoreCase)
                   && Certificate.Equals(other.Certificate)
                   && CertificateType == other.CertificateType;
        }
        /// <inheritdoc />
        public override Int32 GetHashCode() {
            unchecked {
                Int32 hashCode = StringComparer.OrdinalIgnoreCase.GetHashCode(Name);
                hashCode = (hashCode * 397) ^ Certificate.GetHashCode();
                hashCode = (hashCode * 397) ^ (Int32)CertificateType;
                return hashCode;
            }
        }
    }
}
