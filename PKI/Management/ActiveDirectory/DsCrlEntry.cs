using System;
using System.Security.Cryptography.X509Certificates;

namespace SysadminsLV.PKI.Management.ActiveDirectory {
    /// <summary>
    /// Represents a certificate object in Active Directory.
    /// </summary>
    public class DsCrlEntry {
        internal DsCrlEntry(String name, X509CRL2 crl) {
            Name = name;
            CRL = crl;
        }

        /// <summary>
        /// Gets the Active Directory entry name that holds current certificate object.
        /// </summary>
        public String Name { get; }
        /// <summary>
        /// Gets the certificate associated with the current Active Directory entry.
        /// </summary>
        public X509CRL2 CRL { get; }

        /// <inheritdoc />
        public override Boolean Equals(Object other) {
            return !(other is null)
                   && (ReferenceEquals(this, other)
                       || other.GetType() == GetType()
                       && Equals((DsCrlEntry)other));
        }
        protected Boolean Equals(DsCrlEntry other) {
            return String.Equals(Name, other.Name) && CRL.Equals(other.CRL);
        }
        /// <inheritdoc />
        public override Int32 GetHashCode() {
            unchecked {
                return (Name.GetHashCode() * 397) ^ CRL.GetHashCode();
            }
        }
    }
}