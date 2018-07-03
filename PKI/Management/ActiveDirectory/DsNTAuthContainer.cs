using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;

namespace SysadminsLV.PKI.Management.ActiveDirectory {
    /// <summary>
    /// Represents NTAuth certificate store in Active Directory. This store contains CA certificates that are
    /// eligible to issue client authentication and logon certificates and perform client key archival on CA server.
    /// </summary>
    public sealed class DsNTAuthContainer : DsPkiContainer {
        readonly List<X509Certificate2> _certs = new List<X509Certificate2>();
        /// <summary>
        /// Initializes a new instance of <strong>DsNTAuthContainer</strong> object.
        /// </summary>
        internal DsNTAuthContainer() {
            ContainerType = DsContainerType.NTAuth;
            BaseEntryPath = "CN=NTAuthCertificates";
            if (BaseEntry == null) { return; }
            Byte[][] rawData = GetEntryProperty<Byte[]>(BaseEntry, "cACertificate");
            foreach (Byte[] bytes in rawData.Where(x => x.Length > 1)) {
                _certs.Add(new X509Certificate2(bytes));
            }
        }

        /// <summary>
        /// Gets a collection of certificates included in NTAuth store. Certificates cannot be added or
        /// removed from the store by using this member. Use <see cref="Add"/> and <see cref="Remove"/>
        /// and <see cref="Clear"/> methods to update this store.
        /// </summary>
        public X509Certificate2Collection Certificates => new X509Certificate2Collection(_certs.ToArray());

        /// <summary>
        /// Adds CA certificate to NTAuth store in Active Directory.
        /// </summary>
        /// <param name="cert">CA certificate to add.</param> 
        /// <inheritdoc cref="DsPkiContainer.SafeAddCertToCollection" section="exception|returns|remarks/*"/>
        public Boolean Add(X509Certificate2 cert) {
            return SafeAddCertToCollection(_certs, cert);
        }
        /// <summary>
        /// Removes certificate from NTAuth store in Active Directory.
        /// </summary>
        /// <param name="cert">Certificate to remove.</param>
        /// <inheritdoc cref="DsPkiContainer.SafeRemoveCertFromCollection" section="exception|returns|remarks/*"/>
        public Boolean Remove(X509Certificate2 cert) {
            return SafeRemoveCertFromCollection(_certs, cert);
        }
        /// <summary>
        /// Removes all certificates from NTAuth store.
        /// </summary>
        public void Clear() {
            _certs.Clear();
        }


        /// <inheritdoc />
        public override void SaveChanges(Boolean forceDelete) {
            BaseEntry.Properties["cACertificate"].Clear();
            foreach (X509Certificate2 cert in _certs) {
                BaseEntry.Properties["cACertificate"].Add(cert.RawData);
            }
            BaseEntry.CommitChanges();
        }
    }
}
