using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using PKI.Exceptions;
using SysadminsLV.PKI.Management.ActiveDirectory;

namespace PKI.Management.ActiveDirectory {
    /// <summary>
    /// Represents trusted Root CA certificate container in Active Directory. This container is used by domain members
    /// to build certificate chains with trusted root CAs defined by organization.
    /// </summary>
    public class DsRootCaContainer : DsPkiCertContainer {
        internal DsRootCaContainer() {
            ContainerType = DsContainerType.RootCA;
            BaseEntryPath = "CN=Certification Authorities";
            ReadChildren(new[] { DsCertificateType.CACertificate });
        }

        /// <summary>
        /// Adds CA certificate to RootCA entry in Active Directory. The type is determined by <strong>type</strong>
        /// parameter.
        /// </summary>
        /// <param name="cert">Root CA certificate to add.</param>
        /// <inheritdoc cref="DsPkiContainer.SafeAddCertToCollection" section="exception|returns|remarks/*"/>
        public Boolean AddCertificate(X509Certificate2 cert) {
            if (cert == null) {
                throw new ArgumentNullException(nameof(cert));
            }
            if (cert.RawData == null) {
                throw new UninitializedObjectException();
            }
            String containerName = GetContainerName(cert);
            var entry = new DsCertificateEntry(containerName, cert, DsCertificateType.CACertificate);
            return AddCertificate(entry);
        }
        /// <summary>
        /// Removes CA certificate from a current AIA object.
        /// </summary>
        /// <param name="entry">CA certificate to remove</param>
        /// <inheritdoc cref="DsPkiContainer.SafeRemoveCertFromCollection" section="exception|returns|remarks/*"/>
        public Boolean RemoveCertificate(DsCertificateEntry entry) {
            return RemoveCertificateEntry(entry);
        }

        /// <inheritdoc />
        public override void SaveChanges(Boolean forceDelete) {
            if (!IsModified) { return; }
            // this list contains only entries we need to update.
            IEnumerable<String> namesToProcess = GetUpdateList();
            foreach (String name in namesToProcess) {
                DirectoryEntry dsEntry = DirectoryEntry.Exists($"LDAP://CN={name},{DsPath}")
                    ? new DirectoryEntry($"LDAP://CN={name},{DsPath}")
                    // if no such entry exists, create it.
                    : AddChild($"CN={name}", "certificationAuthority");
                // if we elected to delete empty entries --> check them
                if (forceDelete && CheckDelete(dsEntry, name)) {
                    continue;
                }
                // write CA certificates
                dsEntry.Properties["cACertificate"].Clear();
                DsCertificateEntry[] caCerts = DsList[name].Where(x => x.CertificateType == DsCertificateType.CACertificate).ToArray();
                // cACertificate is mandatory attribute
                if (!caCerts.Any()) {
                    dsEntry.Properties["cACertificate"].Add(new Byte[] { 0 });
                } else {
                    foreach (DsCertificateEntry entry in caCerts) {
                        dsEntry.Properties["cACertificate"].Add(entry.Certificate.RawData);
                    }
                }
                dsEntry.CommitChanges();
            }
            CleanupSave();
        }
    }
}
