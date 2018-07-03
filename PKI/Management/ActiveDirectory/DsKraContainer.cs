using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using PKI.Exceptions;
using PKI.Management.ActiveDirectory;
using PKI.Structs;
using PKI.Utils;
using SysadminsLV.PKI.Utils.CLRExtensions;

namespace SysadminsLV.PKI.Management.ActiveDirectory {
    /// <summary>
    /// Represents key recovery agent (KRA) store in Active Directory. This container is used by Microsoft CA server
    /// to locate key recovery agent certificates when implementing key archival functionality.
    /// </summary>
    public sealed class DsKraContainer : DsPkiContainer {
        readonly ISet<DsCertificateEntry> _list = new HashSet<DsCertificateEntry>();
        readonly ISet<String> _toBeAdded = new HashSet<String>();
        readonly ISet<String> _toBeRemoved = new HashSet<String>();
        readonly IDictionary<String, List<DsCertificateEntry>> _dsList = new Dictionary<String, List<DsCertificateEntry>>(StringComparer.OrdinalIgnoreCase);

        internal DsKraContainer() {
            ContainerType = DsContainerType.KRA;
            BaseEntryPath = "CN=KRA";
            readChildren();
        }

        /// <summary>
        /// Gets an array of key recovery agent (KRA) certificates
        /// </summary>
        public DsCertificateEntry[] Certificates => _list.OrderBy(x => x.Name).ToArray();

        void readChildren() {
            foreach (DirectoryEntry child in BaseEntry.Children) {
                String childName = child.Properties["cn"][0].ToString();
                List<DsCertificateEntry> items = readCertsFromDsAttribute(child);
                // add to global list
                foreach (DsCertificateEntry item in items) {
                    _list.Add(item);
                }
                // add to child-specific list.
                if (_dsList.ContainsKey(childName)) {
                    _dsList[childName].AddRange(items);
                } else {
                    _dsList.Add(childName, items);
                }
            }
        }
        List<DsCertificateEntry> readCertsFromDsAttribute(DirectoryEntry entry) {
            Byte[][] rawData = GetEntryProperty<Byte[]>(entry, "userCertificate");
            // x.Length > 1 is necessary, because empty value contains a 1 byte element inside
            return rawData.Where(x => x.Length > 1)
                .Select(bytes => new DsCertificateEntry(entry.Properties["cn"][0].ToString(), new X509Certificate2(bytes), DsCertificateType.UserCertificate))
                .ToList();
        }
        IEnumerable<String> getUpdateList() {
            ISet<String> namesToProcess = new HashSet<String>();
            // toBeAdded and toBeRemoved can overlap on different items only.
            foreach (String name in _toBeAdded) {
                namesToProcess.Add(name);
            }
            foreach (String name in _toBeRemoved) {
                namesToProcess.Add(name);
            }
            return namesToProcess;
        }
        Boolean checkDelete(DirectoryEntry entry) {
            // if there was at least one removal and DS entry is empty from any certificate,
            // delete DS entry. Otherwise do nothing
            if (_toBeRemoved.Contains(entry.Name) && _dsList[entry.Name].Count == 0) {
                BaseEntry.Children.Remove(entry);
                BaseEntry.CommitChanges();
                return true;
            }
            return false;
        }
        static String getContainerName(X509Certificate2 fromCert) {
            X500DistinguishedName fullSubject = fromCert.IssuerName;
            X500RdnAttributeCollection tokens = fullSubject.GetRdnAttributes();
            // if subject is empty, calculate SHA1 hash over subject name's raw data (48, 0)
            if (tokens.Count == 0) {
                var sb = new StringBuilder();
                using (SHA1 hasher = SHA1.Create()) {
                    foreach (Byte b in hasher.ComputeHash(fullSubject.RawData)) {
                        sb.AppendFormat("{0:x2}", b);
                    }
                }
                return sb.ToString();
            }
            return DsUtils.GetSanitizedName(tokens[0].Value);
        }
        static Boolean validateConstraints(X509Certificate2 cert) {
            // check if KRA certificate is trusted, not revoked and is valid for KRA purpose.
            var chain = new X509Chain(true);
            Boolean status = chain.Build(cert);
            if (status && cert.Version < 3) {
                return true;
            }
            if (status && cert.Version == 3) {
                var ext = (X509EnhancedKeyUsageExtension)cert.Extensions[X509CertExtensions.X509EnhancedKeyUsage];
                if (ext != null) {
                    foreach (Oid oid in ext.EnhancedKeyUsages) {
                        if (oid.Value == "1.3.6.1.4.1.311.21.6") {
                            return true;
                        }
                    }
                }
            }
            return false;
        }

        /// <summary>
        /// Adds key recovery agent (KRA) certificate to Active Directory.
        /// </summary>
        /// <param name="cert">Key recovery agent certificate to add.</param>
        /// <returns>
        /// <strong>True</strong> if 
        /// </returns>
        public Boolean AddCertificate(X509Certificate2 cert) {
            if (cert == null) {
                throw new ArgumentNullException(nameof(cert));
            }
            if (cert.RawData == null) {
                throw new UninitializedObjectException();
            }
            if (!validateConstraints(cert)) {
                return false;
            }
            String containerName = getContainerName(cert);
            var entry = new DsCertificateEntry(containerName, cert, DsCertificateType.UserCertificate);
            if (_list.Contains(entry)) { return false; }
            // mutually exclusive. entry cannot be added and removed at the same time.
            _toBeAdded.Add(entry.Name);
            _toBeRemoved.Remove(entry.Name);
            _list.Add(entry);
            if (_dsList.ContainsKey(containerName)) {
                _dsList[containerName].Add(entry);
            } else {
                _dsList.Add(containerName, new List<DsCertificateEntry>());
                _dsList[containerName].Add(entry);
            }
            return IsModified = true;
        }
        public Boolean RemoveCertificate(DsCertificateEntry entry) {
            if (entry == null) {
                throw new ArgumentNullException(nameof(entry));
            }
            if (!_list.Contains(entry)) {
                return false;
            }
            // mutually exclusive. entry cannot be added and removed at the same time.
            _toBeRemoved.Add(entry.Name);
            _toBeAdded.Remove(entry.Name);
            _list.Remove(entry);
            _dsList[entry.Name].Remove(entry);
            return IsModified = true;
        }

        public override void SaveChanges(Boolean forceDelete) {
            if (!IsModified) { return; }
            // this list contains only entries we need to update.
            IEnumerable<String> namesToProcess = getUpdateList();
            foreach (String name in namesToProcess) {
                // if no such entry exists, create it.
                DirectoryEntry dsEntry = DirectoryEntry.Exists($"LDAP://CN={name},{DsPath}")
                    ? new DirectoryEntry($"LDAP://CN={name},{DsPath}")
                    : AddChild($"CN={name}", "msPKI-PrivateKeyRecoveryAgent");
                // if we elected to delete empty entries --> check them
                if (forceDelete && checkDelete(dsEntry)) {
                    continue;
                }
                // write certificates certificates
                dsEntry.Properties["userCertificate"].Clear();
                foreach (DsCertificateEntry entry in _dsList[name]) {
                    dsEntry.Properties["userCertificate"].Add(entry.Certificate.RawData);
                }
            }
            // clear processing lists
            _toBeAdded.Clear();
            _toBeRemoved.Clear();
            IsModified = false;
        }
    }
}
