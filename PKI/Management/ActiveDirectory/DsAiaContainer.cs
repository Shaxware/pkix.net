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
    /// Represents intermediate CA certificate container in Active Directory. This container is used by domain members
    /// to build certificate chains with CAs defined by organization. In addition, this container stores
    /// cross-certificates when organization establishes a qualified trust with other organizations.
    /// </summary>
    public class DsAiaContainer : DsPkiContainer {
        readonly ISet<DsCertificateEntry> _list = new HashSet<DsCertificateEntry>();
        readonly ISet<String> _toBeAdded = new HashSet<String>();
        readonly ISet<String> _toBeRemoved = new HashSet<String>();
        readonly IDictionary<String, List<DsCertificateEntry>> _dsList = new Dictionary<String, List<DsCertificateEntry>>(StringComparer.OrdinalIgnoreCase);

        internal DsAiaContainer() {
            ContainerType = DsContainerType.AIA;
            BaseEntryPath = "CN=AIA";
            readChildren();
        }

        /// <summary>
        /// Gets an array of certificates stored in AIA container.
        /// </summary>
        public DsCertificateEntry[] Certificates => _list.OrderBy(x => x.Name).ToArray();

        void readChildren() {
            foreach (DirectoryEntry child in BaseEntry.Children) {
                String childName = child.Properties["cn"][0].ToString();
                foreach (DsCertificateType type in new[] { DsCertificateType.CACertificate, DsCertificateType.CrossCertificate }) {
                    List<DsCertificateEntry> items = readCertsFromDsAttribute(child, type);
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
        }
        List<DsCertificateEntry> readCertsFromDsAttribute(DirectoryEntry entry, DsCertificateType type) {
            String attribute;
            switch (type) {
                case DsCertificateType.CACertificate:
                    attribute = "cACertificate";
                    break;
                case DsCertificateType.CrossCertificate:
                    attribute = "crossCertificatePair";
                    break;
                case DsCertificateType.UserCertificate:
                    attribute = "userCertificate";
                    break;
                default:
                    throw new ArgumentOutOfRangeException(nameof(type), type, null);
            }

            Byte[][] rawData = GetEntryProperty<Byte[]>(entry, attribute);
            // x.Length > 1 is necessary, because empty value contains a 1 byte element inside
            return rawData.Where(x => x.Length > 1)
                .Select(bytes => new DsCertificateEntry(entry.Properties["cn"][0].ToString(), new X509Certificate2(bytes), type))
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
        Boolean checkDelete(DirectoryEntry entry, String entryName) {

            // if there was at least one removal and DS entry is empty from any certificate,
            // delete DS entry. Otherwise do nothing
            if (_toBeRemoved.Contains(entryName) && _dsList[entryName].Count == 0) {
                BaseEntry.Children.Remove(entry);
                BaseEntry.CommitChanges();
                return true;
            }
            return false;
        }

        // TODO: need to check if this logic is correct.
        static String getContainerName(X509Certificate2 fromCert) {
            X500DistinguishedName fullSubject;
            // get the name to be used as the name in DS. If certificate subject is end entity,
            // use issuer name (first attribute), if subject is CA, use subject name (first attrbiute).
            if (fromCert.Version == 3) {
                X509Extension ext = fromCert.Extensions[X509CertExtensions.X509BasicConstraints];
                if (ext == null) {
                    fullSubject = fromCert.IssuerName;
                } else {
                    var bc = (X509BasicConstraintsExtension)CryptographyUtils.ConvertExtension(ext);
                    fullSubject = bc.CertificateAuthority
                        ? fromCert.SubjectName
                        : fromCert.IssuerName;
                }
            } else {
                // V1 certificates are threated as end entity, so pick up issuer name.
                fullSubject = fromCert.IssuerName;
            }
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

        /// <summary>
        /// Adds CA certificate to AIA entry as CA certificate or cross-certificate. The type is determined by <strong>type</strong>
        /// parameter.
        /// <para>
        /// <strong>Note:</strong> 'userCertificate' type is not supported by this method.
        /// </para>
        /// </summary>
        /// <param name="cert">CA certificate to add.</param>
        /// <param name="type">Certificate type. Can be either 'CACertificate' or 'CrossCertificate'.</param>
        /// <inheritdoc cref="DsPkiContainer.SafeAddCertToCollection" section="exception|returns|remarks/*"/>
        public Boolean AddCertificate(X509Certificate2 cert, DsCertificateType type) {
            if (cert == null) {
                throw new ArgumentNullException(nameof(cert));
            }
            if (cert.RawData == null) {
                throw new UninitializedObjectException();
            }
            if (type == DsCertificateType.UserCertificate) {
                throw new ArgumentException("Specified type is not supported.");
            }
            String containerName = getContainerName(cert);
            var entry = new DsCertificateEntry(containerName, cert, type);
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
        /// <summary>
        /// Removes CA certificate from a current AIA object.
        /// </summary>
        /// <param name="entry">CA certificate to remove</param>
        /// <inheritdoc cref="DsPkiContainer.SafeRemoveCertFromCollection" section="exception|returns|remarks/*"/>
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

        /// <inheritdoc />
        public override void SaveChanges(Boolean forceDelete) {
            if (!IsModified) { return; }
            // this list contains only entries we need to update.
            IEnumerable<String> namesToProcess = getUpdateList();
            foreach (String name in namesToProcess) {
                DirectoryEntry dsEntry = DirectoryEntry.Exists($"LDAP://CN={name},{DsPath}")
                    ? new DirectoryEntry($"LDAP://CN={name},{DsPath}")
                    // if no such entry exists, create it.
                    : AddChild($"CN={name}", "certificationAuthority");
                // if we elected to delete empty entries --> check them
                if (forceDelete && checkDelete(dsEntry, name)) {
                    continue;
                }
                // write CA certificates
                dsEntry.Properties["cACertificate"].Clear();
                DsCertificateEntry[] caCerts = _dsList[name].Where(x => x.CertificateType == DsCertificateType.CACertificate).ToArray();
                // cACertificate is mandatory attribute
                if (!caCerts.Any()) {
                    dsEntry.Properties["cACertificate"].Add(new Byte[] { 0 });
                } else {
                    foreach (DsCertificateEntry entry in caCerts) {
                        dsEntry.Properties["cACertificate"].Add(entry.Certificate.RawData);
                    }
                }
                // write cross-certificates
                dsEntry.Properties["crossCertificatePair"].Clear();
                foreach (DsCertificateEntry entry in _dsList[name].Where(x => x.CertificateType == DsCertificateType.CrossCertificate)) {
                    dsEntry.Properties["crossCertificatePair"].Add(entry.Certificate.RawData);
                }
                dsEntry.CommitChanges();
            }
            // clear processing lists
            _toBeAdded.Clear();
            _toBeRemoved.Clear();
            IsModified = false;
        }
    }
}
