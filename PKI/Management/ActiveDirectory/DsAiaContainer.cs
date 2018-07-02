using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using PKI.Exceptions;
using PKI.Management.ActiveDirectory;
using PKI.Structs;
using PKI.Utils;
using SysadminsLV.PKI.Utils.CLRExtensions;

namespace SysadminsLV.PKI.Management.ActiveDirectory {
    public class DsAiaContainer : DsPkiContainer {
        readonly ISet<DsCertificateEntry> _list = new HashSet<DsCertificateEntry>();
        readonly ISet<String> _toBeAdded = new HashSet<String>();
        readonly ISet<String> _toBeRemoved = new HashSet<String>();
        readonly IDictionary<String, List<DsCertificateEntry>> _dsList = new Dictionary<String, List<DsCertificateEntry>>(StringComparer.OrdinalIgnoreCase);

        public DsAiaContainer() {
            ContainerType = DsContainerType.NTAuth;
            BaseEntryPath = "CN=AIA";
            readChildren();
        }

        public DsCertificateEntry[] Certificates => _list.OrderBy(x => x.Name).ToArray();

        void readChildren() {
            foreach (DirectoryEntry child in BaseEntry.Children) {
                foreach (DsCertificateType type in new[] { DsCertificateType.CACertificate, DsCertificateType.CrossCertificate }) {
                    List<DsCertificateEntry> items = readCertsFromDsAttribute(child, type);
                    // add to global list
                    foreach (DsCertificateEntry item in items) {
                        _list.Add(item);
                    }
                    // add to child-specific list.
                    if (_dsList.ContainsKey(child.Name)) {
                        _dsList[child.Name].AddRange(items);
                    } else {
                        _dsList.Add(child.Name, items);
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
                .Select(bytes => new DsCertificateEntry(entry.Name, new X509Certificate2(bytes), type))
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
                // if no such entry exists, create it.
                DirectoryEntry dsEntry = DirectoryEntry.Exists($"LDAP://CN={name},{BaseEntryPath}")
                    ? new DirectoryEntry($"LDAP://CN={name},{BaseEntryPath}")
                    : BaseEntry.Children.Add(name, "certificationAuthority");
                // if we elected to delete empty entries --> check them
                if (forceDelete && checkDelete(dsEntry)) {
                    continue;
                }
                // write CA certificates
                dsEntry.Properties["cACertificate"].Clear();
                foreach (DsCertificateEntry entry in _dsList[name].Where(x => x.CertificateType == DsCertificateType.CACertificate)) {
                    dsEntry.Properties["cACertificate"].Add(entry.Certificate.RawData);
                }
                // write cross-certificates
                dsEntry.Properties["crossCertificatePair"].Clear();
                foreach (DsCertificateEntry entry in _dsList[name].Where(x => x.CertificateType == DsCertificateType.CrossCertificate)) {
                    dsEntry.Properties["crossCertificatePair"].Add(entry.Certificate.RawData);
                }
            }
            // clear processing lists
            _toBeAdded.Clear();
            _toBeRemoved.Clear();
            IsModified = false;
        }
    }
}
