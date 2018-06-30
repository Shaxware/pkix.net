using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using PKI.Structs;
using PKI.Utils;
using SysadminsLV.PKI.Management.ActiveDirectory;
using SysadminsLV.PKI.Utils.CLRExtensions;

namespace PKI.Management.ActiveDirectory {
    public class DsAiaEntry : DsPkiContainer {
        readonly List<X509Certificate2> _cACerts    = new List<X509Certificate2>();
        readonly List<X509Certificate2> _crossCerts = new List<X509Certificate2>();
        readonly DsAiaContainer _parent;
        String dsName;

        internal DsAiaEntry(String name, DsAiaContainer parent) {
            _parent = parent;
            dsName = name;
            ContainerType = DsContainerType.AIA;
            BaseEntryPath = $"CN={dsName},CN=AIA";
            // read CA certs
            readCertsFromAttribute(_cACerts, "cACertificate");
            // read crossCerts
            readCertsFromAttribute(_crossCerts, "crossCertificatePair");
        }
        public X509Certificate2Collection CACertificates => new X509Certificate2Collection(_cACerts.ToArray());
        public X509Certificate2Collection CrossCertificates => new X509Certificate2Collection(_crossCerts.ToArray());

        /// <summary>
        /// Adds CA certificate to AIA entry.
        /// </summary>
        /// <param name="cert">CA certificate to add.</param>
        /// <inheritdoc cref="DsPkiContainer.SafeAddCertToCollection" section="exception|returns|remarks/*"/>
        public Boolean AddCACertificate(X509Certificate2 cert) {
            Boolean status = SafeAddCertToCollection(_cACerts, cert);
            if (status) {
                updateContainerName(cert);
            }
            return status;
        }
        /// <summary>
        /// Adds a cross-certificate to AIA entry.
        /// </summary>
        /// <param name="cert">Cross-certificate to add.</param>
        /// <inheritdoc cref="DsPkiContainer.SafeAddCertToCollection" section="exception|returns|remarks/*"/>
        public Boolean AddCrossCertificate(X509Certificate2 cert) {
            Boolean status = SafeAddCertToCollection(_crossCerts, cert);
            if (status) {
                updateContainerName(cert);
            }
            return status;
        }
        /// <summary>
        /// Removes CA certificate from a current AIA object.
        /// </summary>
        /// <param name="cert">CA certificate to remove</param>
        /// <inheritdoc cref="DsPkiContainer.SafeRemoveCertFromCollection" section="exception|returns|remarks/*"/>
        public Boolean RemoveCACertificate(X509Certificate2 cert) {
            return SafeRemoveCertFromCollection(_cACerts, cert);
        }
        /// <summary>
        /// Removes cross-certificate from a current AIA object.
        /// </summary>
        /// <param name="cert">Cross-certificate to remove.</param>
        /// <inheritdoc cref="DsPkiContainer.SafeRemoveCertFromCollection" section="exception|returns|remarks/*"/>
        public Boolean RemoveCrossCertificate(X509Certificate2 cert) {
            return SafeRemoveCertFromCollection(_crossCerts, cert);
        }
        /// <summary>
        /// Removes all CA certificate from a current AIA object.
        /// </summary>
        public void ClearCACertificates() {
            _cACerts.Clear();
        }
        /// <summary>
        /// Removes all certificates from cross-certificate collection.
        /// </summary>
        /// <inheritdoc cref="AddCACertificate" section="remarks/*"/>
        public void ClearCrossCertificates() {
            _crossCerts.Clear();
        }

        // TODO: subject to refactor
        void updateContainerName(X509Certificate2 fromCert) {
            if (!String.IsNullOrWhiteSpace(BaseEntryPath)) { return; }

            X500DistinguishedName fullSubject;
            // get the name to be used as the name in DS. If certificate subject is end entity,
            // use issuer name (first attribute), if subject is CA, use subject name (first attrbiute).
            if (fromCert.Version == 3) {
                X509Extension ext = fromCert.Extensions[X509CertExtensions.X509BasicConstraints];
                if (ext == null) {
                    fullSubject = fromCert.IssuerName;
                } else {
                    X509BasicConstraintsExtension bc = (X509BasicConstraintsExtension)CryptographyUtils.ConvertExtension(ext);
                    fullSubject = bc.CertificateAuthority
                        ? fromCert.SubjectName
                        : fromCert.IssuerName;
                }
            } else {
                // V1 certificates are threated as end entity, so pick up issuer name.
                fullSubject = fromCert.IssuerName;
            }

            X500RdnAttributeCollection tokens = fullSubject.GetRdnAttributes();
            String name = DsUtils.GetSanitizedName(tokens[0].Value);
            BaseEntryPath = $"CN={name},CN=AIA";
        }
        void readCertsFromAttribute(ICollection<X509Certificate2> certs, String attribute) {
            Byte[][] rawData = GetEntryProperty<Byte[]>(BaseEntry, attribute);
            foreach (Byte[] bytes in rawData.Where(x => x.Length > 1)) {
                certs.Add(new X509Certificate2(bytes));
            }
        }

        /// <inheritdoc />
        public override void SaveChanges(Boolean forceDelete) {
            if (_cACerts.Count == 0 && _crossCerts.Count == 0 && forceDelete) {
                var parent = BaseEntry.Parent;
                parent.Children.Remove(BaseEntry);
                parent.CommitChanges();
                return;
            }
            // write CA certs
            BaseEntry.Properties["cACertificate"].Clear();
            foreach (X509Certificate2 cert in _cACerts) {
                BaseEntry.Properties["cACertificate"].Add(cert.RawData);
            }
            // write cross-certs
            BaseEntry.Properties["crossCertificatePair"].Clear();
            foreach (X509Certificate2 cert in _crossCerts) {
                BaseEntry.Properties["crossCertificatePair"].Add(cert.RawData);
            }
            BaseEntry.CommitChanges();
        }
    }
}
