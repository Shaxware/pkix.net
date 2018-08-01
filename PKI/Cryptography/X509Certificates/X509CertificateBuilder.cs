using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using PKI.Structs;
using PKI.Utils;
using SysadminsLV.Asn1Parser;

namespace SysadminsLV.PKI.Cryptography.X509Certificates {
    public class X509CertificateBuilder {
        readonly HashSet<String> _excludedExtensions = new HashSet<String>(
            new[] {
                X509CertExtensions.X509SubjectKeyIdentifier,
                X509CertExtensions.X509AuthorityKeyIdentifier
            }
        );
        readonly List<X509Extension> _extensions = new List<X509Extension>();
        Byte[] serialNumber;

        public Int32 Version => 3;
        public String SerialNumber { get; set; }
        public X500DistinguishedName Subject { get; set; }
        public DateTime NotBefore { get; set; } = DateTime.Now;
        public DateTime NotAfter { get; set; } = DateTime.Now.AddYears(1);
        public X509ExtensionCollection Extensions { get; } = new X509ExtensionCollection();
        public Oid2 HashingAlgorithm { get; set; } = new Oid2(AlgorithmOids.SHA256, false);
        public Boolean AlternateSignatureFormat { get; set; }
        public X509PrivateKeyBuilder PrivateKeyInfo { get; } = new X509PrivateKeyBuilder();

        void generateSerialNumber() {
            if (String.IsNullOrWhiteSpace(SerialNumber)) {
                using (var hasher = MD5.Create()) {
                    serialNumber = hasher.ComputeHash(Guid.NewGuid().ToByteArray());
                }
            } else {
                serialNumber = AsnFormatter.StringToBinary(SerialNumber, EncodingType.Hex);
            }
        }
        void validateDates(X509Certificate2 signer) {
            if (signer == null) {
                if (NotAfter <= NotBefore) {
                    NotAfter = NotBefore.AddYears(1);
                }
            } else {
                if (NotBefore < signer.NotBefore) {
                    NotBefore = signer.NotBefore;
                }

                if (NotAfter > signer.NotAfter) {
                    NotAfter = signer.NotAfter;
                }
            }
        }
        // generates SKI and optionally AKI
        void generateKeyIdentifiers(X509Certificate2 signer) {
            using (var hasher = SHA1.Create()) {
                var hash = hasher.ComputeHash(PrivateKeyInfo.GetPublicKey().EncodedKeyValue.RawData);
                var ext = new X509SubjectKeyIdentifierExtension(hash, false);
                _extensions.Add(ext);
            }
            if (signer != null) {
                var ext = new X509AuthorityKeyIdentifierExtension(signer, AuthorityKeyIdentifierFlags.KeyIdentifier, false);
                _extensions.Add(ext);
            }
        }
        void processExtensions() {
            foreach (X509Extension extension in Extensions) {
                if (_excludedExtensions.Contains(extension.Oid.Value)) {
                    continue;
                }
                _extensions.Add(CryptographyUtils.ConvertExtension(extension));
            }
        }

        void preGenerate(X509Certificate2 signer) {
            PrivateKeyInfo.Create();
            generateSerialNumber();
            validateDates(signer);
            generateKeyIdentifiers(signer);
            processExtensions();
        }

        public X509Certificate2 Build(X509Certificate2 signer = null) {
            preGenerate(signer);
            return null;
        }
    }
}
