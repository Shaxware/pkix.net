﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using Interop.CERTENROLLLib;
using PKI.Utils;
using SysadminsLV.PKI.Utils.CLRExtensions;
using X509KeyUsageFlags = System.Security.Cryptography.X509Certificates.X509KeyUsageFlags;

namespace PKI.CertificateTemplates {
    /// <summary>
    /// This class represents certificate template cryptography settings.
    /// </summary>
    public class CryptographyTemplateSettings {
        Int32 pkf, schemaVersion;
        readonly IDictionary<String, Object> _entry;

        internal CryptographyTemplateSettings(IX509CertificateTemplate template) {
            InitializeCom(template);
        }
        internal CryptographyTemplateSettings(IDictionary<String, Object> Entry) {
            _entry = Entry;
            InitializeDs();
        }

        /// <summary>
        /// Gets or sets a list of cryptographic service providers (CSPs) that are used to create the private key and public key.
        /// If the property is null, a client may use any CSP installed on the client system.
        /// </summary>
        public String[] CSPList { get; private set; }
        /// <summary>
        /// Gets or sets key algorithm required by the certificate template.
        /// </summary>
        public Oid KeyAlgorithm { get; private set; }
        /// <summary>
        /// Gets or sets hash algorithm is used to sign request required by the certificate template.
        /// </summary>
        public Oid HashAlgorithm { get; private set; }
        /// <summary>
        /// Gets or sets the minimum size, in bits, of the public key that the client should create to obtain a certificate based
        /// on this template.
        /// </summary>
        public Int32 MinimalKeyLength { get; private set; }
        /// <summary>
        /// Gets or sets private key options.
        /// </summary>
        public PrivateKeyFlags PrivateKeyOptions {
            get {
                Int32 pkflags = 0;
                if ((pkf & 0x001) > 0) { pkflags += 0x001; }
                if ((pkf & 0x010) > 0) { pkflags += 0x010; }
                if ((pkf & 0x020) > 0) { pkflags += 0x020; }
                if ((pkf & 0x040) > 0) { pkflags += 0x040; }
                if ((pkf & 0x080) > 0) { pkflags += 0x080; }
                if ((pkf & 0x100) > 0) { pkflags += 0x100; }
                return (PrivateKeyFlags)pkflags;
            }
        }
        /// <summary>
        /// Indicates operations for which the private key can be used.
        /// </summary>
        public X509KeySpecFlags KeySpec { get; private set; }
        /// <summary>
        /// Gets key usages allowed by the template.
        /// </summary>
        public X509KeyUsageFlags KeyUsage { get; private set; }
        /// <summary>
        /// Gets key usages for CNG keys.
        /// </summary>
        public X509CNGKeyUsages CNGKeyUsage { get; private set; }
        /// <summary>
        /// Gets the permissions when a private key is created
        /// </summary>
        public String PrivateKeySecuritySDDL { get; private set; }

        void InitializeDs() {
            schemaVersion = (Int32)_entry[DsUtils.PropPkiSchemaVersion];
            KeyAlgorithm = new Oid("RSA");
            HashAlgorithm = new Oid("SHA1");
            MinimalKeyLength = (Int32)_entry[DsUtils.PropPkiKeySize];
            pkf = (Int32)_entry[DsUtils.PropPkiPKeyFlags];
            KeySpec = (X509KeySpecFlags)(Int32)_entry[DsUtils.PropPkiKeySpec];
            get_csp();
            get_keyusages();
            String ap = (String)_entry[DsUtils.PropPkiRaAppPolicy];
            if (ap != null && ap.Contains("`")) {
                String[] splitstring = { "`" };
                String[] strings = ap.Split(splitstring, StringSplitOptions.RemoveEmptyEntries);
                for (Int32 index = 0; index < strings.Length; index += 3) {
                    switch (strings[index]) {
                        case DsUtils.PropPkiKeySddl: PrivateKeySecuritySDDL = strings[index + 2]; break;
                        case DsUtils.PropPkiAsymAlgo: KeyAlgorithm = new Oid(strings[index + 2]); break;
                        case DsUtils.PropPkiHashAlgo: HashAlgorithm = new Oid(strings[index + 2]); break;
                        case DsUtils.PropPkiKeyUsageCng: CNGKeyUsage = (X509CNGKeyUsages)Convert.ToInt32(strings[index + 2]); break;
                    }
                }
            }

        }
        void get_csp() {
            List<String> csplist = new List<String>();

            try {
                Object[] CSPObject = (Object[])_entry[DsUtils.PropPkiKeyCsp];
                if (CSPObject != null) {
                    csplist.AddRange(CSPObject.Select(csp => Regex.Replace(csp.ToString(), "^\\d+,", String.Empty)));
                }
            } catch {
                String cspString = (String)_entry[DsUtils.PropPkiKeyCsp];
                csplist.Add(Regex.Replace(cspString, "^\\d+,", String.Empty));
            }
            CSPList = csplist.ToArray();
        }
        void get_keyusages() {
            Byte[] ku = (Byte[])_entry[DsUtils.PropPkiKeyUsage];
            if (ku == null) {
                KeyUsage = 0;
            } else {
                if (ku.Length == 1) {
                    KeyUsage = (X509KeyUsageFlags)ku[0];
                } else {
                    Array.Reverse(ku);
                    KeyUsage = (X509KeyUsageFlags)Convert.ToInt32(String.Join("", ku.Select(item => $"{item:x2}").ToArray()), 16);
                }
            }
            if (schemaVersion > 2) {
                X509CNGKeyUsages cngUsages = 0;
                if (
                    ((Int32)KeyUsage & (Int32)X509KeyUsageFlags.DataEncipherment) != 0 &&
                    ((Int32)KeyUsage & (Int32)X509KeyUsageFlags.DecipherOnly) != 0 &&
                    ((Int32)KeyUsage & (Int32)X509KeyUsageFlags.EncipherOnly) != 0 &&
                    ((Int32)KeyUsage & (Int32)X509KeyUsageFlags.KeyEncipherment) != 0
                ) { cngUsages |= X509CNGKeyUsages.DecryptOnly; }
                if (
                    ((Int32)KeyUsage & (Int32)X509KeyUsageFlags.CrlSign) != 0 &&
                    ((Int32)KeyUsage & (Int32)X509KeyUsageFlags.DigitalSignature) != 0 &&
                    ((Int32)KeyUsage & (Int32)X509KeyUsageFlags.KeyCertSign) != 0
                ) { cngUsages |= X509CNGKeyUsages.SignatureOnly; }
                if (((Int32)KeyUsage & (Int32)X509KeyUsageFlags.KeyAgreement) != 0) {
                    cngUsages |= X509CNGKeyUsages.KeyAgreement;
                }
                if (
                    (((Int32)KeyUsage & (Int32)X509KeyUsageFlags.DataEncipherment) != 0 ||
                    ((Int32)KeyUsage & (Int32)X509KeyUsageFlags.DecipherOnly) != 0 ||
                    ((Int32)KeyUsage & (Int32)X509KeyUsageFlags.EncipherOnly) != 0 ||
                    ((Int32)KeyUsage & (Int32)X509KeyUsageFlags.KeyEncipherment) != 0) &&
                    (((Int32)KeyUsage & (Int32)X509KeyUsageFlags.CrlSign) != 0 ||
                    ((Int32)KeyUsage & (Int32)X509KeyUsageFlags.DigitalSignature) != 0 ||
                    ((Int32)KeyUsage & (Int32)X509KeyUsageFlags.KeyCertSign) != 0) &&
                    ((Int32)KeyUsage & (Int32)X509KeyUsageFlags.KeyAgreement) != 0
                ) { cngUsages = X509CNGKeyUsages.AllUsages; }
                CNGKeyUsage = cngUsages;
            }
        }
        void InitializeCom(IX509CertificateTemplate template) {
            if (CryptographyUtils.TestOleCompat()) {
                try {
                    pkf = (Int32)template.Property[EnrollmentTemplateProperty.TemplatePropPrivateKeyFlags];
                } catch { }
                MinimalKeyLength = (Int32)template.Property[EnrollmentTemplateProperty.TemplatePropMinimumKeySize];
                KeySpec = (X509KeySpecFlags)(Int32)template.Property[EnrollmentTemplateProperty.TemplatePropKeySpec];
                try {
                    CNGKeyUsage = (X509CNGKeyUsages)(Int32)template.Property[EnrollmentTemplateProperty.TemplatePropKeyUsage];
                } catch { }
            } else {
                try {
                    pkf = Convert.ToInt32((UInt32)template.Property[EnrollmentTemplateProperty.TemplatePropPrivateKeyFlags]);
                } catch { }
                MinimalKeyLength = Convert.ToInt32((UInt32)template.Property[EnrollmentTemplateProperty.TemplatePropMinimumKeySize]);
                KeySpec = (X509KeySpecFlags)Convert.ToInt32((UInt32)template.Property[EnrollmentTemplateProperty.TemplatePropKeySpec]);
                try {
                    CNGKeyUsage = (X509CNGKeyUsages)Convert.ToInt32((UInt32)template.Property[EnrollmentTemplateProperty.TemplatePropKeyUsage]);
                } catch { }
            }
            try {
                CSPList = (String[])template.Property[EnrollmentTemplateProperty.TemplatePropCryptoProviders];
            } catch { }
            try {
                KeyAlgorithm = new Oid((String)template.Property[EnrollmentTemplateProperty.TemplatePropAsymmetricAlgorithm]);
            } catch {
                KeyAlgorithm = new Oid("RSA");
            }
            try {
                HashAlgorithm = new Oid((String)template.Property[EnrollmentTemplateProperty.TemplatePropHashAlgorithm]);
            } catch {
                HashAlgorithm = new Oid("SHA1");
            }
            try {
                PrivateKeySecuritySDDL = (String)template.Property[EnrollmentTemplateProperty.TemplatePropKeySecurityDescriptor];
            } catch { }
        }

        /// <summary>
        /// Gets a textual representation of the certificate template cryptography settings.
        /// </summary>
        /// <returns>A textual representation of the certificate template cryptography settings</returns>
        public override String ToString() {
            String nl = Environment.NewLine;
            StringBuilder SB = new StringBuilder();
            SB.Append($"[Cryptography Settings]{nl}");
            SB.Append("  CSP list: ");
            if (CSPList == null) {
                SB.Append($"Any installed CSP{nl}");
            } else {
                SB.Append(nl);
                foreach (String csp in CSPList) {
                    SB.Append($"     {csp}{nl}");
                }
                SB.Append(nl);
            }
            SB.Append($"  Key Algorithm: {KeyAlgorithm.Format(true)}{nl}");
            SB.Append($"  Hash Algorithm: {HashAlgorithm.Format(true)}{nl}");
            SB.Append($"  Key Length: {MinimalKeyLength}{nl}");
            SB.Append($"  Private key options: {PrivateKeyOptions}{nl}");
            SB.Append($"  KeySpec: {KeySpec}{nl}");
            SB.Append($"  CNG key usage: {CNGKeyUsage}");
            if (!String.IsNullOrEmpty(PrivateKeySecuritySDDL)) {
                SB.Append($"{nl}  Private key security descriptor: {PrivateKeySecuritySDDL}");
            }
            return SB.ToString();
        }
    }
}
