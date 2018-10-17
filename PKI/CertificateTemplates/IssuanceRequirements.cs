using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using Interop.CERTENROLLLib;
using PKI.Utils;

namespace PKI.CertificateTemplates {
    /// <summary>
    /// Represents registration authority requirements. These are number of authorized signatures and authorized certificate application and/or issuance
    /// policy requirements.
    /// </summary>
    public class IssuanceRequirements {
        readonly IDictionary<String, Object> _entry;
        Int32 enrollmentFlags;

        internal IssuanceRequirements(IX509CertificateTemplate template) {
            InitializeCom(template);
        }
        internal IssuanceRequirements(IDictionary<String, Object> Entry) {
            _entry = Entry;
            InitializeDs();
        }
        /// <summary>
        /// Gets the number of registration agent (aka enrollment agent) signatures that are required on a request
        /// that references this template.
        /// </summary>
        public Int32 SignatureCount { get; private set; }
        /// <summary>
        /// Gets a set of application policy OID for the enrollment aget certificates.
        /// </summary>
        public Oid ApplicationPolicy { get; private set; }
        /// <summary>
        /// Gets a set of certificate policy OIDs for the enrollment aget certificates.
        /// </summary>
        public OidCollection CertificatePolicies { get; private set; }
        /// <summary>
        /// Gets the certificate reenrollment requirements. If the property is set to <strong>True</strong>,
        /// existing valid certificate is sufficient for reenrollment, otherwise, the same enrollment
        /// criteria is required for certificate renewal as was used for initial enrollment.
        /// </summary>
        public Boolean ExistingCertForRenewal => (enrollmentFlags & (Int32)CertificateTemplateEnrollmentFlags.ReenrollExistingCert) > 0;

        void InitializeDs() {
            enrollmentFlags = (Int32)_entry[DsUtils.PropPkiEnrollFlags];
            SignatureCount = (Int32)_entry[DsUtils.PropPkiRaSignature];
            if (SignatureCount > 0) {
                String ap = (String)_entry[DsUtils.PropPkiRaAppPolicy];
                if (ap == null) { return; }
                if (ap.Contains("`")) {
                    String[] splitstring = { "`" };
                    String[] strings = ap.Split(splitstring, StringSplitOptions.RemoveEmptyEntries);
                    for (Int32 index = 0; index < strings.Length; index += 3) {
                        switch (strings[index]) {
                            case DsUtils.PropPkiRaAppPolicy: ApplicationPolicy = new Oid(strings[index + 2]); break;
                        }
                    }
                } else { ApplicationPolicy = new Oid(ap); }
                get_rapolicies();
            }
        }
        void get_rapolicies() {
            OidCollection oids = new OidCollection();
            try {
                Object[] RaObject = (Object[])_entry[DsUtils.PropPkiRaCertPolicy];
                if (RaObject != null) {
                    foreach (Object obj in RaObject) {
                        oids.Add(new Oid(obj.ToString()));
                    }
                }
            } catch {
                String RaString = (String)_entry[DsUtils.PropPkiRaCertPolicy];
                oids.Add(new Oid(RaString));
            }
            CertificatePolicies = oids;
        }
        void InitializeCom(IX509CertificateTemplate template) {
            if (CryptographyUtils.TestOleCompat()) {
                try {
                    SignatureCount = (Int32)template.Property[EnrollmentTemplateProperty.TemplatePropRASignatureCount];
                    enrollmentFlags = (Int32)template.Property[EnrollmentTemplateProperty.TemplatePropEnrollmentFlags];
                } catch {
                    SignatureCount = 0;
                    enrollmentFlags = 0;
                }
            } else {
                try {
                    SignatureCount = Convert.ToInt32((UInt32)template.Property[EnrollmentTemplateProperty.TemplatePropRASignatureCount]);
                    enrollmentFlags = Convert.ToInt32((UInt32)template.Property[EnrollmentTemplateProperty.TemplatePropEnrollmentFlags]);
                } catch {
                    SignatureCount = 0;
                    enrollmentFlags = 0;
                }
            }
            if (SignatureCount > 0) {
                try {
                    IObjectIds oids = (IObjectIds)template.Property[EnrollmentTemplateProperty.TemplatePropRAEKUs];
                    ApplicationPolicy = new Oid(oids[0].Value);
                } catch { }
                try {
                    OidCollection raoids = new OidCollection();
                    IObjectIds oids = (IObjectIds)template.Property[EnrollmentTemplateProperty.TemplatePropRACertificatePolicies];
                    foreach (IObjectId rapoid in oids) { raoids.Add(new Oid(rapoid.Value)); }
                    CertificatePolicies = raoids;
                } catch { }
            }
        }

        /// <summary>
        /// Returns a textual representation of the certificate template issuance settings.
        /// </summary>
        /// <returns>A textual representation of the certificate template issuance settings.</returns>
        public override String ToString() {
            StringBuilder SB = new StringBuilder();
            SB.Append("[Issuance Requirements]" + Environment.NewLine);
            SB.Append("  Authorized signature count: " + SignatureCount + Environment.NewLine);
            if (SignatureCount > 0) {
                if (ApplicationPolicy == null) {
                    SB.Append("  Application policy required: none" + Environment.NewLine);
                } else {
                    SB.Append("  Application policy required: " + ApplicationPolicy.FriendlyName + "(" + ApplicationPolicy.Value + ")" + Environment.NewLine);
                }
                if (CertificatePolicies == null) {
                    SB.Append("  Issuance policies required: None" + Environment.NewLine);
                } else {
                    SB.Append("  Issuance policies required: ");
                    foreach (Oid oid in CertificatePolicies) {
                        SB.Append(oid.FriendlyName + "(" + oid.Value + "); ");
                    }
                    SB.Append(Environment.NewLine);
                }
            }
            SB.Append(ExistingCertForRenewal
                ? "  Reenrollment requires: existing valid certificate."
                : "  Reenrollment requires: same criteria as for enrollment.");
            return SB.ToString();
        }
    }
}
