using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SysadminsLV.Asn1Parser.Universal;

namespace SysadminsLV.PKI.Cryptography.X509Certificates {
    /// <summary>
    /// Defines Microsoft proprietary X.509 extension that represents certificate template name extension used by
    /// Enterprise CA to store certificate template information. This extension is used by Version 1 certificate
    /// templates.
    /// </summary>
    public sealed class X509CertificateTemplateNameExtension : X509Extension {
        readonly Oid _oid = new Oid(X509ExtensionOidMap.X509CertTemplateName);

        internal X509CertificateTemplateNameExtension(Byte[] rawData, Boolean critical)
            : base(X509ExtensionOidMap.X509CertificateTemplate, rawData, critical) {
            if (rawData == null) { throw new ArgumentNullException(nameof(rawData)); }
            m_decode(rawData);
        }

        /// <summary>
        /// Initializes a new instance of the <strong>X509CertificateTemplateNameExtension</strong> class.
        /// </summary>
        public X509CertificateTemplateNameExtension() { Oid = _oid; }
        /// <summary>
        /// Initializes a new instance of the <strong>X509CertificateTemplateNameExtension</strong> class using an
        /// <see cref="AsnEncodedData"/> object and a value that identifies whether the extension is critical.
        /// </summary>
        /// <param name="templateNameInfo">The encoded data to use to create the extension.</param>
        /// <param name="critical"><strong>True</strong> if the extension is critical; otherwise, <strong>False</strong>.</param>
        public X509CertificateTemplateNameExtension(AsnEncodedData templateNameInfo, Boolean critical) :
            this(templateNameInfo.RawData, critical) { }
        /// <summary>
        /// Initializes a new instance of the <strong>X509CertificateTemplateNameExtension</strong> class by using
        /// certificate template common name.
        /// </summary>
        /// <param name="templateName">Certificate template's common name.</param>
        public X509CertificateTemplateNameExtension(String templateName) {
            m_initialize(templateName);
        }

        /// <summary>
        /// Gets certificate template name.
        /// </summary>
        public String TemplateName { get; private set; }
        /// <summary>
        /// Gets certificate template major version.
        /// </summary>
        public Int32 MajorVersion { get; private set; }
        /// <summary>
        /// Gets certificate template minor version.
        /// </summary>
        public Int32 MinorVersion { get; private set; }

        void m_initialize(String templateName) {
            Oid = _oid;
            TemplateName = templateName;
            RawData = new Asn1BMPString(templateName).RawData;
        }
        void m_decode(Byte[] rawData) {
            var asn = new Asn1BMPString(rawData);
            TemplateName = asn.Value;
            RawData = asn.RawData;
        }
    }
}
