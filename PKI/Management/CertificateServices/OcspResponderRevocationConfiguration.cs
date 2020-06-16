using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using CERTADMINLib;
using PKI.Utils;
using SysadminsLV.PKI.Cryptography.Pkcs;

namespace SysadminsLV.PKI.Management.CertificateServices {
    /// <summary>
    /// Represents Online Responder revocation configuration object.
    /// </summary>
    public class OcspResponderRevocationConfiguration {
        #region config properties
        // items prefixed with 'MSFT_' are Microsoft properties. Custom properties are prefixed with ''
        const String MSFT_CONF_CACERTIFICATE              = "CACertificate";
        const String MSFT_CONF_HASHALGORITHMID            = "HashAlgorithmId";
        const String MSFT_CONF_SIGNINGFLAGS               = "SigningFlags";
        const String MSFT_CONF_REMINDERDURATION           = "ReminderDuration";
        const String MSFT_CONF_SIGNINGCERTIFICATE         = "SigningCertificate";
        const String MSFT_CONF_CSPNAME                    = "CSPName";
        const String MSFT_CONF_KEYSPEC                    = "KeySpec";
        const String MSFT_CONF_ERRORCODE                  = "ErrorCode";
        const String MSFT_CONF_PROVIDERCLSID              = "ProviderCLSID";
        const String MSFT_CONF_PROVIDERPROPERTIES         = "Provider";
        const String MSFT_CONF_LOCALREVOCATIONINFORMATION = "LocalRevocationInformation";
        const String MSFT_CONF_SIGNINGCERTIFICATETEMPLATE = "SigningCertificateTemplate";
        const String MSFT_CONF_CACONFIG                   = "CAConfig";
        const String MSFT_PROV_CRLURLTIMEOUT              = "CrlUrlTimeOut";
        const String MSFT_PROV_BASECRLURLS                = "BaseCrlUrls";
        const String MSFT_PROV_BASECRL                    = "BaseCrl";
        const String MSFT_PROV_DELTACRLURLS               = "DeltaCrlUrls";
        const String MSFT_PROV_DELTACRL                   = "DeltaCrl";
        const String MSFT_PROV_REFRESHTIMEOUT             = "RefreshTimeOut";
        const String MSFT_PROV_ERRORCODE                  = "RevocationErrorCode";
        const String MSFT_PROV_SERIALNUMBERSDIRS          = "IssuedSerialNumbersDirectories";
        #endregion
        readonly String _computerName;
        readonly X509CRLEntryCollection _crlEntries = new X509CRLEntryCollection();
        readonly ISet<String> _updateList = new HashSet<String>();

        Int32 crlUrlTimeout, refreshTimeout, reminderDuration;
        String certTemplate;
        String[] baseCrlUrls, deltaCrlUrls, serialDirs;
        Oid2 hashAlgorithm;
        OcspSigningFlag signingFlags;
        X509CRL2 localCrl;
        X509Certificate2 signingCertificate;

        internal OcspResponderRevocationConfiguration(String computerName, IOCSPCAConfiguration config) {
            _computerName = computerName;
            Name = config.Identifier;
            ConfigString = config.CAConfig;
            CACertificate = new X509Certificate2((Byte[])config.CACertificate);
            try {
                CryptoProviderName = config.CSPName;
            } catch { }

            readProperties(config);
            CryptographyUtils.ReleaseCom(config);
        }

        /// <summary>
        /// Gets the display name of revocation configuration.
        /// </summary>
        public String Name { get; }
        /// <summary>
        /// Gets the configuration string for online certification authority.
        /// </summary>
        public String ConfigString { get; }
        /// <summary>
        /// Gets the certification authority certificate.
        /// </summary>
        public X509Certificate2 CACertificate { get; }
        /// <summary>
        /// Gets or sets signing certificate used to sign OCSP responses for current CA.
        /// </summary>
        public X509Certificate2 SigningCertificate {
            get => signingCertificate;
            set {
                signingCertificate = value ?? throw new ArgumentNullException(nameof(value));
                _updateList.Add(MSFT_CONF_SIGNINGCERTIFICATE);
            }
        }
        /// <summary>
        /// Gets or sets the certificate template common name Online Responder will use to enroll for signing certificate.
        /// </summary>
        public String SigningCertificateTemplate {
            get => certTemplate;
            set {
                if (value != certTemplate) {
                    certTemplate = value;
                    _updateList.Add(MSFT_CONF_SIGNINGCERTIFICATETEMPLATE);
                }
            }
        }
        /// <summary>
        /// Gets or sets the hashing algorithm used to sign OCSP responses.
        /// </summary>
        public Oid2 HashAlgorithm {
            get => hashAlgorithm;
            set {
                if (value == null) {
                    throw new ArgumentNullException(nameof(value));
                }
                if (value.OidGroup != OidGroupEnum.HashAlgorithm) {
                    throw new ArgumentException("Specified algorithm identifier does not belong to hashing algorithm group.");
                }
                if (!value.Equals(hashAlgorithm)) {
                    hashAlgorithm = value;
                    _updateList.Add(MSFT_CONF_HASHALGORITHMID);
                }
            }
        }
        /// <summary>
        /// Gets the cryptographic provider name used to store OCSP response signing keys.
        /// </summary>
        public String CryptoProviderName { get; }
        /// <summary>
        /// Gets or sets the signing certificate handling options.
        /// </summary>
        public OcspSigningFlag SigningFlags {
            get => signingFlags;
            set {
                if (value != signingFlags) {
                    signingFlags = value;
                    _updateList.Add(MSFT_CONF_SIGNINGFLAGS);
                }
            }
        }
        /// <summary>
        /// Gets a percentage of the signing certificate validity period at which the responder will notify the administrator that certificate
        /// is about to expire. Default value is 90%.
        /// </summary>
        /// <remarks>Setter value must be in range 0-100.</remarks>
        public Int32 ReminderDuration {
            get => reminderDuration;
            set {
                if (reminderDuration < 0 || reminderDuration > 100) {
                    throw new ArgumentOutOfRangeException(nameof(value), "Value must be in range 0 - 100.");
                }
                if (value != reminderDuration) {
                    reminderDuration = value;
                    _updateList.Add(MSFT_CONF_REMINDERDURATION);
                }
            }
        }
        /// <summary>
        /// Gets the local revocation information.
        /// </summary>
        public X509CRLEntryCollection LocalRevocationInformation => new X509CRLEntryCollection(_crlEntries);
        /// <summary>
        /// Gets or sets an array of URLs that point to Base CRL locations. Every URL must be either HTTP or LDAP.
        /// </summary>
        public String[] BaseCrlUrls {
            get => baseCrlUrls;
            set {
                baseCrlUrls = value;
                _updateList.Add(MSFT_PROV_BASECRLURLS);
            }
        }
        /// <summary>
        /// Gets or sets an array of URLs that point to Delta CRL locations. Every URL must be either HTTP or LDAP.
        /// </summary>
        public String[] DeltaCrlUrls {
            get => deltaCrlUrls;
            set {
                deltaCrlUrls = value;
                _updateList.Add(MSFT_PROV_DELTACRLURLS);
            }
        }
        /// <summary>
        /// Gets the time-out in seconds that the revocation provider must wait before it times out while trying
        /// to retrieve the CRL for which it is configured.
        /// </summary>
        public Int32 CrlUrlTimeout {
            get => crlUrlTimeout;
            set {
                if (value != crlUrlTimeout) {
                    crlUrlTimeout = value;
                    _updateList.Add(MSFT_PROV_CRLURLTIMEOUT);
                }
            }
        }
        /// <summary>
        /// Gets local CRL cache lifetime in minutes. If the value is zero, then CRL cache is valid while CRLs are valid.
        /// </summary>
        public Int32 RefreshTimeout {
            get => refreshTimeout;
            set {
                if (value != refreshTimeout) {
                    refreshTimeout = value;
                    _updateList.Add(MSFT_PROV_REFRESHTIMEOUT);
                }
            }
        }
        /// <summary>
        /// Gets an array of UNC or local file paths that are being used by the CA to store the serial numbers of certificates.
        /// </summary>
        /// <remarks>This property has no effect for systems prior to Windows Server 2016.</remarks>
        public String[] IssuedSerialNumbersDirectories {
            get => serialDirs;
            set {
                serialDirs = value;
                _updateList.Add(MSFT_PROV_SERIALNUMBERSDIRS);
            }
        }
        /// <summary>
        /// Gets the revocation information status code.
        /// </summary>
        public Int32 RevocationStatusCode { get; private set; }
        /// <summary>
        /// Gets the current configuration status code.
        /// </summary>
        public Int32 ConfigurationStatusCode { get; private set; }

        void readProperties(IOCSPCAConfiguration config) {
            try { hashAlgorithm = new Oid2(config.HashAlgorithm, OidGroupEnum.HashAlgorithm, false); } catch { }
            try { signingFlags = (OcspSigningFlag)config.SigningFlags; } catch { }
            try {
                signingCertificate = config.SigningCertificate == null
                    ? null
                    : new X509Certificate2((Byte[])config.SigningCertificate);
            } catch { }
            try { reminderDuration = unchecked((Int32)config.ReminderDuration); } catch { }
            try { ConfigurationStatusCode = unchecked((Int32)config.ErrorCode); } catch { }
            try { SigningCertificateTemplate = config.SigningCertificateTemplate; } catch { }

            // read properties
            Object[,] props = (Object[,])config.ProviderProperties;
            for (Int32 i = 0; i < props.GetUpperBound(0); i++) {
                switch (props[i, 0]) {
                    case MSFT_PROV_ERRORCODE:
                        RevocationStatusCode = (Int32)props[i, 1];
                        break;
                    case MSFT_PROV_REFRESHTIMEOUT:
                        refreshTimeout = (Int32)props[i, 1] / 60000;
                        break;
                    case MSFT_PROV_CRLURLTIMEOUT:
                        crlUrlTimeout = (Int32)props[i, 1] / 1000;
                        break;
                    case MSFT_PROV_BASECRLURLS:
                        baseCrlUrls = (String[])props[i, 1];
                        break;
                    case MSFT_PROV_DELTACRLURLS:
                        deltaCrlUrls = (String[])props[i, 1];
                        break;
                }
            }
        }

        static Object[,] writeProvProperties(Object[,] source, String propName, Object value) {
            for (Int32 i = 0; i < source.GetUpperBound(0); i++) {
                if (propName.Equals(source[i, 0])) {
                    source[i, 1] = value;
                    return source;
                }
            }
            
            // if we reach this far, then requested property is not found in provider properties
            var list = new List<Object[]>();
            // copy current properties to jagged list
            for (Int32 i = 0; i < source.GetUpperBound(0); i++) {
                list.Add(new[] { source[i, 0], source[i, 1] });
            }
            // add new property
            list.Add(new[] { propName, value });

            // copy jagged list to normal two-dimensional array
            var retValue = new Object[list.Count, 2];
            for (Int32 i = 0; i < retValue.GetUpperBound(0); i++) {
                retValue[i, 0] = list[i][0];
                retValue[i, 1] = list[i][1];
            }

            return retValue;
        }

        /// <summary>
        /// Gets a collection of OCSP signing certificate candidates for current CA configuration.
        /// <para>This method searches certificates installed in 'LocalMachine\My' ('Local Machine\Personal'). Certificates stored in other places
        /// or other accounts (such as Network Service account) are not shown.</para>
        /// </summary>
        /// <returns>A collection of OCSP signing certificate candidates.</returns>
        /// <remarks>
        /// Each signing certificate has the following properties:
        /// <list type="bullet">
        ///     <item>Signed by the CA specified in this revocation configuration object.</item>
        ///     <item>Includes the Online Certificate Status Protocol signing (id-kp-OCSPSigning) enhanced key usage</item>
        ///     <item>Has not expired.</item>
        ///     <item>Responder server can access the certificate private key</item>
        /// </list>
        /// </remarks>
        public X509Certificate2Collection GetSigningCertificateCandidates() {
            var ocspConfig = new OCSPAdminClass();
            try {
                var cms = new DefaultSignedPkcs7((Byte[])ocspConfig.GetSigningCertificates(_computerName, CACertificate.RawData));
                return cms.Certificates;
            } catch {
                return new X509Certificate2Collection();
            } finally {
                CryptographyUtils.ReleaseCom(ocspConfig);
            }
        }
        /// <summary>
        /// Commits changes to Online Responder.
        /// </summary>
        public void Commit() {
            if (!_updateList.Any()) {
                return;
            }

            var ocspAdmin = new OCSPAdminClass();
            IOCSPCAConfiguration revConfig = null;
            try {
                ocspAdmin.GetConfiguration(_computerName, true);
                revConfig = (IOCSPCAConfiguration)ocspAdmin.OCSPCAConfigurationCollection.ItemByName[Name];

                foreach (String updateProperty in _updateList) {
                    switch (updateProperty) {
                        case MSFT_CONF_HASHALGORITHMID:
                            revConfig.HashAlgorithm = hashAlgorithm.FriendlyName;
                            break;
                        case MSFT_CONF_SIGNINGFLAGS:
                            revConfig.SigningFlags = (UInt32)signingFlags;
                            break;
                        case MSFT_CONF_SIGNINGCERTIFICATE:
                            revConfig.SigningCertificate = signingCertificate?.RawData;
                            break;
                        case MSFT_CONF_REMINDERDURATION:
                            revConfig.ReminderDuration = (UInt32)reminderDuration;
                            break;
                        case MSFT_CONF_SIGNINGCERTIFICATETEMPLATE:
                            revConfig.SigningCertificateTemplate = certTemplate;
                            break;
                        case MSFT_PROV_REFRESHTIMEOUT:
                            revConfig.ProviderProperties = writeProvProperties((Object[,])revConfig.ProviderProperties, updateProperty, refreshTimeout * 60000);
                            break;
                        case MSFT_PROV_CRLURLTIMEOUT:
                            revConfig.ProviderProperties = writeProvProperties((Object[,])revConfig.ProviderProperties, updateProperty, crlUrlTimeout * 1000);
                            break;
                        case MSFT_PROV_BASECRLURLS:
                            revConfig.ProviderProperties = writeProvProperties((Object[,])revConfig.ProviderProperties, updateProperty, baseCrlUrls);
                            break;
                        case MSFT_PROV_DELTACRLURLS:
                            revConfig.ProviderProperties = writeProvProperties((Object[,])revConfig.ProviderProperties, updateProperty, deltaCrlUrls);
                            break;
                        case MSFT_PROV_SERIALNUMBERSDIRS:
                            revConfig.ProviderProperties = writeProvProperties((Object[,])revConfig.ProviderProperties, updateProperty, serialDirs);
                            break;
                    }
                }

                ocspAdmin.SetConfiguration(_computerName, true);
                _updateList.Clear();
            } finally {
                CryptographyUtils.ReleaseCom(ocspAdmin);
                if (revConfig != null) {
                    CryptographyUtils.ReleaseCom(revConfig);
                }
            }
        }
    }
}
