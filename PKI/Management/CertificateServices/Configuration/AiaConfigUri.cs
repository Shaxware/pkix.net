using System;
using System.ComponentModel;
using System.IO;
using System.Text.RegularExpressions;

namespace SysadminsLV.PKI.Management.CertificateServices.Configuration {
    /// <summary>
    /// Represents an AuthorityInformationAccess URL object. An object contains URL information and URL
    /// publication settings. An URL indicates how clients can obtain presented certificate's issuer certificate,
    /// or how to locate authoritative OCSP responder. These URLs are generally used for certificate chain building
    /// purposes to determine whether the presented certificate came from trusted CA.
    /// </summary>
    public class AiaConfigUri : INotifyPropertyChanged {
        readonly Regex _regex = new Regex(@"(\d+):(.+)", RegexOptions.Compiled);
        String url;
        Boolean serverPublish, includeToExtension, ocsp;

        /// <summary>
        /// Initializes a new instance of the <strong>AiaConfigUri</strong> class using URL string.
        /// </summary>
        /// <param name="uri">An URL that points to a publication location including file name.
        /// See <see cref="URI"/> property for variable replacement tokens.
        /// </param>
        /// <exception cref="ArgumentNullException">The <strong>uri</strong> parameter is null or empty.</exception>
        /// <remarks>
        /// <p>Only absolute (local), UNC paths and LDAP URLs are supported for CRT file publishing.</p>
        /// <p>Only LDAP and HTTP URLs are supported for CRT file retrieval.</p>
        /// </remarks>
        public AiaConfigUri(String uri) {
            if (String.IsNullOrWhiteSpace(uri)) {
                throw new ArgumentNullException(nameof(uri));
            }
            Match match = _regex.Match(uri);
            if (match.Success) {
                Int32 flag         = Convert.ToInt32(match.Groups[1].Value);
                ServerPublish      = (flag & 1) > 0;
                IncludeToExtension = (flag & 2) > 0;
                OCSP               = (flag & 32) > 0;
                URI                = match.Groups[2].Value;
            } else {
                URI = uri;
            }
        }

        /// <summary>
        /// Gets or sets a publication URL. Can be local path, UNC, LDAP or HTTP path. Cannot be null or empty string.
        /// See <strong>Remarks</strong> for detailed URL structure.
        /// </summary>
        /// <remarks>
        /// The following replacement tokens are defined for AIA URL variables:
        /// <list type="table">
        ///     <listheader>
        ///         <term>Registry Variable</term>
        ///         <term>Config Variable</term>
        ///         <description>Description</description>
        ///     </listheader>
        ///     <item>
        ///         <term>%1</term>
        ///         <term>&lt;ServerDNSName&gt;</term>
        ///         <description>DNS name of the certification authority server</description>
        ///     </item>
        ///     <item>
        ///         <term>%2</term>
        ///         <term>&lt;ServerShortName&gt;</term>
        ///         <description>NetBIOS name of the certification authority server</description>
        ///     </item>
        ///     <item>
        ///         <term>%3</term>
        ///         <term>&lt;CaName&gt;</term>
        ///         <description>Name of the certification authority</description>
        ///     </item>
        ///     <item>
        ///         <term>%4</term>
        ///         <term>&lt;CRLNameSuffix&gt;</term>
        ///         <description>Renewal index of CA certificate. Blank for initial CA certificate and zero-based index of CA certificate in parentheses.</description>
        ///     </item>
        ///     <item>
        ///         <term>%6</term>
        ///         <term>&lt;ConfigurationContainer&gt;</term>
        ///         <description>Location of the Configuration container in Active Directory</description>
        ///     </item>
        ///     <item>
        ///         <term>%7</term>
        ///         <term>&lt;CATruncatedName&gt;</term>
        ///         <description>"sanitized" name of the certification authority, truncated to 32 characters with a hash on the end</description>
        ///     </item>     
        ///     <item>
        ///         <term>%11</term>
        ///         <term>&lt;CAObjectClass&gt;</term>
        ///         <description>Active Directory object class identifier for a certification authority, used when publishing to an LDAP URL</description>
        ///     </item>
        /// </list>
        /// </remarks>
        public String URI {
            get => url;
            set {
                if (String.IsNullOrWhiteSpace(value)) {
                    return;
                }
                url = value;
                OnPropertyChanged(nameof(URI));
            }
        }
        /// <summary>
        /// Gets an URL representation that is shown in Certification Authority MMC snap-in Extensions tab. See
        /// <see cref="URI"/> for detailed variable token replacement rules.
        /// </summary>
        public String ConfigURI {
            get {
                if (String.IsNullOrWhiteSpace(URI)) { return String.Empty; }
                return URI
                    .Replace("%11", "<CAObjectClass>")
                    .Replace("%1", "<ServerDNSName>")
                    .Replace("%2", "<ServerShortName>")
                    .Replace("%3", "<CaName>")
                    .Replace("%4", "<CertificateName>")
                    .Replace("%6", "<ConfigurationContainer>")
                    .Replace("%7", "<CATruncatedName>");
            }
        }
        /// <summary>
        /// Gets or sets the value if specified URL is configured to publish the CRT file to the specified location.
        /// </summary>
        /// <remarks>Only absolute (local), UNC and LDAP paths are supported.</remarks>
        public Boolean ServerPublish {
            get => serverPublish;
            set {
                serverPublish = value;
                OnPropertyChanged(nameof(ServerPublish));
            }
        }
        /// <summary>
        /// Gets or sets the value if the URL is configured to include specified URL to all issued
        /// certificate's Authority Information Access extension.
        /// </summary>
        /// <remarks>Only HTTP and LDAP paths are supported.</remarks>
        public Boolean IncludeToExtension {
            get => includeToExtension;
            set {
                includeToExtension = value;
                OnPropertyChanged(nameof(IncludeToExtension));
            }
        }
        /// <summary>
        /// Gets or sets if the URL is configured to include specified URL to all issued certificate's
        /// Authority Information Access extension as a OCSP Locator.
        /// </summary>
        /// <remarks>Only HTTP paths are supported.</remarks>
        public Boolean OCSP {
            get => ocsp;
            set {
                ocsp = value;
                OnPropertyChanged(nameof(OCSP));
            }
        }

        public String GetConfigUri() {
            if (String.IsNullOrWhiteSpace(URI)) {
                throw new InvalidDataException("The URI is null or empty.");
            }
            Int32 flag = 0;
            if (ServerPublish) {
                flag |= 1;
            }
            if (IncludeToExtension) {
                flag |= 2;
            }
            if (OCSP) {
                flag |= 32;
            }

            return $"{flag}:{URI}";
        }
        /// <summary>
        /// Returns a string representation of the current AIA URI object.
        /// </summary>
        /// <returns>A string representation of the current AIA URI object.</returns>
        public override String ToString() {
            return ConfigURI;
        }

        public event PropertyChangedEventHandler PropertyChanged;
        void OnPropertyChanged(String propertyName) {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }
    }
}
