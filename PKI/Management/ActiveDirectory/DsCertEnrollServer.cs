using System;
using System.DirectoryServices;
using System.Security.Cryptography.X509Certificates;

namespace SysadminsLV.PKI.Management.ActiveDirectory {
    /// <summary>
    /// Represents an Enterprise Certification Authority entry in Active Directory.
    /// </summary>
    public class DsCertEnrollServer {

        internal DsCertEnrollServer(DirectoryEntry entry) {
            Name = entry.Properties["cn"].Value?.ToString();
            DisplayName = entry.Properties["displayName"].Value?.ToString();
            ComputerName = entry.Properties["dNSHostName"].Value?.ToString();
            CertificateTemplates = entry.Properties["certificateTemplates"].Value as String[];
            Byte[] certProp = entry.Properties["cACertificate"].Value as Byte[];
            if (certProp?.Length > 1) {
                Certificate = new X509Certificate2(certProp);
            }
        }
        /// <summary>
        /// Gets the common name of Certification Authority.
        /// </summary>
        public String Name { get; }
        /// <summary>
        /// Gets the display name of Certification Authority.
        /// </summary>
        public String DisplayName { get; }
        /// <summary>
        /// Gets the computer name where Certification Authority is installed.
        /// </summary>
        public String ComputerName { get; }
        /// <summary>
        /// Gets the Certification Authority certificate.
        /// </summary>
        public X509Certificate2 Certificate { get; }
        /// <summary>
        /// Gets an array of certificate templates supported by the Certification Authority. Each certificate template is referenced by
        /// its common name.
        /// </summary>
        public String[] CertificateTemplates { get; }
    }
}