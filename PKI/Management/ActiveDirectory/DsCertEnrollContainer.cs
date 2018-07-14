using System;
using PKI.CertificateServices;

namespace SysadminsLV.PKI.Management.ActiveDirectory {
    /// <summary>
    /// Represents an Active Directory container with registered enrollment services (Enterprise CAs).
    /// </summary>
    public class DsCertEnrollContainer : DsPkiContainer {

        internal DsCertEnrollContainer() {
            ContainerType = DsContainerType.EnrollmentServices;
            BaseEntryPath = "CN=Enrollment Services";
        }

        /// <summary>
        /// Gets an array of registered in Active Directory enrollment services (Enterprise CAs).
        /// </summary>
        public CertificateAuthority[] CertificationAuthorities => CertificateAuthority.EnumEnterpriseCAs("Name", "*");

        /// <inheritdoc />
        public override void SaveChanges(Boolean forceDelete) { }
    }
}
