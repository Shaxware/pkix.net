using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.Linq;
using PKI.CertificateServices;

namespace SysadminsLV.PKI.Management.ActiveDirectory {
    /// <summary>
    /// Represents an Active Directory container with registered enrollment services (Enterprise CAs).
    /// </summary>
    public class DsCertEnrollContainer : DsPkiContainer {
        readonly IList<DsCertEnrollServer> _dsList = new List<DsCertEnrollServer>();

        internal DsCertEnrollContainer() {
            ContainerType = DsContainerType.EnrollmentServices;
            BaseEntryPath = "CN=Enrollment Services";
            readChildren();
        }

        /// <summary>
        /// Gets an array of registered in Active Directory enrollment services (Enterprise CAs).
        /// </summary>
        [Obsolete("Use 'EnrollmentServers' member instead", true)]
        public CertificateAuthority[] CertificationAuthorities => CertificateAuthority.EnumEnterpriseCAs("Name", "*");
        /// <summary>
        /// Gets an array of registered in Active Directory enrollment service (Enterprise CAs) entries.
        /// </summary>
        public DsCertEnrollServer[] EnrollmentServers => _dsList.ToArray();

        void readChildren() {
            foreach (DirectoryEntry entry in BaseEntry.Children) {
                using (entry) {
                    _dsList.Add(new DsCertEnrollServer(entry));
                }
            }
        }

        /// <inheritdoc />
        public override void SaveChanges(Boolean forceDelete) { }
    }
}
