using System;
using PKI.CertificateServices;
using PKI.CertificateServices.Flags;

namespace SysadminsLV.PKI.Management.CertificateServices.Configuration {
    /// <summary>
    /// Contains security configuration of CA management
    /// (<strong>ICertAdmin</strong>) and enrollment (<strong>ICertRequest</strong>) RPC/DCOM interfaces.
    /// </summary>
    public sealed class CADcomSecurityConfig : AdcsCAConfigurationEntry {
        readonly String _caVersion;
        InterfaceFlagEnum flag;

        /// <inheritdoc />
        public CADcomSecurityConfig(AdcsCertificateAuthority certificateAuthority) : base(certificateAuthority) {
            RegEntries.Add(new AdcsInternalConfigPath { ValueName = "InterfaceFlags" });
            ReadConfig();
            flag = (InterfaceFlagEnum)RegEntries[0].Value;
            _caVersion = certificateAuthority.Version;
        }

        public InterfaceFlagEnum DcomSecurityFlag {
            get => flag;
            set {
                if (flag != value) {
                    flag = value;
                    RegEntries[0].Value = (Int32)flag;
                    IsModified = true;
                }
            }
        }

        /// <summary>
        /// Restores default management interface flags on a specified Certification Authority. The method do not
        /// writes default flags to a configuration. After calling this method call
        /// <see cref="AdcsCAConfigurationEntry.SaveChanges(Boolean)">SaveChanges</see> method to write values back to
        /// a configuration.
        /// </summary>
        /// <remarks>The following default flags are defined depending on an operating system:
        /// <list type="table">
        /// <listheader>
        /// <term>Operating system</term>
        /// <description>Default flags</description>
        /// </listheader>
        /// <item>
        /// <term><list type="bullet">
        /// <item>Windows 2000 Server</item>
        /// <item>Windows Server 2003, Standard, Enterprise, Datacenter editions</item>
        /// <item>Windows Server 2008, Standard, Enterprise, Datacenter editions</item>
        /// <item>Windows Server 2008 R2, Standard, Enterprise, Datacenter editions</item>
        /// </list></term>
        /// <description><list type="bullet">
        /// <item><strong>NoRemoteICertAdminBackup</strong></item>
        /// </list>
        /// </description>
        /// </item>
        /// <item>
        /// <term><list type="bullet">
        /// <item>Windows Server 2012 Foundation, Essentials, Standard, Datacenter editions</item>
        /// <item>Windows Server 2012 R2 Foundation, Essentials, Standard, Datacenter editions</item>
        /// <item>Windows Server 2016 Essentials, Standard, Datacenter editions</item>
        /// </list></term>
        /// <description><list type="bullet">
        /// <item><strong>LockICertRequest</strong></item>
        /// <item><strong>NoRemoteICertAdminBackup</strong></item>
        /// <item><strong>EnforceEncryptICertRequest</strong></item>
        /// <item><strong>EnforceEncryptICertAdmin</strong></item>
        /// </list>
        /// </description>
        /// </item>
        /// </list>
        /// </remarks>
        public void RestoreDefaults() {
            switch (_caVersion) {
                case "2000":
                    DcomSecurityFlag = InterfaceFlagEnum.NoRemoteICertAdminBackup;
                    break;
                case "2003":
                    DcomSecurityFlag = InterfaceFlagEnum.NoRemoteICertAdminBackup;
                    break;
                case "2008":
                    DcomSecurityFlag = InterfaceFlagEnum.NoRemoteICertAdminBackup;
                    break;
                case "2008R2":
                    DcomSecurityFlag = InterfaceFlagEnum.NoRemoteICertAdminBackup;
                    break;
                case "2012":
                case "2012R2":
                case "2016":
                    DcomSecurityFlag = InterfaceFlagEnum.NoRemoteICertAdminBackup |
                                     InterfaceFlagEnum.EnforceEncryptICertAdmin |
                                     InterfaceFlagEnum.EnforceEncryptICertRequest |
                                     InterfaceFlagEnum.LockICertRequest;

                    break;
                default:
                    DcomSecurityFlag = InterfaceFlagEnum.NoRemoteICertAdminBackup;
                    break;
            }
            IsModified = true;
        }
    }
}
