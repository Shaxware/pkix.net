using System;

namespace SysadminsLV.PKI.Management.CertificateServices.Configuration {
    /// <summary>
    /// Represents ADCS database timeout settings. There are two types of timeouts: idle timeout and
    /// connection timeout. When idle timeout is reached, a new connection to CA database must be created.
    /// When connection timeout is reached, a new connection to CA database must be created.
    /// </summary>
    public sealed class CACertViewTimoutConfig : AdcsCAConfigurationEntry {
        readonly AdcsInternalConfigPath _idleTimeout, _ageTimeout;

        /// <inheritdoc />
        public CACertViewTimoutConfig(AdcsCertificateAuthority certificateAuthority) : base(certificateAuthority) {
            RegEntries.Add(_idleTimeout = new AdcsInternalConfigPath { ValueName = "ViewIdleMinutes" });
            RegEntries.Add(_ageTimeout = new AdcsInternalConfigPath { ValueName = "ViewAgeMinutes" });
            ReadConfig();
        }

        /// <summary>
        /// Gets or sets CA database idle connection timeout in minutes. Default is 8 minutes. If there are no
        /// activity within active connection for specified period of time, the connection is closed by CA server
        /// and new connection to CA database must be created.
        /// </summary>
        public Int32 IdleTimeout {
            get => (Int32)_idleTimeout.Value;
            set {
                if ((Int32)_idleTimeout.Value != value) {
                    _idleTimeout.Value = value;
                    IsModified = true;
                }
            }
        }
        /// <summary>
        /// Gets or sets CA database connection validity in minutes. Default is 16 minutes. When connection to CA
        /// database is created, it is valid for specified period of time and then is closed by CA server and new
        /// connection to CA database must be created.
        /// </summary>
        public Int32 ViewTimeout {
            get => (Int32)_ageTimeout.Value;
            set {
                if ((Int32)_ageTimeout.Value != value) {
                    _ageTimeout.Value = value;
                    IsModified = true;
                }
            }
        }
    }
}
