using System;
using Microsoft.Win32;

namespace SysadminsLV.PKI.Management.CertificateServices.Configuration {
    /// <summary>
    /// Represents internal registry-based ADCS single config entry. This class is used only by inheritors of
    /// <see cref="AdcsInternalConfigPath"/> class.
    /// </summary>
    public class AdcsInternalConfigPath {
        /// <summary>
        /// Gets or sets the node path under Configuration section.
        /// </summary>
        public String NodePath { get; set; }
        /// <summary>
        /// Gets or sets registry value name of the setting;
        /// </summary>
        public String ValueName { get; set; }
        /// <summary>
        /// Gets or sets the registry value type.
        /// </summary>
        public RegistryValueKind ValueType { get; set; }
        /// <summary>
        /// Gets or sets value associated with the current setting. When reading from ADCS configuration,
        /// <see cref="AdcsConfigurationEntry"/> object will populate this member with value. Implementers
        /// can use this value for presentation and management purposes. When writing back to ADCS configuration,
        /// implementers are responsible to provide registry-based compatible value to this member.
        /// </summary>
        public Object Value { get; set; }

        /// <inheritdoc />
        public override Boolean Equals(Object obj) {
            return !(obj is null)
                   && (ReferenceEquals(this, obj)
                   || obj.GetType() == GetType()
                   && Equals((AdcsInternalConfigPath) obj));
        }
        protected Boolean Equals(AdcsInternalConfigPath other) {
            return String.Equals(NodePath, other.NodePath, StringComparison.OrdinalIgnoreCase)
                   && String.Equals(ValueName, other.ValueName, StringComparison.OrdinalIgnoreCase);
        }
        /// <inheritdoc />
        public override Int32 GetHashCode() {
            unchecked {
                return ((NodePath != null ? StringComparer.OrdinalIgnoreCase.GetHashCode(NodePath) : 0) * 397)
                       ^ (ValueName != null ? StringComparer.OrdinalIgnoreCase.GetHashCode(ValueName) : 0);
            }
        }
    }
}
