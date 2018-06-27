using System;
using PKI.CertificateServices;

namespace SysadminsLV.PKI.Management.CertificateServices.Configuration {
    /// <summary>
    /// Represents Certification Authority object with defined maximum validity period of issued certificates.
    /// </summary>
    /// <remarks>These settings are not ultimate. Issued certificate's effective validity period is the smallest
    /// value of:
    /// <list type="bullet">
    /// <item>Remaining validity of the CA certificate.</item>
    /// <item>ValidityPeriod registry settings (this object implements ValidityPeriod setting).</item>
    /// <item>Validity defined in certificate template (Enterprise CAs only).</item>
    /// <item>Validity period specified in certificate request.</item>
    /// </list> 
    /// </remarks>
    public sealed class CAIssuedCertValidityConfig : AdcsConfigurationEntry {
        readonly AdcsInternalConfigPath _period, _units;

        /// <inheritdoc />
        public CAIssuedCertValidityConfig(CertificateAuthority certificateAuthority) : base(certificateAuthority) {
            _period = new AdcsInternalConfigPath { ValueName = "ValidityPeriodUnits" };
            _units = new AdcsInternalConfigPath { ValueName = "ValidityPeriod" };
            RegEntries.Add(_period);
            RegEntries.Add(_units);
            ReadConfig();
        }

        /// <summary>
        /// Gets or sets validity period of issued certificates. Period value is measured in units specified in
        /// <see cref="ValidityPeriodUnits"/> member.
        /// </summary>
        /// <exception cref="ArgumentException">
        /// The value is either, zero or negative integer.
        /// </exception>
        public Int32 ValidityPeriod {
            get => (Int32)_period.Value;
            set {
                if (value < 1) {
                    throw new ArgumentException("The value must be nonzero, positive integer.");
                }
                if ((Int32)_period.Value != value) {
                    _period.Value = value;
                    IsModified = true;
                }
            }
        }
        /// <summary>
        /// Gets or sets validity period unit measure.
        /// </summary>
        /// <remarks><strong>Invalid</strong> unit type is not allowed in this member's setter.</remarks>
        public AdcsValidityUnit ValidityPeriodUnits {
            get {
                Enum.TryParse(_units.Value.ToString(), true, out AdcsValidityUnit unit);
                return unit;
            }
            set {
                if (value != AdcsValidityUnit.Invalid) {
                    _units.Value = value.ToString();
                    IsModified = true;
                }
            }
        }
        /// <summary>
        /// Gets a read-only property that displays a composed value of this setting.
        /// </summary>
        public String ValidityPeriodString => $"{ValidityPeriod} {ValidityPeriodUnits}";
    }
}
