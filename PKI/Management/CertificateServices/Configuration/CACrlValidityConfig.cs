using System;
using PKI.CertificateServices;

namespace SysadminsLV.PKI.Management.CertificateServices.Configuration {
    /// <summary>
    /// Represents Certification Authority object with defined certificate revocation list validity settings.
    /// </summary>
    /// <remarks>
    /// Certification Authority publishes Base and (optionally) Delta CRLs on a periodic basis. These periods
    /// are configured by this class. Microsoft ADCS implements overlap term that is supposed to provide extra
    /// validity between moments when new CRL is published and previous CRL expires. It is necessary to allow CRLs to
    /// replicate between CRL distribution points.
    /// <para>
    /// In general, CRLs are published according to publication settings and its validity is prolonged by an
    /// overlap value. For example, if CRL publication period is set to 1 week and overlap is set to 1 day,
    /// then CA will publish new CRL each week, but effective validity will be 8 days or, simply,
    /// Total validity = CRL period + Overlap. More details on how validity and overlap works, read the following
    /// blog article: 
    /// <see href="https://www.sysadmins.lv/blog-en/how-thisupdate-nextupdate-and-nextcrlpublish-are-calculated-v2.aspx">
    /// How ThisUpdate, NextUpdate and NextCRLPublish are calculated (v2)</see>
    /// </para>
    /// </remarks>
    public sealed class CACrlValidityConfig : AdcsConfigurationEntry {
        readonly AdcsInternalConfigPath _basePeriod, _baseUnits, _baseOverlapPeriod, _baseOverlapUnits,
                                        _deltaPeriod, _deltaUnits, _deltaOverlapPeriod, _deltaOverlapUnits;
        /// <inheritdoc />
        public CACrlValidityConfig(CertificateAuthority certificateAuthority) : base(certificateAuthority) {
            _basePeriod         = new AdcsInternalConfigPath { ValueName = "CRLPeriodUnits" };
            _baseUnits          = new AdcsInternalConfigPath { ValueName = "CRLPeriod" };
            _baseOverlapPeriod  = new AdcsInternalConfigPath { ValueName = "CRLOverlapUnits" };
            _baseOverlapUnits   = new AdcsInternalConfigPath { ValueName = "CRLOverlapPeriod" };
            _deltaPeriod        = new AdcsInternalConfigPath { ValueName = "CRLDeltaPeriodUnits" };
            _deltaUnits         = new AdcsInternalConfigPath { ValueName = "CRLDeltaPeriod" };
            _deltaOverlapPeriod = new AdcsInternalConfigPath { ValueName = "CRLDeltaOverlapUnits" };
            _deltaOverlapUnits  = new AdcsInternalConfigPath { ValueName = "CRLDeltaOverlapPeriod" };
            foreach (var entry in new[] {
                    _basePeriod, _baseUnits, _baseOverlapPeriod, _baseOverlapUnits,
                    _deltaPeriod, _deltaUnits, _deltaOverlapPeriod, _deltaOverlapUnits
                }) {
                RegEntries.Add(entry);
            }
            ReadConfig();
        }

        /// <summary>
        /// Gets or sets validity period of Base CRL. Period value is measured in units specified in
        /// <see cref="BaseCrlPeriodUnits"/> member.
        /// </summary>
        /// <exception cref="ArgumentException">
        /// The value is either, zero or negative integer.
        /// </exception>
        public Int32 BaseCrlPeriod {
            get => (Int32)_basePeriod.Value;
            set {
                if (value < 1) {
                    throw new ArgumentException("The value must be a nonzero, positive integer.");
                }
                if ((Int32)_basePeriod.Value != value) {
                    _basePeriod.Value = value;
                    IsModified = true;
                }
            }
        }
        /// <summary>
        /// Gets or sets validity period unit measure for Base CRL.
        /// </summary>
        /// <remarks><strong>Invalid</strong> unit type is not allowed in this member's setter.</remarks>
        public AdcsValidityUnit BaseCrlPeriodUnits {
            get {
                Enum.TryParse(_baseUnits.Value.ToString(), true, out AdcsValidityUnit unit);
                return unit;
            }
            set {
                if (value != AdcsValidityUnit.Invalid) {
                    _baseUnits.Value = value.ToString();
                    IsModified = true;
                }
            }
        }
        /// <summary>
        /// Gets a read-only property that displays a composed value of Base CRL validity setting.
        /// </summary>
        public String BaseCrlPeriodString => $"{BaseCrlPeriod} {BaseCrlPeriodUnits}";

        /// <summary>
        /// Gets or sets Base CRL validity overlap. Overlap value is measured in units specified in
        /// <see cref="BaseCrlOverlapPeriodUnits"/> member.
        /// </summary>
        /// <exception cref="ArgumentException">
        /// The value is negative integer.
        /// </exception>
        /// <remarks>
        /// Setting this member to zero will set overlap value to its default value (10% of Base CRL validity).
        /// </remarks>
        public Int32 BaseCrlOverlapPeriod {
            get => (Int32)_baseOverlapPeriod.Value;
            set {
                if (value < 0) {
                    throw new ArgumentException("The value must be zero or positive integer.");
                }
                if ((Int32)_baseOverlapPeriod.Value != value) {
                    _baseOverlapPeriod.Value = value;
                    IsModified = true;
                }
            }
        }
        /// <summary>
        /// Gets or sets Base CRL overlap period unit measure.
        /// </summary>
        /// <remarks><strong>Invalid</strong> unit type is not allowed in this member's setter.</remarks>
        public AdcsValidityUnit BaseCrlOverlapPeriodUnits {
            get {
                Enum.TryParse(_baseOverlapUnits.Value.ToString(), true, out AdcsValidityUnit unit);
                return unit;
            }
            set {
                if (value != AdcsValidityUnit.Invalid) {
                    _baseOverlapUnits.Value = value.ToString();
                    IsModified = true;
                }
            }
        }
        /// <summary>
        /// Gets a read-only property that displays a composed value of Base CRL overlap setting.
        /// </summary>
        public String BaseCrlOverlapString => $"{BaseCrlOverlapPeriod} {BaseCrlOverlapPeriodUnits}";

        /// <summary>
        /// Gets or sets validity period of Delta CRL. Period value is measured in units specified in
        /// <see cref="DeltaCrlPeriodUnits"/> member.
        /// </summary>
        /// <exception cref="ArgumentException">
        /// The value is negative integer.
        /// </exception>
        /// <remarks>Setting this value to zero will effectively disable Delta CRL publication.</remarks>
        public Int32 DeltaCrlPeriod {
            get => (Int32)_deltaPeriod.Value;
            set {
                if (value < 0) {
                    throw new ArgumentException("The value must be zero or positive integer.");
                }
                if ((Int32)_deltaPeriod.Value != value) {
                    _deltaPeriod.Value = value;
                    IsModified = true;
                }
            }
        }
        /// <summary>
        /// Gets or sets validity period unit measure for Delta CRL.
        /// </summary>
        /// <remarks><strong>Invalid</strong> unit type is not allowed in this member's setter.</remarks>
        public AdcsValidityUnit DeltaCrlPeriodUnits {
            get {
                Enum.TryParse(_deltaUnits.Value.ToString(), true, out AdcsValidityUnit unit);
                return unit;
            }
            set {
                if (value != AdcsValidityUnit.Invalid) {
                    _deltaUnits.Value = value.ToString();
                    IsModified = true;
                }
            }
        }
        /// <summary>
        /// Gets a read-only property that displays a composed value of Delta CRL setting.
        /// </summary>
        public String DeltaCrlPeriodString => $"{DeltaCrlPeriod} {DeltaCrlPeriodUnits}";

        /// <summary>
        /// Gets or sets overlap period for Delta CRL. Overlap value is measured in units specified in
        /// <see cref="DeltaCrlOverlapPeriodUnits"/> member.
        /// </summary>
        /// <exception cref="ArgumentException">
        /// The value is negative integer.
        /// </exception>
        ///  <remarks>
        /// Setting this member to zero will set overlap value to its default value (10% of Delta CRL validity).
        /// </remarks>
        public Int32 DeltaCrlOverlapPeriod {
            get => (Int32)_deltaOverlapPeriod.Value;
            set {
                if (value < 0) {
                    throw new ArgumentException("The value must be zero or positive integer.");
                }
                if ((Int32)_deltaOverlapPeriod.Value != value) {
                    _deltaOverlapPeriod.Value = value;
                    IsModified = true;
                }
            }
        }
        /// <summary>
        /// Gets or sets Delta CRL validity overlap. Overlap value is measured in units specified in
        /// </summary>
        /// <remarks><strong>Invalid</strong> unit type is not allowed in this member's setter.</remarks>
        public AdcsValidityUnit DeltaCrlOverlapPeriodUnits {
            get {
                Enum.TryParse(_deltaOverlapUnits.Value.ToString(), true, out AdcsValidityUnit unit);
                return unit;
            }
            set {
                if (value != AdcsValidityUnit.Invalid) {
                    _deltaOverlapUnits.Value = value.ToString();
                    IsModified = true;
                }
            }
        }
        /// <summary>
        /// Gets a read-only property that displays a composed value of Delta CRL overlap setting.
        /// </summary>
        public String DeltaCrlOverlapPeriodString => $"{DeltaCrlOverlapPeriod} {DeltaCrlOverlapPeriodUnits}";
    }
}
