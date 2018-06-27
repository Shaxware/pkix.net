namespace SysadminsLV.PKI.Management.CertificateServices.Configuration {
    /// <summary>
    /// Contains enumeration of common validity units used by CA server.
    /// </summary>
    public enum AdcsValidityUnit {
        /// <summary>
        /// Specifies invalid period unit type.
        /// </summary>
        Invalid,
        /// <summary>
        /// Period is measured in hours.
        /// </summary>
        Hours,
        /// <summary>
        /// Period is measured in Days.
        /// </summary>
        Days,
        /// <summary>
        /// Period is measured in Weeks.
        /// </summary>
        Weeks,
        /// <summary>
        /// Period is measured in Months.
        /// </summary>
        Months,
        /// <summary>
        /// Period is measured in years.
        /// </summary>
        Years
    }
}