using System;

namespace SysadminsLV.PKI.Management.CertificateServices.Database {
    /// <summary>
    /// A valid column index number for the view or a predefined column specifier
    /// </summary>
    public class AdcsDbQueryFilterEntry {

        public AdcsDbQueryFilterEntry(String columnName, AdcsDbSeekOperator op, Object value) {
            if (String.IsNullOrEmpty(columnName)) {
                throw new ArgumentNullException(nameof(columnName));
            }

            ColumnName = columnName;
            LogicalOperator = op;
            QualifierValue = value ?? throw new ArgumentNullException(nameof(value));
        }

        internal Int32 ColumnID { get; set; }
        /// <summary>
        /// A valid column name for the view or a predefined column specifier.
        /// </summary>
        public String ColumnName { get; }
        /// <summary>
        /// Specifies the logical operator of the data-query qualifier for the column. This parameter
        /// is used with the <see cref="QualifierValue"/> property to define the data-query qualifier.
        /// </summary>
        public AdcsDbSeekOperator LogicalOperator { get; }
        /// <summary>
        /// Specifies the data query qualifier applied to this column. This parameter, along with the
        /// <see cref="LogicalOperator"/> parameter, determines which data is returned to the Certificate Services view.
        /// </summary>
        public Object QualifierValue { get; }

        /// <inheritdoc />
        public override Boolean Equals(Object obj) {
            return !(obj is null)
                   && (ReferenceEquals(this, obj)
                       || obj is AdcsDbQueryFilterEntry other && Equals(other));
        }
        protected Boolean Equals(AdcsDbQueryFilterEntry other) {
            return String.Equals(ColumnName, other.ColumnName, StringComparison.OrdinalIgnoreCase)
                   && LogicalOperator == other.LogicalOperator
                   && Equals(QualifierValue, other.QualifierValue);
        }
        /// <inheritdoc />
        public override Int32 GetHashCode() {
            unchecked {
                Int32 hashCode = ColumnName != null ? StringComparer.OrdinalIgnoreCase.GetHashCode(ColumnName) : 0;
                hashCode = (hashCode * 397) ^ (Int32) LogicalOperator;
                hashCode = (hashCode * 397) ^ (QualifierValue != null ? QualifierValue.GetHashCode() : 0);
                return hashCode;
            }
        }
    }
}
