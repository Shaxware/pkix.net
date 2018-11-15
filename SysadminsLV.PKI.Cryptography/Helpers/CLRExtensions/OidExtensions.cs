using System;
using System.Security.Cryptography;

namespace SysadminsLV.PKI.Helpers.CLRExtensions {
    /// <summary>
    /// Contains extension methods for <see cref="Oid"/> class.
    /// </summary>
    public static class OidExtensions {
        /// <summary>
        /// Formats current OID instance to textual representation.
        /// </summary>
        /// <param name="oid"><see cref="Oid"/> object to format.</param>
        /// <param name="fullValue">Indicates whether to format both, OID friendly name and OID value.</param>
        /// <returns>Formatted OID value.</returns>
        /// <remarks>
        /// Depending on OID value and parameters, OID object can be encoded differently.
        /// <para>If <strong>fullValue</strong> is set to <strong>False</strong> and <see cref="Oid.FriendlyName"/>
        /// is not null, OID friendly name is returned, otherwise returns <see cref="Oid.Value"/>.
        /// </para>
        /// <para>If <strong>fullValue</strong> is set to <strong>True</strong> and <see cref="Oid.FriendlyName"/>
        /// is not null, method returns both, OID friendly name and value, otherwise returns <see cref="Oid.Value"/>.
        /// </para>
        /// <example>Examples:</example>
        /// <code>
        /// Oid oid = new Oid("1.2.3.4.5");
        /// oid.Format(false); // Format is extension method here.
        /// // outputs: 1.2.3.4.5
        /// oid.Format(true);
        /// // outputs: 1.2.3.4.5 -- the same as previously, because the OID is unknown.
        /// oid = new Oid("1.3.14.3.2.26");
        /// oid.Format(false);
        /// // outputs: sha1
        /// oid.Format(true);
        /// // outputs: sha1 (1.3.14.3.2.26)
        /// </code>
        /// </remarks>
        public static String Format(this Oid oid, Boolean fullValue) {
            return fullValue
                ? (String.IsNullOrEmpty(oid.FriendlyName)
                    ? oid.Value
                    : $"{oid.FriendlyName} ({oid.Value})")
                : (String.IsNullOrEmpty(oid.FriendlyName)
                    ? oid.Value
                    : oid.FriendlyName);
        }
        /// <summary>
        /// Compares two <strong>Oid</strong> objects for equality.
        /// </summary>
        /// <param name="oid">Source OID</param>
        /// <param name="other">An <strong>Oid</strong> object to compare to the current object.</param>
        /// <returns>
        /// <strong>True</strong> if <see cref="Oid.Value">Value</see> members of two OID instances are equal.
        /// This method is case-insensitive.
        /// </returns>
        /// <remarks>Original <see cref="Oid"/> class do not override <see cref="Object.Equals(Object)"/> method.</remarks>
        public static Boolean Equals2(this Oid oid, Oid other) {
            return other != null
                && oid.Value.Equals(other.Value, StringComparison.InvariantCultureIgnoreCase);
        }
        /// <summary>
        /// Gets hash code for the current OID object.
        /// </summary>
        /// <param name="oid"></param>
        /// <returns></returns>
        /// <remarks>Original <see cref="Oid"/> class do not override <see cref="Object.GetHashCode"/> method.</remarks>
        public static Int32 GetHashCode2(this Oid oid) {
            return oid.Value?.GetHashCode() ?? 0;
        }
    }
}
