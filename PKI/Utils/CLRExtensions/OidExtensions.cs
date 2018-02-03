using System;
using System.Security.Cryptography;

namespace PKI.Utils.CLRExtensions {
    static class OidExtensions {
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
		public static Boolean Equals2(this Oid oid, Oid other) {
		    return other != null
				&& oid.Value.Equals(other.Value, StringComparison.InvariantCultureIgnoreCase);
	    }
	    public static Int32 GetHashCode2(this Oid oid) {
		    return oid.Value?.GetHashCode() ?? 0;
	    }
    }
}
