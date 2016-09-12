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
    }
}
