﻿using System;
using System.Security.Cryptography;
using SysadminsLV.PKI.Cryptography;

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
                ? String.IsNullOrEmpty(oid.FriendlyName)
                    ? oid.Value
                    : $"{oid.FriendlyName} ({oid.Value})"
                : String.IsNullOrEmpty(oid.FriendlyName)
                    ? oid.Value
                    : oid.FriendlyName;
        }
        /// <summary>
        /// Converts hashing algorithm OID to appropriate OID from signature group. For example, translates
        /// <strong>sha1</strong> hashing algorithm to <strong>sha1NoSign</strong> with the same OID value.
        /// </summary>
        /// <param name="hashAlgorithm">Hashing algorithm</param>
        /// <exception cref="ArgumentNullException">
        /// <strong>hashAlgorithm</strong> parameter is null.
        /// </exception>
        /// <exception cref="ArgumentException">
        /// Input OID doesn't belong to hash algorithm group or it cannot be translated to a respective
        /// </exception>
        /// <returns>OID in signature group.</returns>
        public static Oid MapHashToSignatureOid(Oid hashAlgorithm) {
            if (hashAlgorithm == null) {
                throw new ArgumentNullException(nameof(hashAlgorithm));
            }
            switch (hashAlgorithm.Value) {
                case AlgorithmOids.MD5:
                    return new Oid(AlgorithmOids.MD5, "md5NoSign");
                case AlgorithmOids.SHA1:
                    return new Oid(AlgorithmOids.SHA1, "sha1NoSign");
                case AlgorithmOids.SHA256:
                    return new Oid(AlgorithmOids.SHA256, "sha256NoSign");
                case AlgorithmOids.SHA384:
                    return new Oid(AlgorithmOids.SHA384, "sha384NoSign");
                case AlgorithmOids.SHA512:
                    return new Oid(AlgorithmOids.SHA512, "sha512NoSign");
                default:
                    throw new ArgumentException("Cannot translate hashing algorithm to signature algorithm.");
            }
        }
    }
}
