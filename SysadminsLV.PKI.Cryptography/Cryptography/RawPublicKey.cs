using System;
using System.Security.Cryptography;

namespace SysadminsLV.PKI.Cryptography {
    abstract class RawPublicKey : IDisposable {

        protected RawPublicKey(Oid keyAlgorithm) {
            Oid = keyAlgorithm;
        }

        public Oid Oid { get; }

        /// <summary>
        /// Gets the implementation object for the current asymmetric algorithm.
        /// </summary>
        /// <returns>
        /// Object that implements particular asymmetric algorithm on a current platform.
        /// </returns>
        public abstract AsymmetricAlgorithm GetAsymmetricKey();
        /// <inheritdoc />
        public abstract void Dispose();
    }
}
