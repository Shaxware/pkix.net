using System.Security.Cryptography;

namespace SysadminsLV.PKI.Cryptography {
    abstract class RawPublicKey {

        protected RawPublicKey(Oid keyAlgorithm) {
            Oid = keyAlgorithm;
        }

        public Oid Oid { get; }

        public abstract AsymmetricAlgorithm GetAsymmetricKey();
    }
}
