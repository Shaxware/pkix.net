using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Win32.SafeHandles;
using PKI.Exceptions;
using PKI.Structs;

namespace PKI.Utils {
    /// <summary>
    /// Represents the utility which can be used to sign arbitrary data or verify existing signatures by using
    /// asymmetric encryption.
    /// </summary>
    /// <remarks>
    /// This class implements <see cref="IDisposable"/> interface. It is recommended to wrap this class in
    /// <i>using</i> statement to automatically release unmanaged resources during signing procedure.
    /// </remarks>
    public class MessageSigner : IDisposable {
        Boolean disposed;
        String pubKeyAlgorithm;
        SafeNCryptKeyHandle phCryptProv = new SafeNCryptKeyHandle();
        KeyType keyType;
        AsymmetricAlgorithm key;
        SignaturePadding padding = SignaturePadding.PKCS1;

        /// <summary>
        /// Initializes a new instance of the <strong>MessageSigner</strong> class from signer certificate and
        /// default hash algorithm. Default hash algorithm is SHA256.
        /// </summary>
        /// <param name="signer"></param>
        /// <exception cref="ArgumentException">
        ///     <strong>hashAlgorithm</strong> parameter contains invalid hash algorithm identifier.
        /// </exception>
        /// <exception cref="UninitializedObjectException">Signer certificate is not initialized.</exception>
        /// <exception cref="ArgumentNullException">
        /// <strong>signer</strong> parameter is null.
        /// </exception>
        public MessageSigner(X509Certificate2 signer) : this(signer, new Oid2("sha256", OidGroupEnum.HashAlgorithm, false)) {

        }
        /// <summary>
        /// Initializes a new instance of the <strong>MessageSigner</strong> class from signer certificate and
        /// client-provided hash algorithm.
        /// </summary>
        /// <param name="signer">Signer certificate with associated private key.</param>
        /// <param name="hashAlgorithm">
        /// Hash algorithm that is used to calculate the hash during signing or signature verification
        /// processes.
        /// </param>
        /// <exception cref="ArgumentException">
        ///     <strong>hashAlgorithm</strong> parameter contains invalid hash algorithm identifier.
        /// </exception>
        /// <exception cref="UninitializedObjectException">Signer certificate is not initialized.</exception>
        /// <exception cref="ArgumentNullException">
        /// <strong>signer</strong> and/or <strong>hashAlgorithm</strong> parameter is null.
        /// </exception>
        /// <remarks>
        /// Currently the following hash algorithms are supported:
        /// <list type="bullet">
        ///     <item>MD5</item>
        ///     <item>SHA1</item>
        ///     <item>SHA256</item>
        ///     <item>SHA384</item>
        ///     <item>SHA512</item>
        /// </list>
        /// Hash algorithm is ignored for DSA keys and is automatically set to 'SHA1'.
        /// </remarks>
        public MessageSigner(X509Certificate2 signer, Oid2 hashAlgorithm) {
            if (signer == null) { throw new ArgumentNullException(nameof(signer)); }
            if (hashAlgorithm == null) { throw new ArgumentNullException(nameof(hashAlgorithm)); }
            if (IntPtr.Zero.Equals(signer.Handle)) { throw new UninitializedObjectException(); }

            if (hashAlgorithm.OidGroup != OidGroupEnum.HashAlgorithm) {
                throw new ArgumentException("Invalid hashing algorithm is specified.");
            }
            SignerCertificate = signer;
            HashingAlgorithm = hashAlgorithm;
            getPrivateKey();
        }

        /// <summary>
        /// Gets the certificate associated with the current instance of 
        /// </summary>
        public X509Certificate2 SignerCertificate { get; private set; }
        /// <summary>
        /// Gets hashing algorithm that is used to calculate the hash during signing or signature verification
        /// processes.
        /// </summary>
        public Oid2 HashingAlgorithm { get; }
        /// <summary>
        /// Gets resulting signature algorithm identifier.
        /// </summary>
        public Oid SignatureAlgorithm { get; private set; }

        void getPrivateKey() {
            if (disposed) {
                throw new ObjectDisposedException(nameof(SignerCertificate));
            }
            if (key != null) { return; }

            UInt32 pdwKeySpec = 0;
            Boolean pfCallerFreeProv = false;
            if (!Crypt32.CryptAcquireCertificatePrivateKey(SignerCertificate.Handle,
                Wincrypt.CRYPT_ACQUIRE_ALLOW_NCRYPT_KEY_FLAG, IntPtr.Zero, ref phCryptProv, ref pdwKeySpec,
                ref pfCallerFreeProv)) {
                throw new CryptographicException(Marshal.GetLastWin32Error());
            }
            if (pdwKeySpec == UInt32.MaxValue) {
                getCngKey();
            } else {
                getLegacyKey();
            }
        }
        void getCngKey() {
            keyType = KeyType.Cng;
            CngKey cngKey = CngKey.Open(phCryptProv, CngKeyHandleOpenOptions.None);
            key = new ECDsaCng(cngKey);
            switch (SignerCertificate.PublicKey.Oid.Value) {
                case "1.2.840.10045.2.1": pubKeyAlgorithm = "ECDSA"; break;
                case "1.2.840.113549.1.1.1": pubKeyAlgorithm = "RSA"; break;
                case "1.2.840.10040.4.1": pubKeyAlgorithm = "DSA"; break;
                default: throw new NotSupportedException("Public key algorithm is not supported");
            }
        }
        void getLegacyKey() {
            switch (SignerCertificate.PublicKey.Oid.Value) {
                // RSA
                case "1.2.840.113549.1.1.1":
                    keyType = KeyType.Rsa;
                    pubKeyAlgorithm = "RSA";
                    break;
                // DSA
                case "1.2.840.10040.4.1":
                    keyType = KeyType.Dsa;
                    break;
                default: throw new NotSupportedException("Public key algorithm is not supported");
            }
            key = SignerCertificate.PrivateKey;
        }
        Byte[] calculateHash(Byte[] message) {
            HashAlgorithm hasher = HashAlgorithm.Create(HashingAlgorithm.FriendlyName);
            if (hasher == null) {
                throw new ArgumentException("Invalid hashing algorithm is specified.");
            }
            using (hasher) {
                return hasher.ComputeHash(message);
            }
        }
        void getSignatureAlgorithm() {
            switch (pubKeyAlgorithm) {
                case "ECDSA":
                    if (keyType == KeyType.Cng) {
                        SignatureAlgorithm = padding == SignaturePadding.PSS
                            ? new Oid("1.2.840.10045.4.3")                                      // specifiedECDSA
                            : new Oid($"{HashingAlgorithm}{pubKeyAlgorithm}");                  // ECDSA
                    } else {
                        SignatureAlgorithm = new Oid($"{HashingAlgorithm}{pubKeyAlgorithm}");   // ECDSA
                    }
                    break;
                case "RSA":
                    if (keyType == KeyType.Cng) {
                        SignatureAlgorithm = padding == SignaturePadding.PSS
                            ? new Oid("1.2.840.113549.1.1.10")                                  // RSASSA-PSS
                            : new Oid($"{HashingAlgorithm}{pubKeyAlgorithm}");                  // RSA
                    } else {
                        SignatureAlgorithm = new Oid($"{HashingAlgorithm}{pubKeyAlgorithm}");   // RSA
                    }
                    break;
                case "DSA":
                    // DSA doesn't support PSS padding and hashing algorithm other than SHA1
                    SignatureAlgorithm = new Oid("1.2.840.10040.4.3");                          // sha1DSA
                    break;
            }
        }
        Byte[] signHashCng(Byte[] hash) {
            return ((ECDsa)key).SignHash(hash);
        }
        Byte[] signHashRsa(Byte[] hash) {
            return ((RSACryptoServiceProvider)key).SignHash(hash, HashingAlgorithm.FriendlyName);
        }
        Byte[] signHashDsa(Byte[] hash) {
            return ((DSACryptoServiceProvider)key).SignHash(hash, "sha1");
        }

        public Byte[] SignData(Byte[] message) {
            if (message == null) { throw new ArgumentNullException(nameof(message)); }
            return SignHash(calculateHash(message));
        }
        public Byte[] SignHash(Byte[] hash) {
            if (hash == null) { throw new ArgumentNullException(nameof(hash)); }
            Byte[] signature;
            switch (keyType) {
                case KeyType.Cng: signature = signHashCng(hash); break;
                case KeyType.Rsa: signature = signHashRsa(hash); break;
                case KeyType.Dsa: signature = signHashDsa(hash); break;
                default:
                    throw new InvalidOperationException(new Win32Exception(Error.InvalidParameterException).Message);
            }
            getSignatureAlgorithm();
            return signature;
        }

        #region IDisposable implementation
        void releaseUnmanagedResources() {
            key.Dispose();
            key = null;
            Crypt32.CertFreeCertificateContext(SignerCertificate.Handle);
            SignerCertificate = null;
            disposed = true;
        }
        /// <inheritdoc />
        public void Dispose() {
            releaseUnmanagedResources();
            GC.SuppressFinalize(this);
        }
        /// <inheritdoc />
        ~MessageSigner() {
            releaseUnmanagedResources();
        }
        #endregion

        enum KeyType {
            Cng,
            Rsa,
            Dsa
        }
    }
}
