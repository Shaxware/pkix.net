using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Win32.SafeHandles;
using PKI.Exceptions;
using PKI.Structs;
using PKI.Utils.CLRExtensions;

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
        const String MSFT_KSP_NAME = "Microsoft Software Key Storage Provider";
        Boolean disposed, isCng;
        String pubKeyAlgorithm;
        SafeNCryptKeyHandle phPrivKey = new SafeNCryptKeyHandle();
        SafeNCryptKeyHandle phPubKey = new SafeNCryptKeyHandle();
        KeyType keyType;
        AsymmetricAlgorithm legacyKey;

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
        /// <summary>
        /// Gets or sets signature padding scheme signature creation and validation.
        /// Default is <strong>PKCS1</strong>. Currently, padding is implemented only for<strong>RSA</strong>
        /// asymmetric algorithm.
        /// </summary>
        public SignaturePadding PaddingScheme { get; set; } = SignaturePadding.PKCS1;
        /// <summary>
        /// Gets or sets the size, in bytes, of the random salt to use for the PSS padding.
        /// Default value is 32.
        /// </summary>
        public Int32 PssSaltByteCount { get; set; } = 32;

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
                    if (keyType == KeyType.EcDsa) {
                        SignatureAlgorithm = PaddingScheme == SignaturePadding.PSS
                            ? new Oid("1.2.840.10045.4.3")                                  // specifiedECDSA
                            : new Oid($"{HashingAlgorithm.FriendlyName}{pubKeyAlgorithm}"); // ECDSA
                    } else {
                        SignatureAlgorithm = new Oid($"{HashingAlgorithm}{pubKeyAlgorithm}"); // ECDSA
                    }

                    break;
                case "RSA":
                    if (keyType == KeyType.Rsa) {
                        SignatureAlgorithm = PaddingScheme == SignaturePadding.PSS
                            ? new Oid("1.2.840.113549.1.1.10")                              // RSASSA-PSS
                            : new Oid($"{HashingAlgorithm.FriendlyName}{pubKeyAlgorithm}"); // RSA
                    } else {
                        SignatureAlgorithm = new Oid($"{HashingAlgorithm.FriendlyName}{pubKeyAlgorithm}"); // RSA
                    }

                    break;
                case "DSA":
                    // DSA doesn't support PSS padding and hashing algorithm other than SHA1
                    SignatureAlgorithm = new Oid("1.2.840.10040.4.3"); // sha1DSA
                    break;
            }
        }
        Boolean checkKeyIsLoaded() {
            if (isCng) {
                return !IntPtr.Zero.Equals(phPrivKey.DangerousGetHandle());
            }
            return legacyKey != null;
        }

        #region Private key operations
        void acquirePrivateKey() {
            if (disposed) {
                throw new ObjectDisposedException(nameof(SignerCertificate));
            }
            // the key is already acquired, so skip key retrieval
            if (checkKeyIsLoaded()) { return; }
            // the key is not acquired, so attempt to get it
            UInt32 pdwKeySpec = 0;
            Boolean pfCallerFreeProv = false;
            SafeNCryptKeyHandle phCryptProvOrNCryptKey = new SafeNCryptKeyHandle();
            if (!Crypt32.CryptAcquireCertificatePrivateKey(
                SignerCertificate.Handle,
                Wincrypt.CRYPT_ACQUIRE_ALLOW_NCRYPT_KEY_FLAG,
                IntPtr.Zero,
                ref phCryptProvOrNCryptKey,
                ref pdwKeySpec,
                ref pfCallerFreeProv)) {
                throw new CryptographicException(Marshal.GetLastWin32Error());
            }
            if (pdwKeySpec == UInt32.MaxValue) {
                phPrivKey = phCryptProvOrNCryptKey;
                buildCngPrivateKey();
            } else {
                // translate legacy CSP key to CNG key handle
                getCngHandleFromLegacy(phCryptProvOrNCryptKey);
            }
        }
        void acquirePublicKey() {
            // regardless of public key algorithm and provider, load public keys to CNG provider for unification
            // and wider signature formats and padding support.
            Int32 hresult = nCrypt.NCryptOpenStorageProvider(out SafeNCryptProviderHandle phProvider, MSFT_KSP_NAME, 0);
            if (hresult != 0) {
                throw new CryptographicException(hresult);
            }

            var blob = SignerCertificate.PublicKey.GetCryptBlob();
            hresult = nCrypt.NCryptImportKey(phProvider, IntPtr.Zero, "PUBLICBLOB", IntPtr.Zero, out phPubKey, blob,
                blob.Length, 0);
            if (hresult != 0) {
                throw new CryptographicException(hresult);
            }
        }
        void getCngHandleFromLegacy(SafeHandle phCryptProvOrNCryptKey) {
            // attempt to translate legacy HCRYPTPROV handle to CNG key handle
            Int32 hresult = nCrypt.NCryptTranslateHandle(
                IntPtr.Zero,
                out SafeNCryptKeyHandle cngKey,
                phCryptProvOrNCryptKey.DangerousGetHandle(),
                IntPtr.Zero,
                (UInt32)X509KeySpecFlags.AT_SIGNATURE,
                0);
            // release legacy HCRYPTPROV handle
            AdvAPI.CryptReleaseContext(phCryptProvOrNCryptKey.DangerousGetHandle(), 0);
            if (hresult == 0) {
                // if key is successfully translated, assign new CNG key handle to phPrivKey
                phPrivKey = cngKey;
                buildCngPrivateKey();
            } else {
                // if key translation failed, then switch to legacy RSA/DSACryptoServiceProvider
                buildLegacyPrivateKey();
            }
        }
        void buildCngPrivateKey() {
            // this project is compiled against .NET 4.0, so RsaCng and DsaCng unavailable.
            // as the result, phCryptProv handle is used for signing and signature validation operations
            isCng = true;
            switch (SignerCertificate.PublicKey.Oid.Value) {
                case "1.2.840.10045.2.1":
                    pubKeyAlgorithm = "ECDSA";
                    keyType = KeyType.EcDsa;
                    break;
                case "1.2.840.113549.1.1.1":
                    pubKeyAlgorithm = "RSA";
                    keyType = KeyType.Rsa;
                    break;
                case "1.2.840.10040.4.1":
                    pubKeyAlgorithm = "DSA";
                    keyType = KeyType.Dsa;
                    break;
                default:
                    throw new NotSupportedException("Public key algorithm is not supported");
            }
        }
        void buildLegacyPrivateKey() {
            isCng = false;
            legacyKey = SignerCertificate.PrivateKey;
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
                default:
                    throw new NotSupportedException("Asymmetric key algorithm is not supported");
            }

            // if we reach this far, then the key is presented and legacy. So X509Certificate2.PrivateKey
            // member is not null and contains private key.
            legacyKey = SignerCertificate.PrivateKey;
        }
        #endregion

        #region Generics
        delegate Int32 NCryptSignHash<T>(
            SafeNCryptKeyHandle hKey,
            ref T pvPaddingInfo,
            Byte[] pbHashValue,
            Int32 cbHashValue,
            Byte[] pbSignature,
            Int32 cbSignature,
            out Int32 pcbResult,
            SignaturePadding dwFlags) where T : struct;

        delegate Int32 NCryptVerifySignature<T>(
            SafeNCryptKeyHandle hKey,
            ref T pvPaddingInfo,
            Byte[] pbHashValue,
            Int32 cbHashValue,
            Byte[] pbSignature,
            Int32 cbSignature,
            SignaturePadding dwFlags) where T : struct;

        Byte[] signHashCngGeneric<T>(Byte[] hash, T padding, NCryptSignHash<T> signer)
            where T : struct {
            Int32 hresult = signer(
                phPrivKey,
                ref padding,
                hash,
                hash.Length,
                null,
                0,
                out Int32 pcbResult,
                PaddingScheme);
            if (hresult != 0) {
                throw new CryptographicException(hresult);
            }

            Byte[] pbSignature = new Byte[pcbResult];
            hresult = signer(
                phPrivKey,
                ref padding,
                hash,
                hash.Length,
                pbSignature,
                pbSignature.Length,
                out pcbResult,
                PaddingScheme);
            if (hresult != 0) {
                throw new CryptographicException(hresult);
            }

            return pbSignature;
        }
        Boolean verifyHashGeneric<T>(Byte[] hash, Byte[] signature, T padding, NCryptVerifySignature<T> signer)
            where T : struct {
            Int32 hresult = signer(
                phPubKey,
                ref padding,
                hash,
                hash.Length,
                signature,
                signature.Length,
                PaddingScheme);
            return hresult == 0;
        }
        #endregion

        #region signature creation
        // base methods. They decide which routine to call depending on configuration state
        Byte[] signHashEcDsa(Byte[] hash) {
            return signHashEcDsaCng(hash);
        }
        Byte[] signHashDsa(Byte[] hash) {
            return isCng
                ? signHashDsaCng(hash)
                : signHashDsaLegacy(hash);
        }
        Byte[] signHashRsa(Byte[] hash) {
            return isCng
                ? (PaddingScheme == SignaturePadding.PSS
                    ? signHashRsaCngPss(hash)
                    : signHashRsaCngPkcs1(hash))
                : signHashRsaLegacy(hash);
        }

        // signing with CNG keys
        Byte[] signHashEcDsaCng(Byte[] hash) {
            Int32 hresult = nCrypt.NCryptSignHash(
                phPrivKey,
                IntPtr.Zero,
                hash,
                hash.Length,
                null,
                0,
                out Int32 pcbResult,
                0);
            if (hresult != 0) {
                throw new CryptographicException(hresult);
            }

            Byte[] pbSignature = new Byte[pcbResult];
            hresult = nCrypt.NCryptSignHash(
                phPrivKey,
                IntPtr.Zero,
                hash,
                hash.Length,
                pbSignature,
                pbSignature.Length,
                out pcbResult,
                0);
            if (hresult != 0) {
                throw new CryptographicException(hresult);
            }

            return pbSignature;
        }
        Byte[] signHashRsaCngPkcs1(Byte[] hash) {
            var pad = new nCrypt2.BCRYPT_PKCS1_PADDING_INFO {
                pszAlgId = HashingAlgorithm.FriendlyName.ToUpper()
            };
            return signHashCngGeneric(hash, pad, nCrypt.NCryptSignHash);
        }
        Byte[] signHashRsaCngPss(Byte[] hash) {
            var pad = new nCrypt2.BCRYPT_PSS_PADDING_INFO {
                pszAlgId = HashingAlgorithm.FriendlyName.ToUpper(),
                cbSalt = PssSaltByteCount
            };
            return signHashCngGeneric(hash, pad, nCrypt.NCryptSignHash);
        }
        Byte[] signHashDsaCng(Byte[] hash) {
            return signHashEcDsa(hash);
        }

        // specific fallback methods when legacy key cannot be translated to CNG key.
        // Hardware-based legacy CSPs fall to this category.
        Byte[] signHashRsaLegacy(Byte[] hash) {
            // overwrite padding to PKCS1, legacy CSP doesn't support PSS.
            PaddingScheme = SignaturePadding.PKCS1;
            return ((RSACryptoServiceProvider)legacyKey).SignHash(hash, HashingAlgorithm.Value);
        }
        Byte[] signHashDsaLegacy(Byte[] hash) {
            return ((DSACryptoServiceProvider)legacyKey).SignHash(hash, "sha1");
        }
        #endregion

        #region signature validation
        Boolean verifyHashEcDsa(Byte[] hash, Byte[] signature) {
            Int32 hresult = nCrypt.NCryptVerifySignature(phPubKey, IntPtr.Zero, hash, hash.Length, signature,
                signature.Length, 0);
            return hresult == 0;
        }
        Boolean verifyHashRsa(Byte[] hash, Byte[] signature) {
            return PaddingScheme == SignaturePadding.PSS
                ? verifyHashRsaPss(hash, signature)
                : verifyHashRsaPkcs1(hash, signature);
        }
        Boolean verifyHashDsa(Byte[] hash, Byte[] signature) {
            return verifyHashEcDsa(hash, signature);
        }

        Boolean verifyHashRsaPkcs1(Byte[] hash, Byte[] signature) {
            var pad = new nCrypt2.BCRYPT_PKCS1_PADDING_INFO {
                pszAlgId = HashingAlgorithm.FriendlyName.ToUpper()
            };
            return verifyHashGeneric(hash, signature, pad, nCrypt.NCryptVerifySignature);
        }
        Boolean verifyHashRsaPss(Byte[] hash, Byte[] signature) {
            var pad = new nCrypt2.BCRYPT_PSS_PADDING_INFO {
                pszAlgId = HashingAlgorithm.FriendlyName.ToUpper(),
                cbSalt = PssSaltByteCount
            };
            return verifyHashGeneric(hash, signature, pad, nCrypt.NCryptVerifySignature);
        }
        #endregion

        /// <summary>
        /// Signs the data with signer's private key and specified hash algorithm.
        /// </summary>
        /// <param name="message">Raw message to sign.</param>
        /// <exception cref="ArgumentNullException"><strong>message</strong> parameter is null.</exception>
        /// <returns>Raw signature.</returns>
        /// <remarks>For DSA private key only SHA1 hash is used.</remarks>
        public Byte[] SignData(Byte[] message) {
            if (message == null) { throw new ArgumentNullException(nameof(message)); }
            return SignHash(calculateHash(message));
        }
        /// <summary>
        /// Signs the hash with signer's private key.
        /// </summary>
        /// <param name="hash">Hash to sign.</param>
        /// <exception cref="ArgumentNullException"><strong>hash</strong> parameter is null.</exception>
        /// <returns>Raw signature.</returns>
        public Byte[] SignHash(Byte[] hash) {
            if (hash == null) { throw new ArgumentNullException(nameof(hash)); }
            acquirePrivateKey();
            Byte[] signature;
            switch (keyType) {
                case KeyType.EcDsa:
                    signature = signHashEcDsa(hash);
                    break;
                case KeyType.Rsa:
                    signature = signHashRsa(hash);
                    break;
                case KeyType.Dsa:
                    signature = signHashDsa(hash);
                    break;
                default:
                    throw new InvalidOperationException(new Win32Exception(Error.InvalidParameterException).Message);
            }
            getSignatureAlgorithm();
            return signature;
        }

        /// <summary>
        /// Verifies that the specified signature matches the specified hash.
        /// </summary>
        /// <param name="message">The data that was signed.</param>
        /// <param name="signature">The signature data to be verified.</param>
        /// <exception cref="ArgumentNullException">
        /// <strong>message</strong> or <strong>signature</strong> parameter is null.
        /// </exception>
        /// <returns>
        /// <strong>True</strong> if hash matches the one stored in signature, otherwise <strong>False</strong>.
        /// </returns>
        public Boolean VerifyData(Byte[] message, Byte[] signature) {
            if (message == null) { throw new ArgumentNullException(nameof(message)); }
            if (signature == null) { throw new ArgumentNullException(nameof(signature)); }

            return VerifyHash(calculateHash(message), signature);
        }
        /// <summary>
        /// Verifies that the specified signature matches the specified hash.
        /// </summary>
        /// <param name="hash">The hash value of the signed data.</param>
        /// <param name="signature">The signature data to be verified.</param>
        /// <exception cref="ArgumentNullException">
        /// <strong>hash</strong> or <strong>signature</strong> parameter is null.
        /// </exception>
        /// <returns>
        /// <strong>True</strong> if hash matches the one stored in signature, otherwise <strong>False</strong>.
        /// </returns>
        public Boolean VerifyHash(Byte[] hash, Byte[] signature) {
            if (hash == null) { throw new ArgumentNullException(nameof(hash)); }
            if (signature == null) { throw new ArgumentNullException(nameof(signature)); }
            acquirePublicKey();
            switch (SignerCertificate.PublicKey.Oid.Value) {
                case "1.2.840.10045.2.1":
                    return verifyHashEcDsa(hash, signature);
                case "1.2.840.113549.1.1.1":
                    return verifyHashRsa(hash, signature);
                case "1.2.840.10040.4.1":
                    return verifyHashDsa(hash, signature);
                default:
                    throw new NotSupportedException("Public key algorithm is not supported");
            }
        }

        #region IDisposable implementation
        void releaseUnmanagedResources() {
            // dispose public key handle
            phPubKey.Dispose();
            if (isCng) {
                // dispose CNG private key handle
                phPrivKey.Dispose();
            } else {
                // dispose legacy private CSP key
                legacyKey?.Dispose();
                legacyKey = null;
            }
            //TODO: Crypt32.CertFreeCertificateContext(SignerCertificate.Handle);
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
            EcDsa,
            Rsa,
            Dsa
        }
    }
}
