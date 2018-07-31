using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using CERTENROLLLib;
using PKI.Structs;
using PKI.Utils;

namespace SysadminsLV.PKI.Cryptography.X509Certificates {
    public class X509PrivateKeyBuilder : IDisposable {
        IX509PrivateKey2 keyGen = new CX509PrivateKeyClass();

        public String ProviderName {
            get => keyGen.ProviderName;
            set => keyGen.ProviderName = value;
        }
        public Oid Algorithm {
            get => new Oid(keyGen.Algorithm.Value);
            set {
                keyGen.Algorithm = new CObjectIdClass();
                keyGen.Algorithm.InitializeFromValue(value.Value);
            }
        }
        public X509KeySpecFlags KeySpec {
            get => (X509KeySpecFlags)keyGen.KeySpec;
            set => keyGen.KeySpec = (X509KeySpec)value;
        }
        public Int32 KeyLength {
            get => keyGen.Length;
            set => keyGen.Length = value;
        }
        public Boolean Exportable {
            get => keyGen.ExportPolicy == X509PrivateKeyExportFlags.XCN_NCRYPT_ALLOW_EXPORT_FLAG;
            set => keyGen.ExportPolicy = value
                ? X509PrivateKeyExportFlags.XCN_NCRYPT_ALLOW_EXPORT_FLAG
                : X509PrivateKeyExportFlags.XCN_NCRYPT_ALLOW_EXPORT_NONE;

        }
        public X509PrivateKeyProtection KeyProtection {
            get => keyGen.KeyProtection;
            set => keyGen.KeyProtection = value;
        }
        public Boolean MachineContext {
            get => keyGen.MachineContext;
            set => keyGen.MachineContext = value;
        }
        public String SecurityDescriptor {
            get => keyGen.SecurityDescriptor;
            set => keyGen.SecurityDescriptor = value;
        }

        internal Wincrypt.CRYPT_KEY_PROV_INFO GetKeyProvInfo() {
            return new Wincrypt.CRYPT_KEY_PROV_INFO {
                pwszProvName = keyGen.ProviderName,
                pwszContainerName = keyGen.ContainerName
            };
        }

        public PublicKey ExportPublicKey() {
            var key = new AsnEncodedData(Algorithm, Convert.FromBase64String(keyGen.ExportPublicKey().EncodedKey));
            var param = new AsnEncodedData(Algorithm, Convert.FromBase64String(keyGen.ExportPublicKey().EncodedParameters));
            return new PublicKey(Algorithm, param, key);
        }
        /// <summary>
        /// Creates a new asymmetric key pair based on a current configuration. If the method succeeds, all properties
        /// of this object are read-only and will throw exception when setter accessor is accessed.
        /// </summary>
        public void Create() {
            keyGen.Create();
        }
        public void Reset() {
            if (keyGen.Opened) {
                keyGen.Close();
            }

            CryptographyUtils.ReleaseCom(keyGen);
            keyGen = new CX509PrivateKeyClass();
        }

        #region IDisposable
        void releaseUnmanagedResources() {
            Reset();
        }
        /// <inheritdoc />
        public void Dispose() {
            releaseUnmanagedResources();
            GC.SuppressFinalize(this);
        }
        /// <inheritdoc />
        ~X509PrivateKeyBuilder() {
            releaseUnmanagedResources();
        }
        #endregion
    }
}
