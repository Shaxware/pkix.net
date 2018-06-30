using System;
using System.Security.Cryptography;
using PKI.CertificateServices;
using PKI.Structs;

namespace SysadminsLV.PKI.Management.CertificateServices.Configuration {
    /// <summary>
    /// Represents CA cryptography configuration that is used when signing issued certificates and CRLs.
    /// <para>
    /// CA cryptography configuration specifies:
    /// <list type="bullet">
    ///     <item>Public key of CA signing certificate</item>
    ///     <item>Hashing algorithm to use when signing certificates and CRLs</item>
    ///     <item>The use of alternatue signature algorithm (PKCS#1 v2.1)</item>
    ///     <item>Cryptography provider used to store CA keys</item>
    ///     <item>Cryptography provider type: legacy or CNG</item>
    /// </list>
    /// </para>
    /// </summary>
    public sealed class CASigningCryptographyConfig : AdcsCAConfigurationEntry {
        const String Node = "CSP";
        readonly AdcsInternalConfigPath _prov, _provType, _cngPubAlg, _cngHalg, _halg, _altSig;

        Boolean provIsCng, altSigFormat;
        Oid2 pubKeyAlg = new Oid2(AlgorithmOids.RSA, OidGroupEnum.PublicKeyAlgorithm);
        Oid2 hashAlg = new Oid2(AlgorithmOids.SHA1, OidGroupEnum.HashAlgorithm);

        /// <inheritdoc />
        public CASigningCryptographyConfig(CertificateAuthority certificateAuthority) : base(certificateAuthority) {
            // only these supported systems do not support CNG
            if (certificateAuthority.Version == "2000" || certificateAuthority.Version == "2003") {
                SupportsCng = false;
            }
            _prov     = new AdcsInternalConfigPath { NodePath = Node, ValueName = "Provider" };
            _provType = new AdcsInternalConfigPath { NodePath = Node, ValueName = "ProviderType" };
            _halg     = new AdcsInternalConfigPath { NodePath = Node, ValueName = "HashAlgorithm" };
            RegEntries.Add(_prov);
            RegEntries.Add(_provType);
            RegEntries.Add(_halg);
            // read mandatory to all CAs entries. Then decide if we need more entries
            ReadConfig();
            if (SupportsCng) {
                _cngPubAlg = new AdcsInternalConfigPath { NodePath = Node, ValueName = "CNGPublicKeyAlgorithm" };
                _cngHalg   = new AdcsInternalConfigPath { NodePath = Node, ValueName = "CNGHashAlgorithm" };
                _altSig    = new AdcsInternalConfigPath { NodePath = Node, ValueName = "AlternateSignatureAlgorithm" };
                RegEntries.Add(_cngPubAlg);
                RegEntries.Add(_cngHalg);
                RegEntries.Add(_altSig);
                // if we need more entries, add them to the list and read all of them.
                ReadConfig();
                decodeRegValues();
            }
        }

        /// <summary>
        /// Gets the value that indicates whether CA platform supports cryptography next generation (CNG).
        /// </summary>
        /// <remarks>
        /// Windows operating systems starting with Windows Server 2008 has full support for CNG.
        /// </remarks>
        public Boolean SupportsCng { get; } = true;
        /// <summary>
        /// Gets provider name that is used by a Certification Authority installation.
        /// </summary>
        public String ProviderName {
            get => _prov.Value as String;
            set {
                if (_prov.Value as String != value) {
                    _prov.Value = value;
                    IsModified = true;
                }
            }
        }
        /// <summary>
        /// Specifies whether the CA uses CNG key storage provider or legacy cryptographic service provider.
        /// </summary>
        /// <remarks>
        /// Setter in this member has effect only when CA supports CNG. See <see cref="SupportsCng"/>
        /// for more details.
        /// </remarks>
        public Boolean ProviderIsCNG {
            get => provIsCng;
            set {
                if (SupportsCng && provIsCng != value) {
                    provIsCng = value;
                    _provType.Value = provIsCng ? 0 : 1;
                    IsModified = true;
                }
            }
        }
        /// <summary>
        /// Gets or sets the public key algorithm (such as RSA) that is used for signing purposes.
        /// </summary>
        /// <remarks>
        /// Setter in this member has effect only when CA supports CNG. See <see cref="SupportsCng"/>
        /// for more details. If <see cref="ProviderIsCNG"/> property is set to <strong>False</strong>,
        /// setter is ignored.
        /// </remarks>
        public Oid2 PublicKeyAlgorithm {
            get => pubKeyAlg;
            set {
                // does it make a sense to change this property?
                if (SupportsCng && !pubKeyAlg.Equals(value)) {
                    pubKeyAlg = value;
                    _cngPubAlg.Value = pubKeyAlg.FriendlyName;
                    IsModified = true;
                }
            }
        }
        /// <summary>
        /// Gets or sets the hashing algorithm that is used for signing purposes.
        /// </summary>
        public Oid2 HashingAlgorithm {
            get => hashAlg;
            set {
                if (!hashAlg.Equals(value)) {
                    hashAlg = value;
                    if (provIsCng) {
                        _cngHalg.Value = hashAlg.FriendlyName;
                    }
                    _halg.Value = getValueFromOid(hashAlg);
                    IsModified = true;
                }
            }
        }
        /// <summary>
        /// Gets or sets the value that indicates whether the CA server supports alternate signature algorithms
        /// (PKCS#1 v2.1)
        /// </summary>
        /// <remarks>
        /// Setter in this member has effect only when CA supports CNG. See <see cref="SupportsCng"/>
        /// for more details. If <see cref="ProviderIsCNG"/> property is set to <strong>False</strong>,
        /// setter value is ignored.
        /// </remarks>
        public Boolean AlternateSignatureAlgorithm {
            get => altSigFormat;
            set {
                if (SupportsCng && ProviderIsCNG && altSigFormat != value) {
                    altSigFormat = value;
                    _altSig.Value = Convert.ToInt32(value);
                    IsModified = true;
                }
            }
        }

        void decodeRegValues() {
            provIsCng = !Convert.ToBoolean((Int32)_provType.Value);
            altSigFormat = Convert.ToBoolean(_altSig.Value);
            pubKeyAlg = new Oid2((String)_cngPubAlg.Value);
            hashAlg = SupportsCng
                ? new Oid2((String)_cngHalg.Value)
                : getOidFromValue((Int32)_halg.Value);
        }
        static Oid2 getOidFromValue(Int32 algId) {
            switch (algId) {
                case 0x8001:
                    return new Oid2(AlgorithmOids.MD2, OidGroupEnum.HashAlgorithm);
                case 0x8003:
                    return new Oid2(AlgorithmOids.MD5, OidGroupEnum.HashAlgorithm);
                case 0x8004:
                    return new Oid2(AlgorithmOids.SHA1, OidGroupEnum.HashAlgorithm);
                case 0x8012:
                    return new Oid2(AlgorithmOids.SHA256, OidGroupEnum.HashAlgorithm);
                case 0x8013:
                    return new Oid2(AlgorithmOids.SHA384, OidGroupEnum.HashAlgorithm);
                case 0x8014:
                    return new Oid2(AlgorithmOids.SHA512, OidGroupEnum.HashAlgorithm);
                default:
                    return new Oid2(AlgorithmOids.SHA1, OidGroupEnum.HashAlgorithm);
            }
        }
        static Int32 getValueFromOid(Oid2 oid) {
            switch (oid.Value) {
                case AlgorithmOids.MD2:
                    return 0x8001;
                case AlgorithmOids.MD5:
                    return 0x8003;
                case AlgorithmOids.SHA1:
                    return 0x8004;
                case AlgorithmOids.SHA256:
                    return 0x8012;
                case AlgorithmOids.SHA384:
                    return 0x8013;
                case AlgorithmOids.SHA512:
                    return 0x8014;
                default:
                    return 0;
            }
        }
    }
}
