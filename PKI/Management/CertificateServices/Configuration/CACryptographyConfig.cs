using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using PKI.CertificateServices;
using PKI.Structs;
using SysadminsLV.PKI.Management.CertificateServices.Configuration;

namespace PKI.Management.CertificateServices.Configuration {
    public sealed class CACryptographyConfig : AdcsCAConfigurationEntry {
        readonly AdcsInternalConfigPath _prov, _provType, _cngPubAlg, _cngHalg, _halg, _altSig;
        const String Node = "CSP";



        /// <inheritdoc />
        public CACryptographyConfig(CertificateAuthority certificateAuthority) : base(certificateAuthority) {
            _prov      = new AdcsInternalConfigPath { NodePath = Node, ValueName = "Provider" };
            _provType  = new AdcsInternalConfigPath { NodePath = Node, ValueName = "ProviderType" };
            _cngPubAlg = new AdcsInternalConfigPath { NodePath = Node, ValueName = "CNGPublicKeyAlgorithm" };
            _cngHalg   = new AdcsInternalConfigPath { NodePath = Node, ValueName = "CNGHashAlgorithm" };
            _halg      = new AdcsInternalConfigPath { NodePath = Node, ValueName = "HashAlgorithm" };
            _altSig    = new AdcsInternalConfigPath { NodePath = Node, ValueName = "AlternateSignatureAlgorithm" };
            ReadConfig();
        }
        public Oid PublicKeyAlgorithm
        {
            get => new Oid(_cngPubAlg.Value.ToString());
        }
        public Boolean AlternateSignatureAlgorithm
        {
            get => Convert.ToBoolean(_altSig.Value);
            set
            {
                _altSig.Value = Convert.ToInt32(value);
                IsModified = true;
            }
        }

        static Oid getOidFromValue(Int32 algId) {
            switch (algId) {
                case 0x8001:
                    return new Oid(AlgorithmOids.MD2); // md2
                case 0x8003:
                    return new Oid(AlgorithmOids.MD5); // md5
                case 0x8004:
                    return new Oid(AlgorithmOids.SHA1); // sha1
                case 0x8012:
                    return new Oid(AlgorithmOids.SHA256); // sha256
                case 0x8013:
                    return new Oid(AlgorithmOids.SHA384); // sha384
                case 0x8014:
                    return new Oid(AlgorithmOids.SHA512); // sha512
                default:
                    return null;
            }
        }
        static Int32 getValueFromOid(Oid oid) {
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
        static Boolean validateHashAlgorithm(String value) {
            return new List<String> {
                AlgorithmOids.MD2,
                AlgorithmOids.MD5,
                AlgorithmOids.SHA1,
                AlgorithmOids.SHA256,
                AlgorithmOids.SHA384,
                AlgorithmOids.SHA512
            }.Contains(value);
        }
    }
}
