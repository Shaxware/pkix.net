using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using SysadminsLV.Asn1Parser;

namespace PKI.Cryptography.Pkcs {
    public sealed class Pkcs8Key : Pkcs1Key {
        public Pkcs8Key(Byte[] rawData) : base(rawData, true) {
            
        }
        
        public Oid KeyAlgorithm { get; private set; }

        public override string Format() {
            return "-----BEGIN PRIVATE KEY-----" +
                Environment.NewLine +
                AsnFormatter.BinaryToString(RawData, EncodingType.Base64) +
                "-----End PRIVATE KEY-----";
        }
    }
}
