using System;
using System.Collections.Generic;
using System.Numerics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace SysadminsLV.PKI.Cryptography {
    public class TspToken {
        readonly IList<X509Extension> _extensions = new List<X509Extension>();

        public Int32 Version { get; } = 1;
        public Oid PolicyId { get; }
        public TspMessageImprint TspMessage { get; }
        public BigInteger SerialNumber { get; }
        public Boolean Ordering { get; }
        public Byte[] Nonce { get; }
        public X509AlternativeName TsaID { get; }
        public X509ExtensionCollection Extensions {
            get {
                var retValue = new X509ExtensionCollection();
                foreach (X509Extension extension in _extensions) {
                    retValue.Add(extension);
                }
                return retValue;
            }
        }
    }
}