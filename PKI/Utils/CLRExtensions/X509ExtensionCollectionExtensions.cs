using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using SysadminsLV.Asn1Parser;

namespace PKI.Utils.CLRExtensions {
    static class X509ExtensionCollectionExtensions {
        public static Byte[] Encode(this X509ExtensionCollection extensions) {
            if (extensions == null) { throw new ArgumentNullException(nameof(extensions)); }

            List<Byte> rawData = new List<Byte>();
            foreach (X509Extension e in extensions) {
                rawData.AddRange(e.Encode());
            }
            return Asn1Utils.Encode(rawData.ToArray(), 48);
        }
        public static void Decode(this X509ExtensionCollection extensions, Byte[] rawData) {
            if (rawData == null) { throw new ArgumentNullException(nameof(rawData)); }

            Asn1Reader asn = new Asn1Reader(rawData);
            if (asn.Tag != 48) { throw new Asn1InvalidTagException(); }
            if (!asn.MoveNext() || asn.NextOffset == 0) {
                return;
            }

            do {
                extensions.Add(X509ExtensionExtensions.Decode(asn.GetTagRawData()));
            } while (asn.MoveNextCurrentLevel());
        }

        public static void AddRange(this X509ExtensionCollection exts, IEnumerable<X509Extension> extensions) {
            if (exts == null) { return; }
            foreach (X509Extension e in extensions) {
                exts.Add(e);
            }
        }
        public static void Remove(this X509ExtensionCollection exts, String oid) {
            if (exts == null) { return; }
            for (Int32 i = 0; i < exts.Count; i++) {
                if (exts[i].Oid.Value == oid) {
                    exts.RemoveAt(i);
                    return;
                }
            }
        }
        public static void RemoveAt(this X509ExtensionCollection exts, Int32 index) {
            if (exts == null || index >= exts.Count) { return; }
            List<X509Extension> e = new List<X509Extension>(exts.Cast<X509Extension>());
            e.RemoveAt(index);
            exts = new X509ExtensionCollection();
            foreach (X509Extension ext in e) {
                exts.Add(ext);
            }
        }
    }
}
