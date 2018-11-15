using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using SysadminsLV.Asn1Parser;

namespace SysadminsLV.PKI.Helpers.CLRExtensions {
    /// <summary>
    /// Contains extension methods for <see cref="X509ExtensionCollection"/> class.
    /// </summary>
    public static class X509ExtensionCollectionExtensions {
        /// <summary>
        /// Encodes existing collection of <see cref="X509Extension"/> objects to ASN.1-encoded byte array.
        /// </summary>
        /// <param name="extensions">Extension collection to encode.</param>
        /// <exception cref="ArgumentNullException"><strong>extensions</strong> parameter is null.</exception>
        /// <returns>ASN.1-encoded byte array.</returns>
        public static Byte[] Encode(this X509ExtensionCollection extensions) {
            if (extensions == null) { throw new ArgumentNullException(nameof(extensions)); }

            List<Byte> rawData = new List<Byte>();
            foreach (X509Extension e in extensions) {
                rawData.AddRange(e.Encode());
            }
            return Asn1Utils.Encode(rawData.ToArray(), 48);
        }
        /// <summary>
        /// Decodes ASN.1-encoded byte array that represents a collection of <see cref="X509Extension"/> objects.
        /// </summary>
        /// <param name="extensions">Destination collection where decoded extensions will be added.</param>
        /// <param name="rawData">ASN.1-encoded byte array that represents extension collection.</param>
        /// <exception cref="Asn1InvalidTagException">Decoder encountered an unexpected ASN.1 type identifier.</exception>
        /// <exception cref="ArgumentNullException">
        /// <strong>extensions</strong> and/or <strong>rawData</strong> parameter is null.
        /// </exception>
        /// <remarks>If current collection contains items, decoded items will be appended to existing items.</remarks>
        public static void Decode(this X509ExtensionCollection extensions, Byte[] rawData) {
            if (extensions == null) { throw new ArgumentNullException(nameof(extensions)); }
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
        /// <summary>
        /// Adds a collection of <see cref="X509Extension"/> objects to existing collection.
        /// </summary>
        /// <param name="extensions">Destination collection where items will be added.</param>
        /// <param name="itemsToAdd">A source collection of items to add to destination.</param>
        /// <exception cref="ArgumentNullException">
        /// <strong>extensions</strong> and/or <strong>itemsToAdd</strong> is null.
        /// </exception>
        public static void AddRange(this X509ExtensionCollection extensions, IEnumerable<X509Extension> itemsToAdd) {
            if (extensions == null) { throw new ArgumentNullException(nameof(extensions)); }
            if (itemsToAdd == null) { throw new ArgumentNullException(nameof(itemsToAdd)); }
            foreach (X509Extension e in itemsToAdd) {
                extensions.Add(e);
            }
        }
        internal static void Remove(this X509ExtensionCollection exts, String oid) {
            if (exts == null) { return; }
            for (Int32 i = 0; i < exts.Count; i++) {
                if (exts[i].Oid.Value == oid) {
                    exts.RemoveAt(i);
                    return;
                }
            }
        }
        internal static void RemoveAt(this X509ExtensionCollection exts, Int32 index) {
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
