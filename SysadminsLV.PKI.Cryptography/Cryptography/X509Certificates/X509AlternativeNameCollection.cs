using System;
using System.Collections.Generic;
using SysadminsLV.Asn1Parser;
using SysadminsLV.PKI.Helpers;

namespace SysadminsLV.PKI.Cryptography.X509Certificates {
    /// <summary>
    /// Represents a collection of <see cref="X509AlternativeName"/> objects.
    /// </summary>
    public class X509AlternativeNameCollection : BasicCollection<X509AlternativeName> {
        /// <summary>
        /// Encodes an array of <see cref="X509AlternativeName"/> to an ASN.1-encoded byte array.
        /// </summary>
        /// <returns>ASN.1-encoded byte array.</returns>
        public Byte[] Encode() {
            List<Byte> rawData = new List<Byte>();
            if (InternalList.Count == 0) { return null; }
            foreach (X509AlternativeName item in InternalList) {
                rawData.AddRange(item.RawData);
            }
            return Asn1Utils.Encode(rawData.ToArray(), 48);
        }
        /// <summary>
        /// Decodes ASN.1 encoded byte array to an array of <see cref="X509AlternativeName"/> objects.
        /// </summary>
        /// <param name="rawData">ASN.1-encoded byte array.</param>
        /// <exception cref="Asn1InvalidTagException">
        /// The data in the <strong>rawData</strong> parameter is not valid array of <see cref="X509AlternativeName"/> objects.
        /// </exception>
        public void Decode(Byte[] rawData) {
            if (IsReadOnly) { throw new AccessViolationException(E_COLLECTIONCLOSED); }
            if (rawData == null) { throw new ArgumentNullException(nameof(rawData)); }
            InternalList.Clear();
            Asn1Reader asn = new Asn1Reader(rawData);
            if (asn.Tag != 48) { throw new Asn1InvalidTagException(); }
            asn.MoveNext();
            do {
                InternalList.Add(new X509AlternativeName(asn.GetTagRawData()));
            } while (asn.MoveNextCurrentLevel());
        }
        /// <summary>
        /// Closes current collection state and makes it read-only. The collection cannot be modified further.
        /// </summary>
        public void Close() {
            IsReadOnly = true;
        }
    }
}