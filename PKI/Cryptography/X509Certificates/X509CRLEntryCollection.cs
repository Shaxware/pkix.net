using System.Collections.Generic;
using PKI.Base;
using SysadminsLV.Asn1Parser;

namespace System.Security.Cryptography.X509Certificates {
    /// <summary>
    /// Represents a collection of <see cref="X509CRLEntry"/> objects.
    /// </summary>
    public class X509CRLEntryCollection : BasicCollection<X509CRLEntry> {
        /// <summary>
        /// Initializes a new instance of the <see cref="X509CRLEntryCollection"/> class without any <see cref="X509CRLEntry"/> information.
        /// </summary>
        public X509CRLEntryCollection() { }
        /// <summary>
        /// Initializes a new instance of the <see cref="X509CRLEntryCollection"/> class from an array of
        /// <see cref="X509CRLEntry"/> objects and closes collection (makes it read-only).
        /// </summary>
        /// <param name="entries"></param>
        public X509CRLEntryCollection(IEnumerable<X509CRLEntry> entries) : base(entries) { }

        /// <summary>
        /// Closes current collection state and makes it read-only. The collection cannot be modified further.
        /// </summary>
        public void Close() { IsReadOnly = true; }
        /// <summary>
        /// Encodes a collection of <see cref="X509CRLEntry"/> objects to a ASN.1-encoded byte array.
        /// </summary>
        /// <returns>ASN.1-encoded byte array. If the collection is empty, a <strong>NULL</strong> is returned.</returns>
        public Byte[] Encode() {
            if (_list.Count == 0) { return null; }
            List<Byte> rawData = new List<Byte>();
            foreach (X509CRLEntry item in _list) {
                rawData.AddRange(item.Encode());
            }
            return Asn1Utils.Encode(rawData.ToArray(), 48);
        }
        /// <summary>
        /// Decodes a ASN.1-encoded byte array that contains revoked certificate information to a collection.
        /// </summary>
        /// <param name="rawData">ASN.1-encoded byte array.</param>
        /// <exception cref="Asn1InvalidTagException">The encoded data is not valid.</exception>
        /// <exception cref="ArgumentNullException">The <strong>rawData</strong> parameter is null reference.</exception>
        public void Decode(Byte[] rawData) {
            if (rawData == null) { throw new ArgumentNullException(nameof(rawData)); }
            Asn1Reader asn = new Asn1Reader(rawData);
            if (asn.Tag != 48) { throw new Asn1InvalidTagException(asn.Offset); }
            if (!asn.MoveNext()) { throw new Asn1InvalidTagException(asn.Offset); }
            do {
                _list.Add(new X509CRLEntry(asn.GetTagRawData()));
            } while (asn.MoveNextCurrentLevel());
        }


        /// <summary>
        /// Gets an <see cref="X509CRLEntry"/> object from the <see cref="X509CRLEntryCollection"/> object by revoked certificate's
        /// serial number.
        /// </summary>
        /// <param name="serialNumber">A string that represents a <see cref="X509CRLEntry.SerialNumber">SerialNumber</see>
        /// property.</param>
        /// <remarks>Use this property to retrieve an <see cref="X509CRLEntry"/> object from an <see cref="X509CRLEntryCollection"/>
        /// object if you know the <see cref="X509CRLEntry.SerialNumber">SerialNumber</see> value of the <see cref="X509CRLEntry"/>
        /// object. You can use the <see cref="this[string]"/> property to retrieve an <see cref="X509CRLEntry"/> object if you know
        /// its location in the collection</remarks>
        /// <returns>An <see cref="X509CRLEntry"/> object.</returns>
        public X509CRLEntry this[String serialNumber] {
            get {
                foreach (X509CRLEntry entry in _list) {
                    if (String.Equals(entry.SerialNumber, serialNumber, StringComparison.CurrentCultureIgnoreCase)) { return entry; }
                }
                return null;
            }
        }
    }
}