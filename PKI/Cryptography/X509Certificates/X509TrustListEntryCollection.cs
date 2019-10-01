using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using SysadminsLV.Asn1Parser;

namespace SysadminsLV.PKI.Cryptography.X509Certificates {
    /// <summary>
    /// Represents a collection of <see cref="X509TrustListEntry"/> objects.
    /// </summary>
    public class X509TrustListEntryCollection : BasicCollection<X509TrustListEntry> {
        /// <inheritdoc />
        public X509TrustListEntryCollection() { }
        /// <inheritdoc />
        public X509TrustListEntryCollection(IEnumerable<X509TrustListEntry> collection) : base(collection) { }

        /// <summary>
        /// Gets an <see cref="X509TrustListEntry"/> object from the <see cref="X509TrustListEntryCollection"/> object by certificate's
        /// Thumbprint value.
        /// </summary>
        /// <param name="thumbprint">A string that represents a <see cref="X509TrustListEntry.Thumbprint">Thumbprint</see> property.</param>
        /// <remarks>
        /// Use this property to retrieve an <see cref="X509TrustListEntry"/> object from an <see cref="X509TrustListEntryCollection"/>
        /// object if you know the <see cref="X509TrustListEntry.Thumbprint">Thumbprint</see> value of the <see cref="X509TrustListEntry"/>
        /// object. You can use the <see cref="this[int]"/> property to retrieve an <see cref="X509TrustListEntry"/> object if you know
        /// its location in the collection.
        /// </remarks>
        /// <returns>An <see cref="X509TrustListEntry"/> object if found, or <strong>null</strong> if specified item was not found.</returns>
        public X509TrustListEntry this[String thumbprint] {
            get {
                return InternalList.FirstOrDefault(x => x.Thumbprint.Equals(thumbprint, StringComparison.OrdinalIgnoreCase));
            }
        }

        /// <summary>
        /// Encodes current collection to an ASN.1-encoded byte array.
        /// </summary>
        /// <returns>
        /// ASN.1-encoded byte array.
        /// </returns>
        public Byte[] Encode() {
            if (Count == 0) {
                return new Byte[0];
            }
            var rawData = new List<Byte>();
            foreach (X509TrustListEntry entry in this) {
                rawData.AddRange(entry.Encode());
            }

            return Asn1Utils.Encode(rawData.ToArray(), 48);
        }
        /// <summary>
        /// Decodes ASN.1-encoded certificate trust list collection.
        /// </summary>
        /// <param name="rawData">ASN.1-encoded byte array that represents certificate trust list collection.</param>
        /// <exception cref="ArgumentNullException">
        /// <strong>rawData</strong> parameter is null.
        /// </exception>
        public void Decode(Byte[] rawData) {
            if (rawData == null) { throw new ArgumentNullException(nameof(rawData)); }
            Clear();
            var asn = new Asn1Reader(rawData);
            if (asn.PayloadLength == 0) { return; }
            asn.MoveNext();
            do {
                var entry = new X509TrustListEntry(new AsnEncodedData(asn.GetTagRawData()));
                InternalList.Add(entry);
            } while (asn.MoveNextCurrentLevel());
        }
    }
}
