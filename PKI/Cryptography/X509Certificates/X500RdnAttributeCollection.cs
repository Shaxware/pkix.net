using System.Collections.Generic;
using System.Linq;
using PKI.Base;
using SysadminsLV.Asn1Parser;

namespace System.Security.Cryptography.X509Certificates {
    /// <summary>
    /// Represents a collection of <see cref="X500RdnAttribute"/> objects.
    /// </summary>
    public class X500RdnAttributeCollection : BasicCollection<X500RdnAttribute> {
        /// <summary>
        /// Encodes an array of <see cref="X500RdnAttribute"/> to an ASN.1-encoded byte array.
        /// </summary>
        /// <returns>ASN.1-encoded byte array.</returns>
        public Byte[] Encode() {
            List<Byte> rawData = new List<Byte>();
            if (_list.Count == 0) {
                return null;
            }
            foreach (X500RdnAttribute item in _list) {
                rawData.AddRange(Asn1Utils.Encode(item.RawData, 49));
            }
            return Asn1Utils.Encode(rawData.ToArray(), 48);
        }
        /// <summary>
        /// Decodes ASN.1 encoded byte array to an array of <see cref="X500RdnAttribute"/> objects.
        /// </summary>
        /// <param name="rawData">ASN.1-encoded byte array.</param>
        /// <exception cref="Asn1InvalidTagException">
        /// The data in the <strong>rawData</strong> parameter is not valid array of <see cref="X500RdnAttribute"/> objects.
        /// </exception>
        public void Decode(Byte[] rawData) {
            if (IsReadOnly) {
                throw new AccessViolationException("An object is encoded and is write-protected.");
            }
            if (rawData == null) {
                throw new ArgumentNullException(nameof(rawData));
            }
            _list.Clear();
            Asn1Reader asn = new Asn1Reader(rawData);
            if (asn.Tag != 48) {
                throw new Asn1InvalidTagException(asn.Offset);
            }
            asn.MoveNext();
            do {
                if (asn.Tag != 49) {
                    throw new Asn1InvalidTagException(asn.Offset);
                }
                _list.Add(new X500RdnAttribute(asn.GetPayload()));
            } while (asn.MoveNextCurrentLevel());
        }
        /// <summary>
        /// 
        /// </summary>
        /// <returns></returns>
        public X500DistinguishedName ToDistinguishedName() {
            if (_list.Count == 0) { throw new InvalidOperationException("Current collection contains no elements."); }
            return new X500DistinguishedName(Encode());
        }
        /// <summary>
        /// Closes current collection state and makes it read-only. The collection cannot be modified further.
        /// </summary>
        public void Close() {
            IsReadOnly = true;
        }
        /// <summary>
        /// Gets an <see cref="X500RdnAttribute"/> object from the <see cref="X500RdnAttributeCollection"/> object.
        /// </summary>
        /// <param name="oid">The location of the <see cref="X500RdnAttribute"/> object in the collection.</param>
        /// <returns></returns>
        public X500RdnAttribute this[String oid] => _list.FirstOrDefault(x => x.Oid.Value.Equals(oid, StringComparison.InvariantCultureIgnoreCase));
    }
}