using System;
using System.Collections.Generic;
using PKI.Base;
using SysadminsLV.Asn1Parser;

namespace PKI.OCSP {
    /// <summary>
    /// Represents a collection of <see cref="OCSPSingleRequest"/> objects.
    /// </summary>
    public class OCSPSingleRequestCollection : BasicCollection<OCSPSingleRequest> {

        /// <summary>
        /// Initializes a new instance of the <see cref="OCSPSingleRequestCollection"/> class without any <see cref="OCSPSingleRequest"/> information.
        /// </summary>
        public OCSPSingleRequestCollection() { }
        public OCSPSingleRequestCollection(IEnumerable<OCSPSingleRequest> collection) : base(collection) { }

        /// <summary>
        /// Gets an <see cref="OCSPSingleRequest"/> object from the <see cref="OCSPSingleRequestCollection"/> object by revoked certificate's
        /// serial number.
        /// </summary>
        /// <param name="serialNumber">A string that represents a <see cref="CertID.SerialNumber">SerialNumber</see>
        /// property.</param>
        /// <remarks>Use this property to retrieve an <see cref="OCSPSingleRequest"/> object from an <see cref="OCSPSingleRequestCollection"/>
        /// object if you know the <see cref="CertID.SerialNumber">SerialNumber</see> value of the <see cref="CertID"/>
        /// object. You can use the <see cref="this[string]"/> property to retrieve an <see cref="OCSPSingleRequest"/> object if you know
        /// its location in the collection</remarks>
        /// <returns>An <see cref="OCSPSingleRequest"/> object.</returns>
        public OCSPSingleRequest this[String serialNumber] {
            get {
                foreach (OCSPSingleRequest entry in _list) {
                    if (String.Equals(entry.CertId.SerialNumber, serialNumber, StringComparison.CurrentCultureIgnoreCase)) { return entry; }
                }
                return null;
            }
        }

        /// <summary>
        /// Encodes the collection of OCSPSingleResponse to a ASN.1-encoded byte array.
        /// </summary>
        /// <returns>ASN.1-encoded byte array.</returns>
        public Byte[] Encode() {
            if (_list.Count > 0) {
                List<Byte> rawData = new List<Byte>();
                foreach (OCSPSingleRequest item in _list) {
                    rawData.AddRange(item.Encode());
                }
                return Asn1Utils.Encode(rawData.ToArray(), 48); // requestList
            }
            return null;
        }
    }
}