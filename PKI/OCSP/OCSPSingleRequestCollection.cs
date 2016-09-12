using System;
using System.Collections;
using System.Collections.Generic;
using SysadminsLV.Asn1Parser;

namespace PKI.OCSP {
	/// <summary>
	/// Represents a collection of <see cref="OCSPSingleRequest"/> objects.
	/// </summary>
	public class OCSPSingleRequestCollection : IEnumerable<OCSPSingleRequest> {
		readonly List<OCSPSingleRequest> _list;

		/// <summary>
		/// Initializes a new instance of the <see cref="OCSPSingleRequestCollection"/> class without any <see cref="OCSPSingleRequest"/> information.
		/// </summary>
		public OCSPSingleRequestCollection() { _list = new List<OCSPSingleRequest>(); }

		/// <summary>
		/// Gets the number of <see cref="OCSPSingleRequest"/> objects in a collection.
		/// </summary>
		public Int32 Count => _list.Count;

		/// <internalonly/>
		IEnumerator IEnumerable.GetEnumerator() {
			return new OCSPSingleRequestCollectionEnumerator(this);
		}

		/// <summary>
		/// Adds an <see cref="OCSPSingleRequest"/> object to the <see cref="OCSPSingleRequestCollection"/> object.
		/// </summary>
		/// <remarks>Use this method to add an <see cref="OCSPSingleRequest"/> object to an existing collection at the current location.</remarks>
		/// <param name="entry">The <see cref="OCSPSingleRequest"/> object to add to the collection.</param>
		/// <returns>The index of the added <see cref="OCSPSingleRequest"/> object.</returns>
		public Int32 Add(OCSPSingleRequest entry) {
			_list.Add(entry);
			return _list.Count - 1;
		}
		/// <summary>
		/// Gets an <see cref="OCSPSingleRequest"/> object from the <see cref="OCSPSingleRequestCollection"/> object.
		/// </summary>
		/// <param name="index">The location of the <see cref="OCSPSingleRequest"/> object in the collection.</param>
		/// <returns></returns>
		public OCSPSingleRequest this[Int32 index] => _list[index];

		/// <summary>
		/// Gets an <see cref="OCSPSingleRequest"/> object from the <see cref="OCSPSingleRequestCollection"/> object by revoked certificate's
		/// serial number.
		/// </summary>
		/// <param name="serialNumber">A string that represents a <see cref="CertID.SerialNumber">SerialNumber</see>
		/// property.</param>
		/// <remarks>Use this property to retrieve an <see cref="OCSPSingleRequest"/> object from an <see cref="OCSPSingleRequestCollection"/>
		/// object if you know the <see cref="CertID.SerialNumber">SerialNumber</see> value of the <see cref="CertID"/>
		/// object. You can use the <see cref="this[int]"/> property to retrieve an <see cref="OCSPSingleRequest"/> object if you know
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
		/// Returns an <see cref="OCSPSingleRequestCollectionEnumerator"/> object that can be used to navigate
		/// the <see cref="OCSPSingleRequestCollection"/> object
		/// </summary>
		/// <returns>An <see cref="OCSPSingleRequest"/> object.</returns>
		public OCSPSingleRequestCollectionEnumerator GetEnumerator() {
			return new OCSPSingleRequestCollectionEnumerator(this);
		}
		/// <summary>
		/// Copies the <see cref="OCSPSingleRequestCollection"/> object into an array.
		/// </summary>
		/// <param name="array">The array to copy the <see cref="OCSPSingleRequestCollection"/> object into.</param>
		/// <param name="index">The location where the copy operation starts.</param>
		public void CopyTo(OCSPSingleRequest[] array, Int32 index) {
			((ICollection)this).CopyTo(array, index);
		}
		/// <summary>
		/// Gets a value that indicates whether access to the <see cref="OCSPSingleRequestCollection"/> object is thread safe.
		/// </summary>
		/// <remarks>Returns <strong>False</strong> in all cases.</remarks>
		public bool IsSynchronized => false;

		/// <summary>
		/// Gets an object that can be used to synchronize access to the <see cref="OCSPSingleRequestCollection"/> object.
		/// </summary>
		/// <remarks><see cref="OCSPSingleRequestCollection"/> is not thread safe. Derived classes can provide their own
		/// synchronized version of the <see cref="OCSPSingleRequestCollection"/> class using this property. The synchronizing
		/// code must perform operations on the <strong>SyncRoot</strong> property of the <see cref="OCSPSingleRequestCollection"/>
		/// object, not directly on the object itself. This ensures proper operation of collections that are derived from
		/// other objects. Specifically, it maintains proper synchronization with other threads that might simultaneously
		/// be modifying the <see cref="OCSPSingleRequestCollection"/> object.</remarks>
		public Object SyncRoot => this;

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

		IEnumerator<OCSPSingleRequest> IEnumerable<OCSPSingleRequest>.GetEnumerator() {
			throw new NotImplementedException();
		}
	}
	/// <summary>
	/// Provides the ability to navigate through an <see cref="OCSPSingleRequestCollection"/> object.
	/// </summary>
	public class OCSPSingleRequestCollectionEnumerator : IEnumerator {
		readonly OCSPSingleRequestCollection _entries;
		Int32 m_current;

		internal OCSPSingleRequestCollectionEnumerator(OCSPSingleRequestCollection entries) {
			_entries = entries;
			m_current = -1;
		}
		/// <summary>
		/// Gets the current <see cref="OCSPSingleRequest"/> object in an <see cref="OCSPSingleRequestCollection"/> object.
		/// </summary>
		/// <remarks><p>After an enumerator is created, the <see cref="MoveNext"/> method must be called to advance the
		/// enumerator to the first element of the collection before reading the value of the <strong>Current</strong> property;
		/// otherwise, <strong>Current</strong> returns a null reference (Nothing in Visual Basic) or throws an exception.</p>
		/// <p><strong>Current</strong> also returns a null reference (Nothing in Visual Basic) or throws an exception if the last
		/// call to <see cref="MoveNext"/> returns false, which indicates that the end of the collection has been reached.</p>
		/// <p><strong>Current</strong> does not move the position of the enumerator, and consecutive calls to <strong>Current</strong>
		/// return the same object, until <see cref="MoveNext"/> is called.</p></remarks>
		public OCSPSingleRequest Current => _entries[m_current];

		/// <internalonly/>
		Object IEnumerator.Current => _entries[m_current];

		/// <summary>
		/// Advances to the next <see cref="OCSPSingleRequest"/> object in an <see cref="OCSPSingleRequestCollection"/> object
		/// </summary>
		/// <remarks><p>After an enumerator is created, it is positioned before the first element of the collection,
		/// and the first call to the <strong>MoveNext</strong> method moves the enumerator over the first element of the collection.
		/// Subsequent calls to <strong>MoveNext</strong> advances the enumerator past subsequent items in the collection.</p>
		/// <p>After the end of the collection is passed, calls to <strong>MoveNext</strong> return <strong>False</strong>.</p>
		/// <p>An enumerator is valid as long as the collection remains unchanged. If changes are made to the collection,
		/// such as adding, modifying, or deleting elements, the enumerator becomes invalid and the next call to MoveNext
		/// throws an <see cref="InvalidOperationException"/>.</p>
		/// </remarks>
		/// <returns><strong>True</strong>, if the enumerator was successfully advanced to the next element; <strong>False</strong>,
		/// if the enumerator has passed the end of the collection.</returns>
		public bool MoveNext() {
			if (m_current == _entries.Count - 1) { return false; }
			m_current++;
			return true;
		}
		/// <summary>
		/// Sets an enumerator to its initial position.
		/// </summary>
		/// <remarks>The initial position of an enumerator is before the first element in the <see cref="OCSPSingleRequestCollection"/> object.
		/// An enumerator remains valid as long as the collection remains unchanged. If changes are made to the collection, such
		/// as adding, modifying, or deleting elements, the enumerator becomes invalid and the next call to the <strong>Reset</strong>
		/// method throws an <see cref="InvalidOperationException"/>.</remarks>
		public void Reset() { m_current = -1; }
	}
}