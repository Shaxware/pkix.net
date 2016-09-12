using PKI.Base;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using PKI.Utils;
using SysadminsLV.Asn1Parser;

namespace System.Security.Cryptography.X509Certificates {
	/// <summary>
	/// Represents a collection of <see cref="X509CRLEntry"/> objects.
	/// </summary>
	public class X509CRLEntryCollection : ICryptCollection<X509CRLEntry> {
		readonly List<X509CRLEntry> _list;

		/// <summary>
		/// Initializes a new instance of the <see cref="X509CRLEntryCollection"/> class without any <see cref="X509CRLEntry"/> information.
		/// </summary>
		public X509CRLEntryCollection() { _list = new List<X509CRLEntry>(); }
		/// <summary>
		/// Initializes a new instance of the <see cref="X509CRLEntryCollection"/> class from an array of
		/// <see cref="X509CRLEntry"/> objects and closes collection (makes it read-only).
		/// </summary>
		/// <param name="entries"></param>
		public X509CRLEntryCollection(IEnumerable<X509CRLEntry> entries) {
			_list = new List<X509CRLEntry>(entries);
			IsReadOnly = true;
		}

		/// <summary>
		/// Gets the number of <see cref="X509CRLEntry"/> objects in a collection.
		/// </summary>
		public Int32 Count => _list.Count;

		/// <summary>
		/// Indicates whether the collection is read-only.
		/// </summary>
		public Boolean IsReadOnly { get; private set; }
		/// <summary>
		/// Gets a value that indicates whether access to the <see cref="X509CRLEntryCollection"/> object is thread safe.
		/// </summary>
		/// <remarks>Returns <strong>False</strong> in all cases.</remarks>
		public Boolean IsSynchronized => false;

		/// <summary>
		/// Gets an object that can be used to synchronize access to the <see cref="X509CRLEntryCollection"/> object.
		/// </summary>
		/// <remarks><see cref="X509CRLEntryCollection"/> is not thread safe. Derived classes can provide their own
		/// synchronized version of the <see cref="X509CRLEntryCollection"/> class using this property. The synchronizing
		/// code must perform operations on the <strong>SyncRoot</strong> property of the <see cref="X509CRLEntryCollection"/>
		/// object, not directly on the object itself. This ensures proper operation of collections that are derived from
		/// other objects. Specifically, it maintains proper synchronization with other threads that might simultaneously
		/// be modifying the <see cref="X509CRLEntryCollection"/> object.</remarks>
		public Object SyncRoot => this;

		IEnumerator IEnumerable.GetEnumerator() {
			return new X509CRLEntryCollectionEnumerator(this);
		}
		void ICollection.CopyTo(Array array, Int32 index) {
			if (array == null) { throw new ArgumentNullException(nameof(array)); }
			if (array.Rank != 1) { throw new ArgumentException("Multidimensional arrays are not supported."); }
			if (index < 0 || index >= array.Length) { throw new ArgumentOutOfRangeException(nameof(index)); }
			if (index + Count > array.Length) { throw new ArgumentException("Index is out of range."); }
			for (Int32 i = 0; i < Count; i++) {
				array.SetValue(this[i], index);
				index++;
			}
		}

		/// <summary>
		/// Adds an <see cref="X509CRLEntry"/> object to the <see cref="X509CRLEntryCollection"/> object.
		/// </summary>
		/// <remarks>Use this method to add an <see cref="X509CRLEntry"/> object to an existing collection at the current location.</remarks>
		/// <param name="entry">The <see cref="X509CRLEntry"/> object to add to the collection.</param>
		/// <exception cref="AccessViolationException">The collection is closed and is read-only.</exception>
		/// <returns>The index of the added <see cref="X509CRLEntry"/> object.</returns>
		public Int32 Add(X509CRLEntry entry) {
			if (IsReadOnly) { throw new AccessViolationException(Error.E_COLLECTIONCLOSED); }
			_list.Add(entry);
			return _list.Count - 1;
		}
		/// <summary>
		/// Adds an <see cref="X509CRLEntry"/> object to the <see cref="X509CRLEntryCollection"/> object.
		/// </summary>
		/// <remarks>Use this method to add an array of <see cref="X509CRLEntry"/> objects to an existing collection at the current location.</remarks>
		/// <param name="entries">An array of <see cref="X509CRLEntry"/> objects to add.</param>
		/// <exception cref="AccessViolationException">The collection is closed and is read-only.</exception>
		public void AddRange(IEnumerable<X509CRLEntry> entries) {
			if (IsReadOnly) { throw new AccessViolationException(Error.E_COLLECTIONCLOSED); }
			_list.AddRange(entries);
		}
		/// <summary>
		/// Removes an <see cref="X509CRLEntry"/> object from the <see cref="X509CRLEntryCollection"/> object.
		/// </summary>
		/// <param name="index">An entry index to remove.</param>
		/// <exception cref="AccessViolationException">The collection is closed and is read-only.</exception>
		public void Remove(Int32 index) {
			if (IsReadOnly) { throw new AccessViolationException(Error.E_COLLECTIONCLOSED); }
			_list.RemoveAt(index);
		}
		/// <summary>
		/// Closes current collection state and makes it read-only. The collection cannot be modified further.
		/// </summary>
		public void Close() { IsReadOnly = true; }
		/// <summary>
		/// Resets an array of <see cref="X509CRLEntry"/> objects and enables write-mode for this object.
		/// </summary>
		public void Reset() {
			_list.Clear();
			IsReadOnly = false;
		}
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
		/// <exception cref="InvalidDataException">The encoded data is not valid.</exception>
		/// <exception cref="ArgumentNullException">The <strong>rawData</strong> parameter is null reference.</exception>
		public void Decode(Byte[] rawData) {
			if (rawData == null) { throw new ArgumentNullException(nameof(rawData)); }
			Asn1Reader asn = new Asn1Reader(rawData);
			if (asn.Tag != 48) { throw new InvalidDataException(); }
			if (!asn.MoveNext()) { throw new InvalidDataException(); }
			do {
				_list.Add(new X509CRLEntry(asn.GetTagRawData()));
			} while (asn.MoveNextCurrentLevel());
		}
		/// <summary>
		/// Gets an <see cref="X509CRLEntry"/> object from the <see cref="X509CRLEntryCollection"/> object.
		/// </summary>
		/// <param name="index">The location of the <see cref="X509CRLEntry"/> object in the collection.</param>
		/// <returns></returns>
		public X509CRLEntry this[Int32 index] => _list[index];

		/// <summary>
		/// Gets an <see cref="X509CRLEntry"/> object from the <see cref="X509CRLEntryCollection"/> object by revoked certificate's
		/// serial number.
		/// </summary>
		/// <param name="serialNumber">A string that represents a <see cref="X509CRLEntry.SerialNumber">SerialNumber</see>
		/// property.</param>
		/// <remarks>Use this property to retrieve an <see cref="X509CRLEntry"/> object from an <see cref="X509CRLEntryCollection"/>
		/// object if you know the <see cref="X509CRLEntry.SerialNumber">SerialNumber</see> value of the <see cref="X509CRLEntry"/>
		/// object. You can use the <see cref="this[int]"/> property to retrieve an <see cref="X509CRLEntry"/> object if you know
		/// its location in the collection</remarks>
		/// <returns>An <see cref="X509CRLEntry"/> object.</returns>
		public X509CRLEntry this[String serialNumber] {
			get {
				foreach (X509CRLEntry entry in _list) {
					if (entry.SerialNumber.ToLower() == serialNumber.ToLower()) { return entry; }
				}
				return null;
			}
		}
		/// <summary>
		/// Returns an <see cref="X509CRLEntryCollectionEnumerator"/> object that can be used to navigate
		/// the <see cref="X509CRLEntryCollection"/> object
		/// </summary>
		/// <returns>An <see cref="X509CRLEntry"/> object.</returns>
		public X509CRLEntryCollectionEnumerator GetEnumerator() {
			return new X509CRLEntryCollectionEnumerator(this);
		}
		/// <summary>
		/// Copies the <see cref="X509CRLEntryCollection"/> object into an array.
		/// </summary>
		/// <param name="array">The array to copy the <see cref="X509CRLEntryCollection"/> object into.</param>
		/// <param name="index">The location where the copy operation starts.</param>
		public void CopyTo(X509CRLEntry[] array, Int32 index) {
			((ICollection)this).CopyTo(array, index);
		}
		/// <summary>
		/// Converts a current collection instance to a regular object array.
		/// </summary>
		/// <returns>Collection object array.</returns>
		public X509CRLEntry[] ToArray() {
			return _list.ToArray();
		}
	}
	/// <summary>
	/// Provides the ability to navigate through an <see cref="X509CRLEntryCollection"/> object.
	/// </summary>
	public class X509CRLEntryCollectionEnumerator : IEnumerator {
		readonly X509CRLEntryCollection _entries;
		Int32 m_current;

		internal X509CRLEntryCollectionEnumerator(X509CRLEntryCollection entries) {
			_entries = entries;
			m_current = -1;
		}

		/// <summary>
		/// Gets the current <see cref="X509CRLEntry"/> object in an <see cref="X509CRLEntryCollection"/> object.
		/// </summary>
		/// <remarks><p>After an enumerator is created, the <see cref="MoveNext"/> method must be called to advance the
		/// enumerator to the first element of the collection before reading the value of the <strong>Current</strong> property;
		/// otherwise, <strong>Current</strong> returns a null reference (Nothing in Visual Basic) or throws an exception.</p>
		/// <p><strong>Current</strong> also returns a null reference (Nothing in Visual Basic) or throws an exception if the last
		/// call to <see cref="MoveNext"/> returns false, which indicates that the end of the collection has been reached.</p>
		/// <p><strong>Current</strong> does not move the position of the enumerator, and consecutive calls to <strong>Current</strong>
		/// return the same object, until <see cref="MoveNext"/> is called.</p></remarks>
		public X509CRLEntry Current => _entries[m_current];

		Object IEnumerator.Current => _entries[m_current];

		/// <summary>
		/// Advances to the next <see cref="X509CRLEntry"/> object in an <see cref="X509CRLEntryCollection"/> object
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
		/// <remarks>The initial position of an enumerator is before the first element in the <see cref="X509CRLEntryCollection"/> object.
		/// An enumerator remains valid as long as the collection remains unchanged. If changes are made to the collection, such
		/// as adding, modifying, or deleting elements, the enumerator becomes invalid and the next call to the <strong>Reset</strong>
		/// method throws an <see cref="InvalidOperationException"/>.</remarks>
		public void Reset() { m_current = -1; }
	}
}