using System.Collections;
using System.Collections.Generic;
using System.IO;
using PKI.Base;
using SysadminsLV.Asn1Parser;

namespace System.Security.Cryptography.X509Certificates {
	/// <summary>
	/// Represents a collection of <see cref="X509PolicyQualifier"/> objects.
	/// </summary>
	public class X509PolicyQualifierCollection : ICryptCollection<X509PolicyQualifier> {
		readonly List<X509PolicyQualifier> _list;

		/// <summary>
		/// Initializes a new instance of the <see cref="X509PolicyQualifierCollection"/> class without any <see cref="X509PolicyQualifier"/> information.
		/// </summary>
		public X509PolicyQualifierCollection() { _list = new List<X509PolicyQualifier>(); }

		/// <summary>
		/// Gets the number of <see cref="X509PolicyQualifier"/> objects in a collection.
		/// </summary>
		public Int32 Count {
			get { return _list.Count; }
		}
		/// <summary>
		/// Indicates whether the collection is read-only.
		/// </summary>
		public Boolean IsReadOnly { get; private set; }
		/// <summary>
		/// Gets a value that indicates whether access to the <see cref="X509PolicyQualifierCollection"/> object is thread safe.
		/// </summary>
		/// <remarks>Returns <strong>False</strong> in all cases.</remarks>
		public Boolean IsSynchronized {
			get { return false; }
		}
		/// <summary>
		/// Gets an object that can be used to synchronize access to the <see cref="X509PolicyQualifierCollection"/> object.
		/// </summary>
		/// <remarks><see cref="X509PolicyQualifierCollection"/> is not thread safe. Derived classes can provide their own
		/// synchronized version of the <see cref="X509PolicyQualifierCollection"/> class using this property. The synchronizing
		/// code must perform operations on the <strong>SyncRoot</strong> property of the <see cref="X509PolicyQualifierCollection"/>
		/// object, not directly on the object itself. This ensures proper operation of collections that are derived from
		/// other objects. Specifically, it maintains proper synchronization with other threads that might simultaneously
		/// be modifying the <see cref="X509PolicyQualifierCollection"/> object.</remarks>
		public Object SyncRoot {
			get { return this; }
		}

		IEnumerator IEnumerable.GetEnumerator() {
			return new X509PolicyQualifierCollectionEnumerator(this);
		}
		void ICollection.CopyTo(Array array, Int32 index) {
			if (array == null) { throw new ArgumentNullException("array"); }
			if (array.Rank != 1) { throw new ArgumentException("Multidimensional arrays are not supported."); }
			if (index < 0 || index >= array.Length) { throw new ArgumentOutOfRangeException("index"); }
			if (index + Count > array.Length) { throw new ArgumentException("Index is out of range."); }
			for (Int32 i = 0; i < Count; i++) {
				array.SetValue(this[i], index);
				index++;
			}
		}

		/// <summary>
		/// Closes current collection state and makes it read-only. The collection cannot be modified further.
		/// </summary>
		public void Close() { IsReadOnly = true; }
		/// <summary>
		/// Adds an <see cref="X509PolicyQualifier"/> object to the <see cref="X509PolicyQualifierCollection"/> object.
		/// </summary>
		/// <remarks>Use this method to add an <see cref="X509PolicyQualifier"/> object to an existing collection at the current location.</remarks>
		/// <param name="entry">The <see cref="X509PolicyQualifier"/> object to add to the collection.</param>
		/// <exception cref="AccessViolationException">An array is encoded and is read-only.</exception>
		/// <returns>The index of the added <see cref="X509PolicyQualifier"/> object.</returns>
		public Int32 Add(X509PolicyQualifier entry) {
			if (IsReadOnly) { throw new AccessViolationException("An object is encoded and is write-protected."); }
			_list.Add(entry);
			return _list.Count - 1;
		}
		/// <summary>
		/// Encodes an array of <see cref="X509PolicyQualifier"/> to an ASN.1-encoded byte array.
		/// </summary>
		/// <returns>ASN.1-encoded byte array.</returns>
		public Byte[] Encode() {
			if (_list.Count == 0) { return null; }
			Int32 index = 1;
			List<Byte> rawData = new List<Byte>();
			foreach (X509PolicyQualifier qualifier in _list) {
				if (qualifier.Type == X509PolicyQualifierType.UserNotice) {
					qualifier.NoticeNumber = index;
					index++;
				}
				rawData.AddRange(qualifier.Encode());
			}
			return Asn1Utils.Encode(rawData.ToArray(), 48);
		}
		/// <summary>
		/// Decodes ASN.1 encoded byte array to an array of <see cref="X509PolicyQualifier"/> objects.
		/// </summary>
		/// <param name="rawData">ASN.1-encoded byte array.</param>
		/// <exception cref="InvalidDataException">
		/// The data in the <strong>rawData</strong> parameter is not valid array of <see cref="X509PolicyQualifier"/> objects.
		/// </exception>
		public void Decode(Byte[] rawData) {
			_list.Clear();
			Asn1Reader asn = new Asn1Reader(rawData);
			if (asn.Tag != 48) { throw new InvalidDataException("The data is invalid."); }
			asn.MoveNext();
			do {
				_list.Add(new X509PolicyQualifier(asn.GetTagRawData()));
			} while (asn.MoveNextCurrentLevel());
		}
		/// <summary>
		/// Removes an <see cref="X509PolicyQualifier"/> object from the <see cref="X509PolicyQualifierCollection"/> object.
		/// </summary>
		/// <param name="index">An entry index to remove.</param>
		/// <exception cref="AccessViolationException">An array is encoded and is read-only.</exception>
		public void Remove(Int32 index) {
			if (IsReadOnly) { throw new AccessViolationException("An object is encoded and is write-protected."); }
			_list.RemoveAt(index);
		}
		/// <summary>
		/// Resets an array of <see cref="X509PolicyQualifier"/> objects and enables write-mode for this object.
		/// </summary>
		public void Reset() {
			_list.Clear();
			IsReadOnly = false;
		}
		/// <summary>
		/// Gets an <see cref="X509PolicyQualifier"/> object from the <see cref="X509PolicyQualifierCollection"/> object.
		/// </summary>
		/// <param name="index">The location of the <see cref="X509PolicyQualifier"/> object in the collection.</param>
		/// <returns></returns>
		public X509PolicyQualifier this[Int32 index] {
			get { return _list[index]; }
		}
		/// <summary>
		/// Returns an <see cref="X509PolicyQualifierCollectionEnumerator"/> object that can be used to navigate
		/// the <see cref="X509PolicyQualifierCollection"/> object
		/// </summary>
		/// <returns>An <see cref="X509PolicyQualifier"/> object.</returns>
		public X509PolicyQualifierCollectionEnumerator GetEnumerator() {
			return new X509PolicyQualifierCollectionEnumerator(this);
		}
		/// <summary>
		/// Copies the <see cref="X509PolicyQualifierCollection"/> object into an array.
		/// </summary>
		/// <param name="array">The array to copy the <see cref="X509PolicyQualifierCollection"/> object into.</param>
		/// <param name="index">The location where the copy operation starts.</param>
		public void CopyTo(X509PolicyQualifier[] array, Int32 index) {
			((ICollection)this).CopyTo(array, index);
		}
	}
	/// <summary>
	/// Provides the ability to navigate through an <see cref="X509PolicyQualifierCollection"/> object.
	/// </summary>
	public class X509PolicyQualifierCollectionEnumerator : IEnumerator {
		readonly X509PolicyQualifierCollection _entries;
		Int32 m_current;

		internal X509PolicyQualifierCollectionEnumerator(X509PolicyQualifierCollection entries) {
			_entries = entries;
			m_current = -1;
		}
		/// <summary>
		/// Gets the current <see cref="X509PolicyQualifier"/> object in an <see cref="X509PolicyQualifierCollection"/> object.
		/// </summary>
		/// <remarks><p>After an enumerator is created, the <see cref="MoveNext"/> method must be called to advance the
		/// enumerator to the first element of the collection before reading the value of the <strong>Current</strong> property;
		/// otherwise, <strong>Current</strong> returns a null reference (Nothing in Visual Basic) or throws an exception.</p>
		/// <p><strong>Current</strong> also returns a null reference (Nothing in Visual Basic) or throws an exception if the last
		/// call to <see cref="MoveNext"/> returns false, which indicates that the end of the collection has been reached.</p>
		/// <p><strong>Current</strong> does not move the position of the enumerator, and consecutive calls to <strong>Current</strong>
		/// return the same object, until <see cref="MoveNext"/> is called.</p></remarks>
		public X509PolicyQualifier Current {
			get { return _entries[m_current]; }
		}
		
		/// <internalonly/>
		Object IEnumerator.Current {
			get { return _entries[m_current]; }
		}
		/// <summary>
		/// Advances to the next <see cref="X509PolicyQualifier"/> object in an <see cref="X509PolicyQualifierCollection"/> object
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
			if (m_current == (_entries.Count - 1)) { return false; }
			m_current++;
			return true;
		}
		/// <summary>
		/// Sets an enumerator to its initial position.
		/// </summary>
		/// <remarks>The initial position of an enumerator is before the first element in the <see cref="X509PolicyQualifierCollection"/> object.
		/// An enumerator remains valid as long as the collection remains unchanged. If changes are made to the collection, such
		/// as adding, modifying, or deleting elements, the enumerator becomes invalid and the next call to the <strong>Reset</strong>
		/// method throws an <see cref="InvalidOperationException"/>.</remarks>
		public void Reset() { m_current = -1; }
	}
}