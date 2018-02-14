using PKI.Base;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using SysadminsLV.Asn1Parser;

namespace System.Security.Cryptography.X509Certificates {
	/// <summary>
	/// Represents a collection of <see cref="X500RdnAttribute"/> objects.
	/// </summary>
	public class X500RdnAttributeCollection : ICryptCollection<X500RdnAttribute>, IEnumerable<X500RdnAttribute> {
		readonly List<X500RdnAttribute> _list;

		/// <summary>
		/// Initializes a new instance of the <see cref="X500RdnAttributeCollection"/> class without any <see cref="X500RdnAttribute"/> information.
		/// </summary>
		public X500RdnAttributeCollection() {
			_list = new List<X500RdnAttribute>();
		}

		/// <summary>
		/// Gets the number of <see cref="X500RdnAttribute"/> objects in a collection.
		/// </summary>
		public Int32 Count => _list.Count;
		/// <summary>
		/// Indicates whether the collection is read-only.
		/// </summary>
		public Boolean IsReadOnly { get; private set; }
		/// <summary>
		/// Gets a value that indicates whether access to the <see cref="X500RdnAttributeCollection"/> object is thread safe.
		/// </summary>
		/// <remarks>Returns <strong>False</strong> in all cases.</remarks>
		public Boolean IsSynchronized => false;

		/// <summary>
		/// Gets an object that can be used to synchronize access to the <see cref="X500RdnAttributeCollection"/> object.
		/// </summary>
		/// <remarks><see cref="X500RdnAttributeCollection"/> is not thread safe. Derived classes can provide their own
		/// synchronized version of the <see cref="X500RdnAttributeCollection"/> class using this property. The synchronizing
		/// code must perform operations on the <strong>SyncRoot</strong> property of the <see cref="X500RdnAttributeCollection"/>
		/// object, not directly on the object itself. This ensures proper operation of collections that are derived from
		/// other objects. Specifically, it maintains proper synchronization with other threads that might simultaneously
		/// be modifying the <see cref="X500RdnAttributeCollection"/> object.</remarks>
		public Object SyncRoot => this;

		IEnumerator IEnumerable.GetEnumerator() {
			return new X500RdnAttributeCollectionEnumerator(this);
		}
		void ICollection.CopyTo(Array array, Int32 index) {
			if (array == null) {
				throw new ArgumentNullException(nameof(array));
			}
			if (array.Rank != 1) {
				throw new ArgumentException("Multidimensional arrays are not supported.");
			}
			if (index < 0 || index >= array.Length) {
				throw new ArgumentOutOfRangeException(nameof(index));
			}
			if (index + Count > array.Length) {
				throw new ArgumentException("Index is out of range.");
			}
			for (Int32 i = 0; i < Count; i++) {
				array.SetValue(this[i], index);
				index++;
			}
		}

		/// <summary>
		/// Adds an <see cref="X500RdnAttribute"/> object to the <see cref="X500RdnAttributeCollection"/> object.
		/// </summary>
		/// <remarks>Use this method to add an <see cref="X500RdnAttribute"/> object to an existing collection at the current location.</remarks>
		/// <param name="entry">The <see cref="X500RdnAttribute"/> object to add to the collection.</param>
		/// <exception cref="AccessViolationException">An array is encoded and is read-only.</exception>
		/// <returns>The index of the added <see cref="X500RdnAttribute"/> object.</returns>
		public Int32 Add(X500RdnAttribute entry) {
			if (IsReadOnly) {
				throw new AccessViolationException("An object is encoded and is write-protected.");
			}
			_list.Add(entry);
			return _list.Count - 1;
		}
		/// <summary>
		/// 
		/// </summary>
		/// <param name="altNames"></param>
		public void AddRange(IEnumerable<X500RdnAttribute> altNames) {
			if (IsReadOnly) {
				throw new AccessViolationException("An object is encoded and is write-protected.");
			}
			_list.AddRange(altNames);
		}
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
		/// <exception cref="InvalidDataException">
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
				throw new ArgumentException("The parameter is incorrect.");
			}
			asn.MoveNext();
			do {
				if (asn.Tag != 49) {
					throw new ArgumentException("The parameter is incorrect.");
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
		/// Removes an <see cref="X500RdnAttribute"/> object from the <see cref="X500RdnAttributeCollection"/> object.
		/// </summary>
		/// <param name="index">An entry index to remove.</param>
		/// <exception cref="AccessViolationException">An array is encoded and is read-only.</exception>
		public void Remove(Int32 index) {
			if (IsReadOnly) {
				throw new AccessViolationException("An object is encoded and is write-protected.");
			}
			_list.RemoveAt(index);
		}
		/// <summary>
		/// Closes current collection state and makes it read-only. The collection cannot be modified further.
		/// </summary>
		public void Close() {
			IsReadOnly = true;
		}
		/// <summary>
		/// Resets an array of <see cref="X500RdnAttribute"/> objects and enables write-mode for this object.
		/// </summary>
		public void Reset() {
			_list.Clear();
			IsReadOnly = false;
		}
		/// <summary>
		/// Gets an <see cref="X500RdnAttribute"/> object from the <see cref="X500RdnAttributeCollection"/> object.
		/// </summary>
		/// <param name="index">The location of the <see cref="X500RdnAttribute"/> object in the collection.</param>
		/// <returns></returns>
		public X500RdnAttribute this[Int32 index] => _list[index];

		/// <summary>
		/// Returns an <see cref="X500RdnAttributeCollectionEnumerator"/> object that can be used to navigate
		/// the <see cref="X500RdnAttributeCollection"/> object
		/// </summary>
		/// <returns>An <see cref="X500RdnAttribute"/> object.</returns>
		public X500RdnAttributeCollectionEnumerator GetEnumerator() {
			return new X500RdnAttributeCollectionEnumerator(this);
		}
		/// <summary>
		/// Copies the <see cref="X500RdnAttributeCollection"/> object into an array.
		/// </summary>
		/// <param name="array">The array to copy the <see cref="X500RdnAttributeCollection"/> object into.</param>
		/// <param name="index">The location where the copy operation starts.</param>
		public void CopyTo(X500RdnAttribute[] array, Int32 index) {
			((ICollection) this).CopyTo(array, index);
		}

		IEnumerator<X500RdnAttribute> IEnumerable<X500RdnAttribute>.GetEnumerator() {
			return _list.GetEnumerator();
		}
	}

	/// <summary>
	/// Provides the ability to navigate through an <see cref="X500RdnAttributeCollection"/> object.
	/// </summary>
	public class X500RdnAttributeCollectionEnumerator : IEnumerator {
		readonly X500RdnAttributeCollection _entries;
		Int32 m_current;

		internal X500RdnAttributeCollectionEnumerator(X500RdnAttributeCollection entries) {
			_entries = entries;
			m_current = -1;
		}
		/// <summary>
		/// Gets the current <see cref="X500RdnAttribute"/> object in an <see cref="X500RdnAttributeCollection"/> object.
		/// </summary>
		/// <remarks><p>After an enumerator is created, the <see cref="MoveNext"/> method must be called to advance the
		/// enumerator to the first element of the collection before reading the value of the <strong>Current</strong> property;
		/// otherwise, <strong>Current</strong> returns a null reference (Nothing in Visual Basic) or throws an exception.</p>
		/// <p><strong>Current</strong> also returns a null reference (Nothing in Visual Basic) or throws an exception if the last
		/// call to <see cref="MoveNext"/> returns false, which indicates that the end of the collection has been reached.</p>
		/// <p><strong>Current</strong> does not move the position of the enumerator, and consecutive calls to <strong>Current</strong>
		/// return the same object, until <see cref="MoveNext"/> is called.</p></remarks>
		public X500RdnAttribute Current => _entries[m_current];

		/// <internalonly/>
		Object IEnumerator.Current => _entries[m_current];

		/// <summary>
		/// Advances to the next <see cref="X500RdnAttribute"/> object in an <see cref="X500RdnAttributeCollection"/> object
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
		public Boolean MoveNext() {
			if (m_current == _entries.Count - 1) {
				return false;
			}
			m_current++;
			return true;
		}
		/// <summary>
		/// Sets an enumerator to its initial position.
		/// </summary>
		/// <remarks>The initial position of an enumerator is before the first element in the <see cref="X500RdnAttributeCollection"/> object.
		/// An enumerator remains valid as long as the collection remains unchanged. If changes are made to the collection, such
		/// as adding, modifying, or deleting elements, the enumerator becomes invalid and the next call to the <strong>Reset</strong>
		/// method throws an <see cref="InvalidOperationException"/>.</remarks>
		public void Reset() {
			m_current = -1;
		}
	}
}