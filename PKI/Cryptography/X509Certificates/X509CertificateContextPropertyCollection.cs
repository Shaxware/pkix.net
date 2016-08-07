using System.Collections;
using System.Collections.Generic;

namespace System.Security.Cryptography.X509Certificates {
	/// <summary>
	/// Represents a collection of <see cref="X509CertificateContextProperty"/> objects.
	/// </summary>
	public class X509CertificateContextPropertyCollection : IEnumerable<X509CertificateContextProperty>, ICollection {
		readonly List<X509CertificateContextProperty> _list;

		/// <summary>
		/// Initializes a new instance of the <see cref="X509CertificateContextPropertyCollection"/> class without any <see cref="X509CertificateContextProperty"/> information.
		/// </summary>
		public X509CertificateContextPropertyCollection() { _list = new List<X509CertificateContextProperty>(); }

		/// <summary>
		/// Gets the number of <see cref="X509CertificateContextProperty"/> objects in a collection.
		/// </summary>
		public Int32 Count => _list.Count;

		/// <summary>
		/// Indicates whether the collection is read-only.
		/// </summary>
		public Boolean IsReadOnly { get; private set; }
		/// <summary>
		/// Gets a value that indicates whether access to the <see cref="X509CertificateContextPropertyCollection"/> object is thread safe.
		/// </summary>
		/// <remarks>Returns <strong>False</strong> in all cases.</remarks>
		public Boolean IsSynchronized => false;

		/// <summary>
		/// Gets an object that can be used to synchronize access to the <see cref="X509CertificateContextPropertyCollection"/> object.
		/// </summary>
		/// <remarks><see cref="X509CertificateContextPropertyCollection"/> is not thread safe. Derived classes can provide their own
		/// synchronized version of the <see cref="X509CertificateContextPropertyCollection"/> class using this property. The synchronizing
		/// code must perform operations on the <strong>SyncRoot</strong> property of the <see cref="X509CertificateContextPropertyCollection"/>
		/// object, not directly on the object itself. This ensures proper operation of collections that are derived from
		/// other objects. Specifically, it maintains proper synchronization with other threads that might simultaneously
		/// be modifying the <see cref="X509CertificateContextPropertyCollection"/> object.</remarks>
		public Object SyncRoot => this;

		IEnumerator IEnumerable.GetEnumerator() {
			return new X509CertificateContextPropertyCollectionEnumerator(this);
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
		/// Adds an <see cref="X509CertificateContextProperty"/> object to the <see cref="X509CertificateContextPropertyCollection"/> object.
		/// </summary>
		/// <remarks>Use this method to add an <see cref="X509CertificateContextProperty"/> object to an existing collection at the current location.</remarks>
		/// <param name="entry">The <see cref="X509CertificateContextProperty"/> object to add to the collection.</param>
		/// <exception cref="AccessViolationException">An array is encoded and is read-only.</exception>
		/// <returns>The index of the added <see cref="X509CertificateContextProperty"/> object.</returns>
		public Int32 Add(X509CertificateContextProperty entry) {
			if (IsReadOnly) { throw new AccessViolationException("An object is encoded and is write-protected."); }
			_list.Add(entry);
			return _list.Count - 1;
		}
		/// <summary>
		/// 
		/// </summary>
		/// <param name="altNames"></param>
		public void AddRange(IEnumerable<X509CertificateContextProperty> altNames) {
			if (IsReadOnly) { throw new AccessViolationException("An object is encoded and is write-protected."); }
			_list.AddRange(altNames);
		}
		/// <summary>
		/// Removes an <see cref="X509CertificateContextProperty"/> object from the <see cref="X509CertificateContextPropertyCollection"/> object.
		/// </summary>
		/// <param name="index">An entry index to remove.</param>
		/// <exception cref="AccessViolationException">An array is encoded and is read-only.</exception>
		public void Remove(Int32 index) {
			if (IsReadOnly) { throw new AccessViolationException("An object is encoded and is write-protected."); }
			_list.RemoveAt(index);
		}
		/// <summary>
		/// Closes current collection state and makes it read-only. The collection cannot be modified further.
		/// </summary>
		public void Close() {
			IsReadOnly = true;
		}
		/// <summary>
		/// Resets an array of <see cref="X509CertificateContextProperty"/> objects and enables write-mode for this object.
		/// </summary>
		public void Reset() {
			_list.Clear();
			IsReadOnly = false;
		}
		/// <summary>
		/// Gets an <see cref="X509CertificateContextProperty"/> object from the <see cref="X509CertificateContextPropertyCollection"/> object.
		/// </summary>
		/// <param name="index">The location of the <see cref="X509CertificateContextProperty"/> object in the collection.</param>
		/// <returns></returns>
		public X509CertificateContextProperty this[Int32 index] => _list[index];

		/// <summary>
		/// Returns an <see cref="X509CertificateContextPropertyCollectionEnumerator"/> object that can be used to navigate
		/// the <see cref="X509CertificateContextPropertyCollection"/> object
		/// </summary>
		/// <returns>An <see cref="X509CertificateContextProperty"/> object.</returns>
		public X509CertificateContextPropertyCollectionEnumerator GetEnumerator() {
			return new X509CertificateContextPropertyCollectionEnumerator(this);
		}
		/// <summary>
		/// Copies the <see cref="X509CertificateContextPropertyCollection"/> object into an array.
		/// </summary>
		/// <param name="array">The array to copy the <see cref="X509CertificateContextPropertyCollection"/> object into.</param>
		/// <param name="index">The location where the copy operation starts.</param>
		public void CopyTo(X509CertificateContextProperty[] array, Int32 index) {
			((ICollection)this).CopyTo(array, index);
		}

		IEnumerator<X509CertificateContextProperty> IEnumerable<X509CertificateContextProperty>.GetEnumerator() {
			return _list.GetEnumerator();
		}
	}
	/// <summary>
	/// Provides the ability to navigate through an <see cref="X509CertificateContextPropertyCollection"/> object.
	/// </summary>
	public class X509CertificateContextPropertyCollectionEnumerator : IEnumerator {
		readonly X509CertificateContextPropertyCollection _entries;
		Int32 m_current;

		internal X509CertificateContextPropertyCollectionEnumerator(X509CertificateContextPropertyCollection entries) {
			_entries = entries;
			m_current = -1;
		}
		/// <summary>
		/// Gets the current <see cref="X509CertificateContextProperty"/> object in an <see cref="X509CertificateContextPropertyCollection"/> object.
		/// </summary>
		/// <remarks><p>After an enumerator is created, the <see cref="MoveNext"/> method must be called to advance the
		/// enumerator to the first element of the collection before reading the value of the <strong>Current</strong> property;
		/// otherwise, <strong>Current</strong> returns a null reference (Nothing in Visual Basic) or throws an exception.</p>
		/// <p><strong>Current</strong> also returns a null reference (Nothing in Visual Basic) or throws an exception if the last
		/// call to <see cref="MoveNext"/> returns false, which indicates that the end of the collection has been reached.</p>
		/// <p><strong>Current</strong> does not move the position of the enumerator, and consecutive calls to <strong>Current</strong>
		/// return the same object, until <see cref="MoveNext"/> is called.</p></remarks>
		public X509CertificateContextProperty Current => _entries[m_current];

		/// <internalonly/>
		Object IEnumerator.Current => _entries[m_current];

		/// <summary>
		/// Advances to the next <see cref="X509CertificateContextProperty"/> object in an <see cref="X509CertificateContextPropertyCollection"/> object
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
			if (m_current == _entries.Count - 1) { return false; }
			m_current++;
			return true;
		}
		/// <summary>
		/// Sets an enumerator to its initial position.
		/// </summary>
		/// <remarks>The initial position of an enumerator is before the first element in the <see cref="X509CertificateContextPropertyCollection"/> object.
		/// An enumerator remains valid as long as the collection remains unchanged. If changes are made to the collection, such
		/// as adding, modifying, or deleting elements, the enumerator becomes invalid and the next call to the <strong>Reset</strong>
		/// method throws an <see cref="InvalidOperationException"/>.</remarks>
		public void Reset() { m_current = -1; }
	}
}