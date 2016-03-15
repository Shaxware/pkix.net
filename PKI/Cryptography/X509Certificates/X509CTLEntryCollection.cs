using System.Collections;
using System.Collections.Generic;

namespace System.Security.Cryptography.X509Certificates {
	/// <summary>
	/// Represents a collection of <see cref="X509CTLEntry"/> objects.
	/// </summary>
	public class X509CTLEntryCollection : ICollection {
		private readonly List<X509CTLEntry> _list;

		/// <summary>
		/// Initializes a new instance of the <see cref="X509CTLEntryCollection"/> class without any <see cref="X509CTLEntry"/> information.
		/// </summary>
		public X509CTLEntryCollection() { _list = new List<X509CTLEntry>(); }

		/// <summary>
		/// Gets the number of <see cref="X509CTLEntry"/> objects in a collection.
		/// </summary>
		public Int32 Count {
			get { return _list.Count; }
		}
		/// <summary>
		/// Indicates whether the collection is read-only.
		/// </summary>
		public Boolean IsReadOnly { get; private set; }
		/// <summary>
		/// Gets a value that indicates whether access to the <see cref="X509CTLEntryCollection"/> object is thread safe.
		/// </summary>
		/// <remarks>Returns <strong>False</strong> in all cases.</remarks>
		public Boolean IsSynchronized {
			get { return false; }
		}
		/// <summary>
		/// Gets an object that can be used to synchronize access to the <see cref="X509CTLEntryCollection"/> object.
		/// </summary>
		/// <remarks><see cref="X509CTLEntryCollection"/> is not thread safe. Derived classes can provide their own
		/// synchronized version of the <see cref="X509CTLEntryCollection"/> class using this property. The synchronizing
		/// code must perform operations on the <strong>SyncRoot</strong> property of the <see cref="X509CTLEntryCollection"/>
		/// object, not directly on the object itself. This ensures proper operation of collections that are derived from
		/// other objects. Specifically, it maintains proper synchronization with other threads that might simultaneously
		/// be modifying the <see cref="X509CTLEntryCollection"/> object.</remarks>
		public Object SyncRoot {
			get { return this; }
		}

		/// <internalonly/>
		IEnumerator IEnumerable.GetEnumerator() {
			return new X509CTLEntryCollectionEnumerator(this);
		}
		/// <internalonly/> 
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
		/// Adds an <see cref="X509CTLEntry"/> object to the <see cref="X509CTLEntryCollection"/> object.
		/// </summary>
		/// <param name="entry">The <see cref="X509CTLEntry"/> object to add to the collection.</param>
		/// <exception cref="AccessViolationException">The collection is closed and is read-only.</exception>
		/// <returns>The index of the added <see cref="X509CTLEntry"/> object.</returns>
		/// <remarks>
		/// Use this method to add an <see cref="X509CTLEntry"/> object to an existing collection at the current location.
		/// <para>The method returns a '-1' value if the object is already in the collection.</para>
		/// </remarks>
		public Int32 Add(X509CTLEntry entry) {
			if (IsReadOnly) { throw new AccessViolationException("The collection is in read-only mode."); }
			if (_list.Contains(entry)) { return -1; }
			_list.Add(entry);
			return _list.Count - 1;
		}
		/// <summary>
		/// Removes an <see cref="X509CTLEntry"/> object from the <see cref="X509CTLEntryCollection"/> object.
		/// </summary>
		/// <param name="index">An entry index to remove.</param>
		/// <exception cref="AccessViolationException">The collection is closed and is read-only.</exception>
		public void Remove(Int32 index) {
			if (IsReadOnly) { throw new AccessViolationException("The collection is in read-only mode."); }
			_list.RemoveAt(index);
		}
		/// <summary>
		/// Closes current collection state and makes it read-only. The collection cannot be modified further.
		/// </summary>
		public void Close() { IsReadOnly = true; }
		/// <summary>
		/// Resets an array of <see cref="X509CTLEntry"/> objects and enables write-mode for this object.
		/// </summary>
		public void Reset() {
			_list.Clear();
			IsReadOnly = false;
		}
		/// <summary>
		/// Gets an <see cref="X509CTLEntry"/> object from the <see cref="X509CTLEntryCollection"/> object.
		/// </summary>
		/// <param name="index">The location of the <see cref="X509CTLEntry"/> object in the collection.</param>
		/// <returns></returns>
		public X509CTLEntry this[Int32 index] {
			get { return _list[index] as X509CTLEntry; }
		}
		/// <summary>
		/// Gets an <see cref="X509CTLEntry"/> object from the <see cref="X509CTLEntryCollection"/> object by certificate's
		/// Thumbprint value.
		/// </summary>
		/// <param name="thumbprint">A string that represents a <see cref="X509CTLEntry.Thumbprint">Thumbprint</see>
		/// property.</param>
		/// <remarks>Use this property to retrieve an <see cref="X509CTLEntry"/> object from an <see cref="X509CTLEntryCollection"/>
		/// object if you know the <see cref="X509CTLEntry.Thumbprint">Thumbprint</see> value of the <see cref="X509CTLEntry"/>
		/// object. You can use the <see cref="this[int]"/> property to retrieve an <see cref="X509CTLEntry"/> object if you know
		/// its location in the collection</remarks>
		/// <returns>An <see cref="X509CTLEntry"/> object.</returns>
		public X509CTLEntry this[String thumbprint] {
			get {
				foreach (X509CTLEntry entry in _list) {
					if (entry.Thumbprint.ToLower() == thumbprint.ToLower()) { return entry; }
				}
				return null;
			}
		}
		/// <summary>
		/// Returns an <see cref="X509CTLEntryCollectionEnumerator"/> object that can be used to navigate
		/// the <see cref="X509CTLEntryCollection"/> object
		/// </summary>
		/// <returns>An <see cref="X509CTLEntry"/> object.</returns>
		public X509CTLEntryCollectionEnumerator GetEnumerator() {
			return new X509CTLEntryCollectionEnumerator(this);
		}
		/// <summary>
		/// Copies the <see cref="X509CTLEntryCollection"/> object into an array.
		/// </summary>
		/// <param name="array">The array to copy the <see cref="X509CTLEntryCollection"/> object into.</param>
		/// <param name="index">The location where the copy operation starts.</param>
		public void CopyTo(X509CTLEntry[] array, Int32 index) {
			((ICollection)this).CopyTo(array, index);
		}
	}
	/// <summary>
	/// Provides the ability to navigate through an <see cref="X509CTLEntryCollection"/> object.
	/// </summary>
	public class X509CTLEntryCollectionEnumerator : IEnumerator {
		readonly X509CTLEntryCollection _entries;
		Int32 m_current;

		internal X509CTLEntryCollectionEnumerator(X509CTLEntryCollection entries) {
			_entries = entries;
			m_current = -1;
		}
		/// <summary>
		/// Gets the current <see cref="X509CTLEntry"/> object in an <see cref="X509CTLEntryCollection"/> object.
		/// </summary>
		/// <remarks><p>After an enumerator is created, the <see cref="MoveNext"/> method must be called to advance the
		/// enumerator to the first element of the collection before reading the value of the <strong>Current</strong> property;
		/// otherwise, <strong>Current</strong> returns a null reference (Nothing in Visual Basic) or throws an exception.</p>
		/// <p><strong>Current</strong> also returns a null reference (Nothing in Visual Basic) or throws an exception if the last
		/// call to <see cref="MoveNext"/> returns false, which indicates that the end of the collection has been reached.</p>
		/// <p><strong>Current</strong> does not move the position of the enumerator, and consecutive calls to <strong>Current</strong>
		/// return the same object, until <see cref="MoveNext"/> is called.</p></remarks>
		public X509CTLEntry Current {
			get { return _entries[m_current]; }
		}

		/// <internalonly/>
		Object IEnumerator.Current {
			get { return _entries[m_current]; }
		}
		/// <summary>
		/// Advances to the next <see cref="X509CTLEntry"/> object in an <see cref="X509CTLEntryCollection"/> object
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
			if (m_current == (_entries.Count - 1)) { return false; }
			m_current++;
			return true;
		}
		/// <summary>
		/// Sets an enumerator to its initial position.
		/// </summary>
		/// <remarks>The initial position of an enumerator is before the first element in the <see cref="X509CTLEntryCollection"/> object.
		/// An enumerator remains valid as long as the collection remains unchanged. If changes are made to the collection, such
		/// as adding, modifying, or deleting elements, the enumerator becomes invalid and the next call to the <strong>Reset</strong>
		/// method throws an <see cref="InvalidOperationException"/>.</remarks>
		public void Reset() { m_current = -1; }
	}
}