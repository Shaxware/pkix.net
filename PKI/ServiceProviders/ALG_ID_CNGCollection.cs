using System;
using System.Collections;

namespace PKI.ServiceProviders {
	/// <summary>
	/// Represents a collection of <see cref="ALG_ID_CNG"/> objects.
	/// </summary>
	public class ALG_ID_CNGCollection : ICollection {
		readonly ArrayList _list;

		/// <summary>
		/// Initializes a new instance of the <see cref="ALG_ID_CNGCollection"/> class without any <see cref="ALG_ID_CNG"/> information.
		/// </summary>
		public ALG_ID_CNGCollection() { _list = new ArrayList(); }

		/// <summary>
		/// Gets the number of <see cref="ALG_ID_CNG"/> objects in a collection.
		/// </summary>
		public Int32 Count => _list.Count;

		/// <internalonly/>
		IEnumerator IEnumerable.GetEnumerator() {
			return new ALG_ID_CNGCollectionEnumerator(this);
		}
		/// <internalonly/> 
		void ICollection.CopyTo(Array array, Int32 index) {
			if (array == null) { throw new ArgumentNullException(nameof(array)); }
			if (array.Rank != 1) { throw new ArgumentException("Multidimensional arrays are not supported."); }
			if (index < 0 || index >= array.Length) { throw new ArgumentOutOfRangeException("Index is out of range."); }
			if (index + Count > array.Length) { throw new ArgumentException("Index is out of range."); }
			for (Int32 i = 0; i < Count; i++) {
				array.SetValue(this[i], index);
				index++;
			}
		}

		/// <summary>
		/// Adds an <see cref="ALG_ID_CNG"/> object to the <see cref="ALG_ID_CNGCollection"/> object.
		/// </summary>
		/// <remarks>Use this method to add an <see cref="ALG_ID_CNG"/> object to an existing collection at the current location.</remarks>
		/// <param name="entry">The <see cref="ALG_ID_CNG"/> object to add to the collection.</param>
		/// <returns>The index of the added <see cref="ALG_ID_CNG"/> object.</returns>
		public Int32 Add(ALG_ID_CNG entry) { return _list.Add(entry); }
		/// <summary>
		/// Gets an <see cref="ALG_ID_CNG"/> object from the <see cref="ALG_ID_CNGCollection"/> object.
		/// </summary>
		/// <param name="index">The location of the <see cref="ALG_ID_CNG"/> object in the collection.</param>
		/// <returns></returns>
		public ALG_ID_CNG this[Int32 index] => _list[index] as ALG_ID_CNG;

		/// <summary>
		/// Gets an <see cref="ALG_ID_CNG"/> object from the <see cref="ALG_ID_CNGCollection"/> object by CSP name.
		/// </summary>
		/// <param name="name">A string that represents a <see cref="ALG_ID_CNG.Name">Name</see>
		/// property.</param>
		/// <remarks>Use this property to retrieve an <see cref="ALG_ID_CNG"/> object from an <see cref="ALG_ID_CNGCollection"/>
		/// object if you know the <see cref="ALG_ID_CNG.Name">Name</see> value of the <see cref="ALG_ID_CNG"/>
		/// object. You can use the <see cref="this[int]"/> property to retrieve an <see cref="ALG_ID_CNG"/> object if you know
		/// its location in the collection</remarks>
		/// <returns>An <see cref="ALG_ID_CNG"/> object.</returns>
		public ALG_ID_CNG this[String name] {
			get {
				foreach (ALG_ID_CNG entry in _list) {
					if (entry.Name.ToLower() == name.ToLower()) { return entry; }
				}
				return null;
			}
		}
		/// <summary>
		/// Returns an <see cref="ALG_ID_CNGCollectionEnumerator"/> object that can be used to navigate the <see cref="ALG_ID_CNGCollection"/> object
		/// </summary>
		/// <returns>An <see cref="ALG_ID_CNG"/> object.</returns>
		public ALG_ID_CNGCollectionEnumerator GetEnumerator() {
			return new ALG_ID_CNGCollectionEnumerator(this);
		}
		/// <summary>
		/// Copies the <see cref="ALG_ID_CNGCollection"/> object into an array.
		/// </summary>
		/// <param name="array">The array to copy the <see cref="ALG_ID_CNGCollection"/> object into.</param>
		/// <param name="index">The location where the copy operation starts.</param>
		public void CopyTo(ALG_ID_CNG[] array, Int32 index) {
			((ICollection)this).CopyTo(array, index);
		}
		/// <summary>
		/// Gets a value that indicates whether access to the <see cref="ALG_ID_CNGCollection"/> object is thread safe.
		/// </summary>
		/// <remarks>Returns <strong>False</strong> in all cases.</remarks>
		public bool IsSynchronized => false;

		/// <summary>
		/// Gets an object that can be used to synchronize access to the <see cref="ALG_ID_CNGCollection"/> object.
		/// </summary>
		/// <remarks><see cref="ALG_ID_CNGCollection"/> is not thread safe. Derived classes can provide their own
		/// synchronized version of the <see cref="ALG_ID_CNGCollection"/> class using this property. The synchronizing
		/// code must perform operations on the <strong>SyncRoot</strong> property of the <see cref="ALG_ID_CNGCollection"/>
		/// object, not directly on the object itself. This ensures proper operation of collections that are derived from
		/// other objects. Specifically, it maintains proper synchronization with other threads that might simultaneously
		/// be modifying the <see cref="ALG_ID_CNGCollection"/> object.</remarks>
		public Object SyncRoot => this;
	}
	/// <summary>
	/// Provides the ability to navigate through an <see cref="ALG_ID_CNGCollection"/> object.
	/// </summary>
	public class ALG_ID_CNGCollectionEnumerator : IEnumerator {
		ALG_ID_CNGCollection m_entries;
		Int32 m_current;

		ALG_ID_CNGCollectionEnumerator() { }
		internal ALG_ID_CNGCollectionEnumerator(ALG_ID_CNGCollection entries) {
			m_entries = entries;
			m_current = -1;
		}
		/// <summary>
		/// Gets the current <see cref="ALG_ID_CNG"/> object in an <see cref="ALG_ID_CNGCollection"/> object.
		/// </summary>
		/// <remarks><p>After an enumerator is created, the <see cref="MoveNext"/> method must be called to advance the
		/// enumerator to the first element of the collection before reading the value of the <strong>Current</strong> property;
		/// otherwise, <strong>Current</strong> returns a null reference (Nothing in Visual Basic) or throws an exception.</p>
		/// <p><strong>Current</strong> also returns a null reference (Nothing in Visual Basic) or throws an exception if the last
		/// call to <see cref="MoveNext"/> returns false, which indicates that the end of the collection has been reached.</p>
		/// <p><strong>Current</strong> does not move the position of the enumerator, and consecutive calls to <strong>Current</strong>
		/// return the same object, until <see cref="MoveNext"/> is called.</p></remarks>
		public ALG_ID_CNG Current => m_entries[m_current];

		/// <internalonly/>
		Object IEnumerator.Current => (Object)m_entries[m_current];

		/// <summary>
		/// Advances to the next <see cref="ALG_ID_CNG"/> object in an <see cref="ALG_ID_CNGCollection"/> object
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
			if (m_current == (int)m_entries.Count - 1) { return false; }
			m_current++;
			return true;
		}
		/// <summary>
		/// Sets an enumerator to its initial position.
		/// </summary>
		/// <remarks>The initial position of an enumerator is before the first element in the <see cref="ALG_ID_CNGCollection"/> object.
		/// An enumerator remains valid as long as the collection remains unchanged. If changes are made to the collection, such
		/// as adding, modifying, or deleting elements, the enumerator becomes invalid and the next call to the <strong>Reset</strong>
		/// method throws an <see cref="InvalidOperationException"/>.</remarks>
		public void Reset() { m_current = -1; }
	}
}