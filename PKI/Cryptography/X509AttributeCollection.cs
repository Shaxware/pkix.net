using System.Collections;
using System.Collections.Generic;

namespace System.Security.Cryptography {
	/// <summary>
	/// Represents a collection of <see cref="X509Attribute"/> objects.
	/// </summary>
	public class X509AttributeCollection : ICollection {
		readonly List<X509Attribute> _list;

		/// <summary>
		/// Initializes a new instance of the <see cref="X509AttributeCollection"/> class without any <see cref="X509Attribute"/> information.
		/// </summary>
		public X509AttributeCollection() { _list = new List<X509Attribute>(); }
		/// <summary>
		/// Initializes a new instance of the <see cref="X509AttributeCollection"/> class from an array of <see cref="X509Attribute"/> objects.
		/// </summary>
		/// <param name="attributes">An array of <see cref="X509Attribute"/> objects.</param>
		public X509AttributeCollection(X509Attribute[] attributes) {
			_list = new List<X509Attribute>(attributes);
		}

		/// <summary>
		/// Gets the number of <see cref="X509Attribute"/> objects in a collection.
		/// </summary>
		public Int32 Count => _list.Count;

		/// <internalonly/>
		IEnumerator IEnumerable.GetEnumerator() {
			return new X509AttributeCollectionEnumerator(this);
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
		/// Adds an <see cref="X509Attribute"/> object to the <see cref="X509AttributeCollection"/> object.
		/// </summary>
		/// <remarks>Use this method to add an <see cref="X509Attribute"/> object to an existing collection at the current location.</remarks>
		/// <param name="entry">The <see cref="X509Attribute"/> object to add to the collection.</param>
		/// <returns>The index of the added <see cref="X509Attribute"/> object.</returns>
		public Int32 Add(X509Attribute entry) {
			_list.Add(entry);
			return _list.Count;
		}
		/// <summary>
		/// Gets an <see cref="X509Attribute"/> object from the <see cref="X509AttributeCollection"/> object.
		/// </summary>
		/// <param name="index">The location of the <see cref="X509Attribute"/> object in the collection.</param>
		/// <returns></returns>
		public X509Attribute this[Int32 index] => _list[index] as X509Attribute;

		/// <summary>
		/// Gets an <see cref="X509Attribute"/> object from the <see cref="X509AttributeCollection"/> object by attributes object identifier.
		/// </summary>
		/// <param name="oid">A string that represents an attribute's object identifier.</param>
		/// <remarks>Use this property to retrieve an <see cref="X509Attribute"/> object from an <see cref="X509AttributeCollection"/>
		/// object if you know the value of the object identifier the <see cref="X509Attribute"/>
		/// object. You can use the <see cref="this[int]"/> property to retrieve an <see cref="X509Attribute"/> object if you know
		/// its location in the collection</remarks>
		/// <returns>An <see cref="X509Attribute"/> object.</returns>
		public X509Attribute this[String oid] {
			get {
				foreach (X509Attribute entry in _list) {
					if (entry.Oid.Value == oid.ToLower()) { return entry; }
				}
				return null;
			}
		}
		/// <summary>
		/// Returns an <see cref="X509AttributeCollectionEnumerator"/> object that can be used to navigate
		/// the <see cref="X509AttributeCollection"/> object
		/// </summary>
		/// <returns>An <see cref="X509Attribute"/> object.</returns>
		public X509AttributeCollectionEnumerator GetEnumerator() {
			return new X509AttributeCollectionEnumerator(this);
		}
		/// <summary>
		/// Copies the <see cref="X509AttributeCollection"/> object into an array.
		/// </summary>
		/// <param name="array">The array to copy the <see cref="X509AttributeCollection"/> object into.</param>
		/// <param name="index">The location where the copy operation starts.</param>
		public void CopyTo(X509Attribute[] array, Int32 index) {
			((ICollection)this).CopyTo(array, index);
		}
		/// <summary>
		/// Gets a value that indicates whether access to the <see cref="X509AttributeCollection"/> object is thread safe.
		/// </summary>
		/// <remarks>Returns <strong>False</strong> in all cases.</remarks>
		public bool IsSynchronized => false;

		/// <summary>
		/// Gets an object that can be used to synchronize access to the <see cref="X509AttributeCollection"/> object.
		/// </summary>
		/// <remarks><see cref="X509AttributeCollection"/> is not thread safe. Derived classes can provide their own
		/// synchronized version of the <see cref="X509AttributeCollection"/> class using this property. The synchronizing
		/// code must perform operations on the <strong>SyncRoot</strong> property of the <see cref="X509AttributeCollection"/>
		/// object, not directly on the object itself. This ensures proper operation of collections that are derived from
		/// other objects. Specifically, it maintains proper synchronization with other threads that might simultaneously
		/// be modifying the <see cref="X509AttributeCollection"/> object.</remarks>
		public Object SyncRoot => this;
	}
	/// <summary>
	/// Provides the ability to navigate through an <see cref="X509AttributeCollection"/> object.
	/// </summary>
	public class X509AttributeCollectionEnumerator : IEnumerator {
		X509AttributeCollection m_entries;
		Int32 m_current;

		X509AttributeCollectionEnumerator() { }
		internal X509AttributeCollectionEnumerator(X509AttributeCollection entries) {
			m_entries = entries;
			m_current = -1;
		}
		/// <summary>
		/// Gets the current <see cref="X509Attribute"/> object in an <see cref="X509AttributeCollection"/> object.
		/// </summary>
		/// <remarks><p>After an enumerator is created, the <see cref="MoveNext"/> method must be called to advance the
		/// enumerator to the first element of the collection before reading the value of the <strong>Current</strong> property;
		/// otherwise, <strong>Current</strong> returns a null reference (Nothing in Visual Basic) or throws an exception.</p>
		/// <p><strong>Current</strong> also returns a null reference (Nothing in Visual Basic) or throws an exception if the last
		/// call to <see cref="MoveNext"/> returns false, which indicates that the end of the collection has been reached.</p>
		/// <p><strong>Current</strong> does not move the position of the enumerator, and consecutive calls to <strong>Current</strong>
		/// return the same object, until <see cref="MoveNext"/> is called.</p></remarks>
		public X509Attribute Current => m_entries[m_current];

		/// <internalonly/>
		Object IEnumerator.Current => (Object)m_entries[m_current];

		/// <summary>
		/// Advances to the next <see cref="X509Attribute"/> object in an <see cref="X509AttributeCollection"/> object
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
		/// <remarks>The initial position of an enumerator is before the first element in the <see cref="X509AttributeCollection"/> object.
		/// An enumerator remains valid as long as the collection remains unchanged. If changes are made to the collection, such
		/// as adding, modifying, or deleting elements, the enumerator becomes invalid and the next call to the <strong>Reset</strong>
		/// method throws an <see cref="InvalidOperationException"/>.</remarks>
		public void Reset() { m_current = -1; }
	}
}
