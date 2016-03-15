using System;
using System.Collections;

namespace PKI.ServiceProviders {
	/// <summary>
	/// Represents a collection of <see cref="CspCNG"/> objects.
	/// </summary>
	public class CspCNGCollection : ICollection {
		private ArrayList m_list;

		/// <summary>
		/// Initializes a new instance of the <see cref="CspCNGCollection"/> class without any <see cref="CspCNG"/> information.
		/// </summary>
		public CspCNGCollection() { m_list = new ArrayList(); }

		/// <summary>
		/// Gets the number of <see cref="CspCNG"/> objects in a collection.
		/// </summary>
		public Int32 Count {
			get { return m_list.Count; }
		}

		/// <internalonly/>
		IEnumerator IEnumerable.GetEnumerator() {
			return new CspCNGCollectionEnumerator(this);
		}
		/// <internalonly/> 
		void ICollection.CopyTo(Array array, Int32 index) {
			if (array == null) { throw new ArgumentNullException("array"); }
			if (array.Rank != 1) { throw new ArgumentException("Multidimensional arrays are not supported."); }
			if (index < 0 || index >= array.Length) { throw new ArgumentOutOfRangeException("Index is out of range."); }
			if (index + this.Count > array.Length) { throw new ArgumentException("Index is out of range."); }
			for (Int32 i = 0; i < this.Count; i++) {
				array.SetValue(this[i], index);
				index++;
			}
		}

		/// <summary>
		/// Adds an <see cref="CspCNG"/> object to the <see cref="CspCNGCollection"/> object.
		/// </summary>
		/// <remarks>Use this method to add an <see cref="CspCNG"/> object to an existing collection at the current location.</remarks>
		/// <param name="entry">The <see cref="CspCNG"/> object to add to the collection.</param>
		/// <returns>The index of the added <see cref="CspCNG"/> object.</returns>
		public Int32 Add(CspCNG entry) { return m_list.Add(entry); }
		/// <summary>
		/// Gets an <see cref="CspCNG"/> object from the <see cref="CspCNGCollection"/> object.
		/// </summary>
		/// <param name="index">The location of the <see cref="CspCNG"/> object in the collection.</param>
		/// <returns></returns>
		public CspCNG this[Int32 index] {
			get { return m_list[index] as CspCNG; }
		}
		/// <summary>
		/// Gets an <see cref="CspCNG"/> object from the <see cref="CspCNGCollection"/> object by CSP name.
		/// </summary>
		/// <param name="name">A string that represents a <see cref="CspCNG.Name">Name</see>
		/// property.</param>
		/// <remarks>Use this property to retrieve an <see cref="CspCNG"/> object from an <see cref="CspCNGCollection"/>
		/// object if you know the <see cref="CspCNG.Name">Name</see> value of the <see cref="CspCNG"/>
		/// object. You can use the <see cref="this[int]"/> property to retrieve an <see cref="CspCNG"/> object if you know
		/// its location in the collection</remarks>
		/// <returns>An <see cref="CspCNG"/> object.</returns>
		public CspCNG this[String name] {
			get {
				foreach (CspCNG entry in m_list) {
					if (entry.Name.ToLower() == name.ToLower()) { return entry; }
				}
				return null;
			}
		}
		/// <summary>
		/// Returns an <see cref="CspCNGCollectionEnumerator"/> object that can be used to navigate the <see cref="CspCNGCollection"/> object
		/// </summary>
		/// <returns>An <see cref="CspCNG"/> object.</returns>
		public CspCNGCollectionEnumerator GetEnumerator() {
			return new CspCNGCollectionEnumerator(this);
		}
		/// <summary>
		/// Copies the <see cref="CspCNGCollection"/> object into an array.
		/// </summary>
		/// <param name="array">The array to copy the <see cref="CspCNGCollection"/> object into.</param>
		/// <param name="index">The location where the copy operation starts.</param>
		public void CopyTo(CspCNG[] array, Int32 index) {
			((ICollection)this).CopyTo(array, index);
		}
		/// <summary>
		/// Gets a value that indicates whether access to the <see cref="CspCNGCollection"/> object is thread safe.
		/// </summary>
		/// <remarks>Returns <strong>False</strong> in all cases.</remarks>
		public bool IsSynchronized {
			get { return false; }
		}
		/// <summary>
		/// Gets an object that can be used to synchronize access to the <see cref="CspCNGCollection"/> object.
		/// </summary>
		/// <remarks><see cref="CspCNGCollection"/> is not thread safe. Derived classes can provide their own
		/// synchronized version of the <see cref="CspCNGCollection"/> class using this property. The synchronizing
		/// code must perform operations on the <strong>SyncRoot</strong> property of the <see cref="CspCNGCollection"/>
		/// object, not directly on the object itself. This ensures proper operation of collections that are derived from
		/// other objects. Specifically, it maintains proper synchronization with other threads that might simultaneously
		/// be modifying the <see cref="CspCNGCollection"/> object.</remarks>
		public Object SyncRoot {
			get { return this; }
		}
	}
	/// <summary>
	/// Provides the ability to navigate through an <see cref="CspCNGCollection"/> object.
	/// </summary>
	public class CspCNGCollectionEnumerator : IEnumerator {
		CspCNGCollection m_entries;
		Int32 m_current;

		CspCNGCollectionEnumerator() { }
		internal CspCNGCollectionEnumerator(CspCNGCollection entries) {
			m_entries = entries;
			m_current = -1;
		}
		/// <summary>
		/// Gets the current <see cref="CspCNG"/> object in an <see cref="CspCNGCollection"/> object.
		/// </summary>
		/// <remarks><p>After an enumerator is created, the <see cref="MoveNext"/> method must be called to advance the
		/// enumerator to the first element of the collection before reading the value of the <strong>Current</strong> property;
		/// otherwise, <strong>Current</strong> returns a null reference (Nothing in Visual Basic) or throws an exception.</p>
		/// <p><strong>Current</strong> also returns a null reference (Nothing in Visual Basic) or throws an exception if the last
		/// call to <see cref="MoveNext"/> returns false, which indicates that the end of the collection has been reached.</p>
		/// <p><strong>Current</strong> does not move the position of the enumerator, and consecutive calls to <strong>Current</strong>
		/// return the same object, until <see cref="MoveNext"/> is called.</p></remarks>
		public CspCNG Current {
			get { return m_entries[m_current]; }
		}

		/// <internalonly/>
		Object IEnumerator.Current {
			get { return (Object)m_entries[m_current]; }
		}
		/// <summary>
		/// Advances to the next <see cref="CspCNG"/> object in an <see cref="CspCNGCollection"/> object
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
			if (m_current == ((int)m_entries.Count - 1)) { return false; }
			m_current++;
			return true;
		}
		/// <summary>
		/// Sets an enumerator to its initial position.
		/// </summary>
		/// <remarks>The initial position of an enumerator is before the first element in the <see cref="CspCNGCollection"/> object.
		/// An enumerator remains valid as long as the collection remains unchanged. If changes are made to the collection, such
		/// as adding, modifying, or deleting elements, the enumerator becomes invalid and the next call to the <strong>Reset</strong>
		/// method throws an <see cref="InvalidOperationException"/>.</remarks>
		public void Reset() { m_current = -1; }
	}
}