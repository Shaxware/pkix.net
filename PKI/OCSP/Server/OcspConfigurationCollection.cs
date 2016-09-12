using System.Collections;
using System;
using System.Collections.Generic;
using System.Linq;

namespace PKI.OCSP.Server {
	/// <summary>
	/// Represents a collection of <see cref="OcspConfiguration"/> objects.
	/// </summary>
	public class OcspConfigurationCollection : ICollection {
		readonly List<OcspConfiguration> _list;

		/// <summary>
		/// Initializes a new instance of the <see cref="OcspConfigurationCollection"/> class without any <see cref="OcspConfiguration"/> information.
		/// </summary>
		public OcspConfigurationCollection() { _list = new List<OcspConfiguration>(); }

		/// <summary>
		/// Gets the number of <see cref="OcspConfiguration"/> objects in a collection.
		/// </summary>
		public Int32 Count => _list.Count;

		/// <internalonly/>
		IEnumerator IEnumerable.GetEnumerator() {
			return new OcspConfigurationCollectionEnumerator(this);
		}
		/// <internalonly/> 
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
		/// Adds an <see cref="OcspConfiguration"/> object to the <see cref="OcspConfigurationCollection"/> object.
		/// </summary>
		/// <remarks>Use this method to add an <see cref="OcspConfiguration"/> object to an existing collection at the current location.</remarks>
		/// <param name="entry">The <see cref="OcspConfiguration"/> object to add to the collection.</param>
		/// <returns>The index of the added <see cref="OcspConfiguration"/> object.</returns>
		public Int32 Add(OcspConfiguration entry) {
			_list.Add(entry);
			return _list.Count - 1;
		}
		/// <summary>
		/// Gets an <see cref="OcspConfiguration"/> object from the <see cref="OcspConfigurationCollection"/> object.
		/// </summary>
		/// <param name="index">The location of the <see cref="OcspConfiguration"/> object in the collection.</param>
		/// <returns></returns>
		public OcspConfiguration this[Int32 index] => _list[index];

		/// <summary>
		/// Gets an <see cref="OcspConfiguration"/> object from the <see cref="OcspConfigurationCollection"/> object by configuration name.
		/// </summary>
		/// <param name="name">A string that represents a <see cref="OcspConfiguration.Name">SerialNumber</see>
		/// property.</param>
		/// <remarks>Use this property to retrieve an <see cref="OcspConfiguration"/> object from an <see cref="OcspConfigurationCollection"/>
		/// object if you know the <see cref="OcspConfiguration.Name">SerialNumber</see> value of the <see cref="OcspConfiguration"/>
		/// object. You can use the <see cref="this[int]"/> property to retrieve an <see cref="OcspConfiguration"/> object if you know
		/// its location in the collection</remarks>
		/// <returns>An <see cref="OcspConfiguration"/> object.</returns>
		public OcspConfiguration this[String name] {
			get { return _list.FirstOrDefault(entry => String.Equals(entry.Name, name, StringComparison.CurrentCultureIgnoreCase)); }
		}
		/// <summary>
		/// Returns an <see cref="OcspConfigurationCollectionEnumerator"/> object that can be used to navigate
		/// the <see cref="OcspConfigurationCollection"/> object
		/// </summary>
		/// <returns>An <see cref="OcspConfiguration"/> object.</returns>
		public OcspConfigurationCollectionEnumerator GetEnumerator() {
			return new OcspConfigurationCollectionEnumerator(this);
		}
		/// <summary>
		/// Copies the <see cref="OcspConfigurationCollection"/> object into an array.
		/// </summary>
		/// <param name="array">The array to copy the <see cref="OcspConfigurationCollection"/> object into.</param>
		/// <param name="index">The location where the copy operation starts.</param>
		public void CopyTo(OcspConfiguration[] array, Int32 index) {
			((ICollection)this).CopyTo(array, index);
		}
		/// <summary>
		/// Gets a value that indicates whether access to the <see cref="OcspConfigurationCollection"/> object is thread safe.
		/// </summary>
		/// <remarks>Returns <strong>False</strong> in all cases.</remarks>
		public bool IsSynchronized => false;

		/// <summary>
		/// Gets an object that can be used to synchronize access to the <see cref="OcspConfigurationCollection"/> object.
		/// </summary>
		/// <remarks><see cref="OcspConfigurationCollection"/> is not thread safe. Derived classes can provide their own
		/// synchronized version of the <see cref="OcspConfigurationCollection"/> class using this property. The synchronizing
		/// code must perform operations on the <strong>SyncRoot</strong> property of the <see cref="OcspConfigurationCollection"/>
		/// object, not directly on the object itself. This ensures proper operation of collections that are derived from
		/// other objects. Specifically, it maintains proper synchronization with other threads that might simultaneously
		/// be modifying the <see cref="OcspConfigurationCollection"/> object.</remarks>
		public Object SyncRoot => this;
	}
	/// <summary>
	/// Provides the ability to navigate through an <see cref="OcspConfigurationCollection"/> object.
	/// </summary>
	public class OcspConfigurationCollectionEnumerator : IEnumerator {
		readonly OcspConfigurationCollection _entries;
		Int32 m_current;

		//OcspConfigurationCollectionEnumerator() { }
		internal OcspConfigurationCollectionEnumerator(OcspConfigurationCollection entries) {
			_entries = entries;
			m_current = -1;
		}
		/// <summary>
		/// Gets the current <see cref="OcspConfiguration"/> object in an <see cref="OcspConfigurationCollection"/> object.
		/// </summary>
		/// <remarks><p>After an enumerator is created, the <see cref="MoveNext"/> method must be called to advance the
		/// enumerator to the first element of the collection before reading the value of the <strong>Current</strong> property;
		/// otherwise, <strong>Current</strong> returns a null reference (Nothing in Visual Basic) or throws an exception.</p>
		/// <p><strong>Current</strong> also returns a null reference (Nothing in Visual Basic) or throws an exception if the last
		/// call to <see cref="MoveNext"/> returns false, which indicates that the end of the collection has been reached.</p>
		/// <p><strong>Current</strong> does not move the position of the enumerator, and consecutive calls to <strong>Current</strong>
		/// return the same object, until <see cref="MoveNext"/> is called.</p></remarks>
		public OcspConfiguration Current => _entries[m_current];

		/// <internalonly/>
		Object IEnumerator.Current => _entries[m_current];

		/// <summary>
		/// Advances to the next <see cref="OcspConfiguration"/> object in an <see cref="OcspConfigurationCollection"/> object
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
		/// <remarks>The initial position of an enumerator is before the first element in the <see cref="OcspConfigurationCollection"/> object.
		/// An enumerator remains valid as long as the collection remains unchanged. If changes are made to the collection, such
		/// as adding, modifying, or deleting elements, the enumerator becomes invalid and the next call to the <strong>Reset</strong>
		/// method throws an <see cref="InvalidOperationException"/>.</remarks>
		public void Reset() { m_current = -1; }
	}
}