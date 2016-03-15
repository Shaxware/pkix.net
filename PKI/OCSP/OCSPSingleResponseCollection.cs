using System;
using System.Collections;

namespace PKI.OCSP {
	/// <summary>
	/// Represents a collection of <see cref="OCSPSingleResponse"/> objects.
	/// </summary>
	public class OCSPSingleResponseCollection : ICollection {
		private readonly ArrayList _list;

		/// <summary>
		/// Initializes a new instance of the <see cref="OCSPSingleResponseCollection"/> class without any <see cref="OCSPSingleResponse"/> information.
		/// </summary>
		public OCSPSingleResponseCollection() { _list = new ArrayList(); }

		/// <summary>
		/// Gets the number of <see cref="OCSPSingleResponse"/> objects in a collection.
		/// </summary>
		public Int32 Count {
			get { return _list.Count; }
		}

		/// <internalonly/>
		IEnumerator IEnumerable.GetEnumerator() {
			return new OCSPSingleResponseCollectionEnumerator(this);
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
		/// Adds an <see cref="OCSPSingleResponse"/> object to the <see cref="OCSPSingleResponseCollection"/> object.
		/// </summary>
		/// <remarks>Use this method to add an <see cref="OCSPSingleResponse"/> object to an existing collection at the current location.</remarks>
		/// <param name="entry">The <see cref="OCSPSingleResponse"/> object to add to the collection.</param>
		/// <returns>The index of the added <see cref="OCSPSingleResponse"/> object.</returns>
		public Int32 Add(OCSPSingleResponse entry) { return _list.Add(entry); }
		/// <summary>
		/// Gets an <see cref="OCSPSingleResponse"/> object from the <see cref="OCSPSingleResponseCollection"/> object.
		/// </summary>
		/// <param name="index">The location of the <see cref="OCSPSingleResponse"/> object in the collection.</param>
		/// <returns></returns>
		public OCSPSingleResponse this[Int32 index] {
			get { return _list[index] as OCSPSingleResponse; }
		}
		/// <summary>
		/// Gets an <see cref="OCSPSingleResponse"/> object from the <see cref="OCSPSingleResponseCollection"/> object by revoked certificate's
		/// serial number.
		/// </summary>
		/// <param name="status">A string that represents a <see cref="OCSPSingleResponse.CertStatus">CertStatus</see>
		/// property.</param>
		/// <remarks>Use this property to retrieve an <see cref="OCSPSingleResponse"/> object from an <see cref="OCSPSingleResponseCollection"/>
		/// object if you know the <see cref="OCSPSingleResponse.CertStatus">Status</see> value of the <see cref="OCSPSingleResponse"/>
		/// object. You can use the <see cref="this[int]"/> property to retrieve an <see cref="OCSPSingleResponse"/> object if you know
		/// its location in the collection</remarks>
		/// <returns>An <see cref="OCSPSingleResponse"/> object.</returns>
		public OCSPSingleResponse this[CertificateStatus status] {
			get {
				foreach (OCSPSingleResponse entry in _list) {
					if (entry.CertStatus == status) { return entry; }
				}
				return null;
			}
		}
		/// <summary>
		/// Returns an <see cref="OCSPSingleResponseCollectionEnumerator"/> object that can be used to navigate
		/// the <see cref="OCSPSingleResponseCollection"/> object
		/// </summary>
		/// <returns>An <see cref="OCSPSingleResponse"/> object.</returns>
		public OCSPSingleResponseCollectionEnumerator GetEnumerator() {
			return new OCSPSingleResponseCollectionEnumerator(this);
		}
		/// <summary>
		/// Copies the <see cref="OCSPSingleResponseCollection"/> object into an array.
		/// </summary>
		/// <param name="array">The array to copy the <see cref="OCSPSingleResponseCollection"/> object into.</param>
		/// <param name="index">The location where the copy operation starts.</param>
		public void CopyTo(OCSPSingleResponse[] array, Int32 index) {
			((ICollection)this).CopyTo(array, index);
		}
		/// <summary>
		/// Gets a value that indicates whether access to the <see cref="OCSPSingleResponseCollection"/> object is thread safe.
		/// </summary>
		/// <remarks>Returns <strong>False</strong> in all cases.</remarks>
		public bool IsSynchronized {
			get { return false; }
		}
		/// <summary>
		/// Gets an object that can be used to synchronize access to the <see cref="OCSPSingleResponseCollection"/> object.
		/// </summary>
		/// <remarks><see cref="OCSPSingleResponseCollection"/> is not thread safe. Derived classes can provide their own
		/// synchronized version of the <see cref="OCSPSingleResponseCollection"/> class using this property. The synchronizing
		/// code must perform operations on the <strong>SyncRoot</strong> property of the <see cref="OCSPSingleResponseCollection"/>
		/// object, not directly on the object itself. This ensures proper operation of collections that are derived from
		/// other objects. Specifically, it maintains proper synchronization with other threads that might simultaneously
		/// be modifying the <see cref="OCSPSingleResponseCollection"/> object.</remarks>
		public Object SyncRoot {
			get { return this; }
		}
	}
	/// <summary>
	/// Provides the ability to navigate through an <see cref="OCSPSingleResponseCollection"/> object.
	/// </summary>
	public class OCSPSingleResponseCollectionEnumerator : IEnumerator {
		readonly OCSPSingleResponseCollection _entries;
		Int32 m_current;

		internal OCSPSingleResponseCollectionEnumerator(OCSPSingleResponseCollection entries) {
			_entries = entries;
			m_current = -1;
		}
		/// <summary>
		/// Gets the current <see cref="OCSPSingleResponse"/> object in an <see cref="OCSPSingleResponseCollection"/> object.
		/// </summary>
		/// <remarks><p>After an enumerator is created, the <see cref="MoveNext"/> method must be called to advance the
		/// enumerator to the first element of the collection before reading the value of the <strong>Current</strong> property;
		/// otherwise, <strong>Current</strong> returns a null reference (Nothing in Visual Basic) or throws an exception.</p>
		/// <p><strong>Current</strong> also returns a null reference (Nothing in Visual Basic) or throws an exception if the last
		/// call to <see cref="MoveNext"/> returns false, which indicates that the end of the collection has been reached.</p>
		/// <p><strong>Current</strong> does not move the position of the enumerator, and consecutive calls to <strong>Current</strong>
		/// return the same object, until <see cref="MoveNext"/> is called.</p></remarks>
		public OCSPSingleResponse Current {
			get { return _entries[m_current]; }
		}

		/// <internalonly/>
		Object IEnumerator.Current {
			get { return _entries[m_current]; }
		}
		/// <summary>
		/// Advances to the next <see cref="OCSPSingleResponse"/> object in an <see cref="OCSPSingleResponseCollection"/> object
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
		/// <remarks>The initial position of an enumerator is before the first element in the <see cref="OCSPSingleResponseCollection"/> object.
		/// An enumerator remains valid as long as the collection remains unchanged. If changes are made to the collection, such
		/// as adding, modifying, or deleting elements, the enumerator becomes invalid and the next call to the <strong>Reset</strong>
		/// method throws an <see cref="InvalidOperationException"/>.</remarks>
		public void Reset() { m_current = -1; }
	}
}
//namespace PKI.OCSP {
//    public class OCSPSingleResponseCollection : ICollection {
//        private ArrayList m_list;

//        public OCSPSingleResponseCollection() { m_list = new ArrayList(); }

//        public Int32 Count {
//            get { return m_list.Count; }
//        }

//        /// <internalonly/>
//        IEnumerator IEnumerable.GetEnumerator() {
//            return new OCSPSingleResponseCollectionEnumerator(this);
//        }
//        /// <internalonly/> 
//        void ICollection.CopyTo(Array array, Int32 index) {
//            if (array == null) { throw new ArgumentNullException("array"); }
//            if (array.Rank != 1) { throw new ArgumentException("Multidimensional arrays are not supported."); }
//            if (index < 0 || index >= array.Length) { throw new ArgumentOutOfRangeException("Index is out of range."); }
//            if (index + this.Count > array.Length) { throw new ArgumentException("Index is out of range."); }
//            for (Int32 i = 0; i < this.Count; i++) {
//                array.SetValue(this[i], index);
//                index++;
//            }
//        }

//        public Int32 Add(OCSPSingleResponse entry) { return m_list.Add(entry); }
//        public OCSPSingleResponse this[Int32 index] {
//            get { return m_list[index] as OCSPSingleResponse; }
//        }
//        // Indexer using a serial number. 
//        public OCSPSingleResponse this[CertificateStatus status] {
//            get {
//                foreach (OCSPSingleResponse entry in m_list) {
//                    if (entry.CertStatus == status) { return entry; }
//                }
//                return null;
//            }
//        }
//        public OCSPSingleResponseCollectionEnumerator GetEnumerator() {
//            return new OCSPSingleResponseCollectionEnumerator(this);
//        }
//        public void CopyTo(OCSPSingleResponse[] array, Int32 index) {
//            ((ICollection)this).CopyTo(array, index);
//        }
//        public bool IsSynchronized {
//            get { return false; }
//        }
//        public Object SyncRoot {
//            get { return this; }
//        }
//    }
//    public class OCSPSingleResponseCollectionEnumerator : IEnumerator {
//        OCSPSingleResponseCollection m_entries;
//        Int32 m_current;

//        OCSPSingleResponseCollectionEnumerator() { }
//        internal OCSPSingleResponseCollectionEnumerator(OCSPSingleResponseCollection entries) {
//            m_entries = entries;
//            m_current = -1;
//        }

//        public OCSPSingleResponse Current {
//            get { return m_entries[m_current]; }
//        }

//        /// <internalonly/>
//        Object IEnumerator.Current {
//            get { return (Object)m_entries[m_current]; }
//        }

//        public bool MoveNext() {
//            if (m_current == ((int)m_entries.Count - 1)) { return false; }
//            m_current++;
//            return true;
//        }
//        public void Reset() { m_current = -1; }
//    }
//}