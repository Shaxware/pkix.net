using System.Linq;
using PKI.Base;
using PKI.Utils;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using SysadminsLV.Asn1Parser;

namespace System.Security.Cryptography.X509Certificates {
	/// <summary>
	/// Represents a collection of <see cref="X509CertificatePolicy"/> objects.
	/// </summary>
	public class X509CertificatePolicyCollection : ICryptCollection<X509CertificatePolicy> {
		readonly List<X509CertificatePolicy> _list;
		
		/// <summary>
		/// Initializes a new instance of the <see cref="X509CertificatePolicyCollection"/> class without any <see cref="X509CertificatePolicy"/> information.
		/// </summary>
		public X509CertificatePolicyCollection() { _list = new List<X509CertificatePolicy>(); }

		/// <summary>
		/// Gets the number of <see cref="X509CertificatePolicy"/> objects in a collection.
		/// </summary>
		public Int32 Count {
			get { return _list.Count; }
		}
		/// <summary>
		/// Indicates whether the collection is read-only.
		/// </summary>
		public Boolean IsReadOnly { get; private set; }
		/// <summary>
		/// Gets a value that indicates whether access to the <see cref="X509CertificatePolicyCollection"/> object is thread safe.
		/// </summary>
		/// <remarks>Returns <strong>False</strong> in all cases.</remarks>
		public Boolean IsSynchronized {
			get { return false; }
		}
		/// <summary>
		/// Gets an object that can be used to synchronize access to the <see cref="X509CertificatePolicyCollection"/> object.
		/// </summary>
		/// <remarks><see cref="X509CertificatePolicyCollection"/> is not thread safe. Derived classes can provide their own
		/// synchronized version of the <see cref="X509CertificatePolicyCollection"/> class using this property. The synchronizing
		/// code must perform operations on the <strong>SyncRoot</strong> property of the <see cref="X509CertificatePolicyCollection"/>
		/// object, not directly on the object itself. This ensures proper operation of collections that are derived from
		/// other objects. Specifically, it maintains proper synchronization with other threads that might simultaneously
		/// be modifying the <see cref="X509CertificatePolicyCollection"/> object.</remarks>
		public Object SyncRoot {
			get { return this; }
		}

		/// <internalonly/>
		IEnumerator IEnumerable.GetEnumerator() {
			return new X509CertificatePolicyCollectionEnumerator(this);
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
		/// Adds an <see cref="X509CertificatePolicy"/> object to the <see cref="X509CertificatePolicyCollection"/> object.
		/// </summary>
		/// <remarks>Use this method to add an <see cref="X509CertificatePolicy"/> object to an existing collection at the current location.</remarks>
		/// <param name="entry">The <see cref="X509CertificatePolicy"/> object to add to the collection.</param>
		/// <returns>
		/// The index of the added <see cref="X509CertificatePolicy"/> object.
		/// <para>
		/// If the method return a negative number (-1), then collection already contains a duplicated policy OID.
		/// Duplicated OIDs are not allowed.
		/// </para>
		/// </returns>
		/// <exception cref="AccessViolationException">The collection is closed and is read-only.</exception>
		public Int32 Add(X509CertificatePolicy entry) {
			if (IsReadOnly) { throw new AccessViolationException(Error.E_COLLECTIONCLOSED); }
			if (_list.Any(item => item.PolicyOid.Value == entry.PolicyOid.Value)) {
				return -1;
			}
			_list.Add(entry);
			return _list.Count - 1;
		}
		/// <summary>
		/// Removes an <see cref="X509CertificatePolicy"/> object from the <see cref="X509CertificatePolicyCollection"/> object.
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
		/// Resets an array of <see cref="X509CertificatePolicy"/> objects and enables write-mode for this object.
		/// </summary>
		public void Reset() {
			IsReadOnly = false;
			_list.Clear();
		}
		/// <summary>
		/// Encodes policy collection to a ASN.1-encoded byte array. Encoded byte array represents certificate policies extension value. 
		/// </summary>
		/// <returns>ASN.1-encoded byte array.</returns>
		public Byte[] Encode() {
			if (_list.Count == 0) { return null; }
			List<Byte> rawData = new List<Byte>();
			foreach (X509CertificatePolicy policy in _list) {
				rawData.AddRange(policy.Encode());
			}
			return Asn1Utils.Encode(rawData.ToArray(), 48);
		}
		/// <summary>
		/// Decodes a collection of certificate policies from a ASN.1-encoded byte array.
		/// <para>
		/// Byte array in the <strong>rawData</strong> parameter must represent certificate policies extension value.
		/// </para>
		/// </summary>
		/// <param name="rawData">ASN.1-encoded byte array that represents certificate policies extension value.</param>
		/// <exception cref="InvalidDataException">The data in the <strong>rawData</strong> parameter is not valid
		/// extension value.</exception>
		/// <exception cref="ArgumentNullException"><strong>rawData</strong> is null.</exception>
		public void Decode(Byte[] rawData) {
			if (rawData == null) { throw new ArgumentNullException("rawData"); }
			_list.Clear();
			Asn1Reader asn = new Asn1Reader(rawData);
			if (asn.Tag != 48) { throw new InvalidDataException("The data is invalid."); }
			asn.MoveNext();
			do {
				_list.Add(new X509CertificatePolicy(asn.GetTagRawData()));
			} while (asn.MoveNextCurrentLevel());
		}
		/// <summary>
		/// Gets an <see cref="X509CertificatePolicy"/> object from the <see cref="X509CertificatePolicyCollection"/> object.
		/// </summary>
		/// <param name="index">The location of the <see cref="X509CertificatePolicy"/> object in the collection.</param>
		/// <returns></returns>
		public X509CertificatePolicy this[Int32 index] {
			get { return _list[index]; }
		}
		/// <summary>
		/// Gets an <see cref="X509CertificatePolicy"/> object from the <see cref="X509CertificatePolicyCollection"/> object by policy's
		/// OID value or friendly name.
		/// </summary>
		/// <param name="oid">A string that represents a name or the value of spcific policy.</param>
		/// <remarks>Use this property to retrieve an <see cref="X509CertificatePolicy"/> object from an <see cref="X509CertificatePolicyCollection"/>
		/// object if you know the OID name or value value of the <see cref="X509CertificatePolicy"/>
		/// object. You can use the <see cref="this[int]"/> property to retrieve an <see cref="X509CertificatePolicy"/> object if you know
		/// its location in the collection</remarks>
		/// <returns>An <see cref="X509CertificatePolicy"/> object.</returns>
		public X509CertificatePolicy this[String oid] {
			get {
				return _list.FirstOrDefault(
					entry => String.Equals(entry.PolicyOid.FriendlyName, oid, StringComparison.CurrentCultureIgnoreCase) || entry.PolicyOid.Value == oid);
			}
		}
		/// <summary>
		/// Returns an <see cref="X509CertificatePolicyCollectionEnumerator"/> object that can be used to navigate
		/// the <see cref="X509CertificatePolicyCollection"/> object
		/// </summary>
		/// <returns>An <see cref="X509CertificatePolicy"/> object.</returns>
		public X509CertificatePolicyCollectionEnumerator GetEnumerator() {
			return new X509CertificatePolicyCollectionEnumerator(this);
		}
		/// <summary>
		/// Copies the <see cref="X509CertificatePolicyCollection"/> object into an array.
		/// </summary>
		/// <param name="array">The array to copy the <see cref="X509CertificatePolicyCollection"/> object into.</param>
		/// <param name="index">The location where the copy operation starts.</param>
		public void CopyTo(X509CertificatePolicy[] array, Int32 index) {
			((ICollection)this).CopyTo(array, index);
		}
	}
	/// <summary>
	/// Provides the ability to navigate through an <see cref="X509CertificatePolicyCollection"/> object.
	/// </summary>
	public class X509CertificatePolicyCollectionEnumerator : IEnumerator {
		readonly X509CertificatePolicyCollection _entries;
		Int32 m_current;

		internal X509CertificatePolicyCollectionEnumerator(X509CertificatePolicyCollection entries) {
			_entries = entries;
			m_current = -1;
		}
		/// <summary>
		/// Gets the current <see cref="X509CertificatePolicy"/> object in an <see cref="X509CertificatePolicyCollection"/> object.
		/// </summary>
		/// <remarks><p>After an enumerator is created, the <see cref="MoveNext"/> method must be called to advance the
		/// enumerator to the first element of the collection before reading the value of the <strong>Current</strong> property;
		/// otherwise, <strong>Current</strong> returns a null reference (Nothing in Visual Basic) or throws an exception.</p>
		/// <p><strong>Current</strong> also returns a null reference (Nothing in Visual Basic) or throws an exception if the last
		/// call to <see cref="MoveNext"/> returns false, which indicates that the end of the collection has been reached.</p>
		/// <p><strong>Current</strong> does not move the position of the enumerator, and consecutive calls to <strong>Current</strong>
		/// return the same object, until <see cref="MoveNext"/> is called.</p></remarks>
		public X509CertificatePolicy Current {
			get { return _entries[m_current]; }
		}

		/// <internalonly/>
		Object IEnumerator.Current {
			get { return _entries[m_current]; }
		}
		/// <summary>
		/// Advances to the next <see cref="X509CertificatePolicy"/> object in an <see cref="X509CertificatePolicyCollection"/> object
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
		/// <remarks>The initial position of an enumerator is before the first element in the <see cref="X509CertificatePolicyCollection"/> object.
		/// An enumerator remains valid as long as the collection remains unchanged. If changes are made to the collection, such
		/// as adding, modifying, or deleting elements, the enumerator becomes invalid and the next call to the <strong>Reset</strong>
		/// method throws an <see cref="InvalidOperationException"/>.</remarks>
		public void Reset() { m_current = -1; }
	}
}