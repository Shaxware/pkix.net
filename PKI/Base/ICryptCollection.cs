using System;
using System.Collections;

namespace PKI.Base {
	/// <summary>
	/// This interface defines required members for classes that represent a corresponding SEQUENCE OF in the
	/// ASN.1 structure.
	/// </summary>
	/// <typeparam name="T">The type of the elements in the collection.</typeparam>
	public interface ICryptCollection<in T> : ICollection {
		/// <summary>
		/// Adds new element to the collection.
		/// </summary>
		/// <param name="item">Element to add.</param>
		/// <returns>The index at which new item has been added.</returns>
		Int32 Add(T item);
		//void AddRange(IEnumerable<T> items);
		/// <summary>
		/// Removes en element from the collection by specifying the index of the item to remove.
		/// </summary>
		/// <param name="index">An array index to remove.</param>
		void Remove(Int32 index);
		/// <summary>
		/// Closes the current collection. When the collection is closed, no modifications shall be allowed. Any
		/// method that modifies the collection (say, Add, Remove, Insert, etc.) must throw
		/// <see cref="AccessViolationException"/>.
		/// <para>A collection can be unlocked by re-instantiating the collection or by calling <see cref="Reset"/> method.</para>
		/// </summary>
		void Close();
		/// <summary>
		/// Clears all items from the current collection and unlocks the collection (if it was previously closed).
		/// </summary>
		void Reset();
		/// <summary>
		/// Initializes a collection from a ASN.1-encoded byte array. By convention, ASN.1-encoded array that represent
		/// a SEQUENCE OF structure should consist of encoded array of elements wrapped by a SEQUENCE container.
		/// </summary>
		/// <param name="rawData">ASN.1-encoded byte array.</param>
		void Decode(Byte[] rawData);
		/// <summary>
		/// Encodes current instance of the collection to a ASN.1-encoded byte array.
		/// </summary>
		/// <returns>ASN.1-encoded byte array.</returns>
		Byte[] Encode();
		/// <summary>
		/// Indicates whether the collection is write-protected or not. If this member returns <strong>True</strong>,
		/// no modifications should be allowed without resetting the collection.
		/// </summary>
		Boolean IsReadOnly { get; }
	}
}
