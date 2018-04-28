using System;
using System.Collections;
using System.Collections.Generic;
using PKI.Utils;

namespace SysadminsLV.PKI {
    /// <summary>
    /// Represents a strongly-typed collection of <see cref="T"/> objects.
    /// </summary>
    /// <typeparam name="T">The type of elements in the list.</typeparam>
    /// <remarks>This class is abstract and cannot be used directly. Inherit from this class instead.</remarks>
    public abstract class BasicCollection<T> : IList<T> {
        protected readonly List<T> _list;

        /// <summary>
        /// Initializes a new instance of the <see cref="T"/> class.
        /// </summary>
        protected BasicCollection() {
            _list = new List<T>();
        }
        /// <summary>
        /// Initializes a new instance of the <see cref="BasicCollection{T}"/> class that contains elements copied
        /// from the specified collection and has sufficient capacity to accommodate the number of elements copied.
        /// </summary>
        /// <param name="collection">The collection whose elements are copied to the new list.</param>
        /// <exception cref="ArgumentNullException"><strong>collection</strong> is null.</exception>
        protected BasicCollection(IEnumerable<T> collection) {
            _list = new List<T>(collection);
        }

        /// <summary>
        /// Returns an enumerator that iterates through the collection
        /// </summary>
        /// <returns>Enumerator for current collection</returns>
        public IEnumerator<T> GetEnumerator() {
            return _list.GetEnumerator();
        }
        /// <internalonly />
        IEnumerator IEnumerable.GetEnumerator() {
            return GetEnumerator();
        }

        /// <summary>
        /// Gets the number of elements contained in the current collection.
        /// </summary>
        public Int32 Count => _list.Count;
        /// <inheritdoc />
        public Boolean IsReadOnly { get; protected set; }
        /// <summary>
        /// Gets or sets the element at the specified index.
        /// </summary>
        /// <param name="index">The zero-based index of the element to get or set.</param>
        /// <returns>The element at the specified index.</returns>
        /// <exception cref="ArgumentOutOfRangeException">
        /// index is less than 0 or index is equal to or greater than <see cref="Count"/>.
        /// </exception>
        public T this[Int32 index] {
            get => _list[index];
            set => _list[index] = value;
        }

        /// <summary>
        /// Adds an object to the end of the CollectionBase&lt;T&gt;.
        /// </summary>
        /// <remarks>Use this method to add an object to an existing collection at the current location.</remarks>
        /// <param name="item">
        /// The object to be added to the end of the current collection.
        /// The value can be null for reference types.
        /// </param>
        /// <exception cref="AccessViolationException">A collection is read-only.</exception>
        public virtual void Add(T item) {
            if (IsReadOnly) {
                throw new AccessViolationException(Error.E_COLLECTIONCLOSED);
            }
            _list.Add(item);
        }
        /// <summary>
        /// Adds the elements of the specified collection to the end of the current collection.
        /// </summary>
        /// <param name="collection">
        /// The collection whose elements should be added to the end of the current collection.
        /// The collection itself cannot be null, but it can contain elements that are null, if type <strong>T</strong>
        /// is a reference type.
        /// </param>
        /// <exception cref="AccessViolationException">A collection is read-only.</exception>
        public virtual void AddRange(IEnumerable<T> collection) {
            if (IsReadOnly) {
                throw new AccessViolationException(Error.E_COLLECTIONCLOSED);
            }
            _list.AddRange(collection);
        }
        /// <summary>
        /// Removes all elements from the current collection and resets <see cref="IsReadOnly"/> member to
        /// <strong>False</strong>.
        /// </summary>
        public void Clear() {
            _list.Clear();
            IsReadOnly = false;
        }
        /// <summary>
        /// Determines whether an element is in the current collection.
        /// </summary>
        /// <param name="item">The object to locate in the current collection.</param>
        /// <returns><strong>True</strong> if item is found in the collection, otherwise <strong>False</strong>.</returns>
        public Boolean Contains(T item) {
            return _list.Contains(item);
        }
        /// <summary>
        /// Copies the entire collection to a compatible one-dimensional array, starting at the specified
        /// index of the target array.
        /// </summary>
        /// <param name="array">
        /// The one-dimensional Array that is the destination of the elements copied from current collection.
        /// </param>
        /// <param name="arrayIndex">The zero-based index in array at which copying begins.</param>
        public void CopyTo(T[] array, Int32 arrayIndex) {
            _list.CopyTo(array, arrayIndex);
        }
        /// <summary>
        /// Removes the first occurrence of a specific object from the current collection. 
        /// </summary>
        /// <param name="item">Object to remove.</param>
        /// <returns><strong>True</strong> if object was removed, otherwise <strong>False</strong>.</returns>
        /// <exception cref="AccessViolationException">A collection is read-only.</exception>
        public virtual Boolean Remove(T item) {
            if (IsReadOnly) {
                throw new AccessViolationException(Error.E_COLLECTIONCLOSED);
            }
            return _list.Remove(item);
        }
        /// <summary>
        /// Searches for the specified object and returns the zero-based index of the first occurrence within
        /// the entire collection.
        /// </summary>
        /// <param name="item">Object to find.</param>
        /// <returns>
        /// The zero-based index of the first occurrence of item within the entire collection, if found;
        /// otherwise, –1.
        /// </returns>
        public Int32 IndexOf(T item) {
            return _list.IndexOf(item);
        }
        /// <summary>
        /// Inserts an element into the current collection at the specified index.
        /// </summary>
        /// <param name="index">The zero-based index at which item should be inserted.</param>
        /// <param name="item">The object to insert. The value can be null for reference types.</param>
        /// <exception cref="AccessViolationException">A collection is read-only.</exception>
        public virtual void Insert(Int32 index, T item) {
            if (IsReadOnly) {
                throw new AccessViolationException(Error.E_COLLECTIONCLOSED);
            }
            _list.Insert(index, item);
        }
        /// <summary>
        /// Removes the element at the specified index of the current collection.
        /// </summary>
        /// <param name="index">The zero-based index of the element to remove.</param>
        /// <exception cref="AccessViolationException">A collection is read-only.</exception>
        public virtual void RemoveAt(Int32 index) {
            if (IsReadOnly) {
                throw new AccessViolationException(Error.E_COLLECTIONCLOSED);
            }
            _list.RemoveAt(index);
        }
    }
}
