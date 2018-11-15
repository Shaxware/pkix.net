using System;
using System.Collections;
using System.Collections.Generic;

namespace SysadminsLV.PKI.Helpers {
    /// <summary>
    /// Represents a strongly-typed collection of <see cref="T"/> objects.
    /// </summary>
    /// <typeparam name="T">The type of elements in the list.</typeparam>
    /// <remarks>This class is abstract and cannot be used directly. Inherit from this class instead.</remarks>
    public abstract class BasicCollection<T> : IList<T> {
        protected const String E_COLLECTIONCLOSED = "The collection is in read-only mode.";
        /// <summary>
        /// Gets internal list.
        /// </summary>
        protected readonly List<T> InternalList;

        /// <summary>
        /// Initializes a new instance of the <see cref="T"/> class.
        /// </summary>
        protected BasicCollection() {
            InternalList = new List<T>();
        }
        /// <summary>
        /// Initializes a new instance of the <see cref="BasicCollection{T}"/> class that contains elements copied
        /// from the specified collection and has sufficient capacity to accommodate the number of elements copied.
        /// </summary>
        /// <param name="collection">The collection whose elements are copied to the new list.</param>
        /// <exception cref="ArgumentNullException"><strong>collection</strong> is null.</exception>
        protected BasicCollection(IEnumerable<T> collection) {
            InternalList = new List<T>(collection);
        }

        /// <inheritdoc />
        public IEnumerator<T> GetEnumerator() {
            return InternalList.GetEnumerator();
        }
        /// <inheritdoc />
        /// <internalonly />
        IEnumerator IEnumerable.GetEnumerator() {
            return GetEnumerator();
        }

        /// <inheritdoc />
        public Int32 Count => InternalList.Count;
        /// <inheritdoc />
        public Boolean IsReadOnly { get; protected set; }
        /// <inheritdoc />
        public T this[Int32 index] {
            get => InternalList[index];
            set => InternalList[index] = value;
        }

        /// <inheritdoc />
        /// <exception cref="T:System.AccessViolationException">A collection is read-only.</exception>
        public virtual void Add(T item) {
            if (IsReadOnly) {
                throw new AccessViolationException(E_COLLECTIONCLOSED);
            }
            InternalList.Add(item);
        }
        /// <inheritdoc cref="List{T}"/>
        /// <exception cref="AccessViolationException">A collection is read-only.</exception>
        public virtual void AddRange(IEnumerable<T> collection) {
            if (IsReadOnly) {
                throw new AccessViolationException(E_COLLECTIONCLOSED);
            }
            InternalList.AddRange(collection);
        }
        /// <inheritdoc />
        public void Clear() {
            InternalList.Clear();
            IsReadOnly = false;
        }
        /// <inheritdoc />
        public Boolean Contains(T item) {
            return InternalList.Contains(item);
        }
        /// <inheritdoc />
        public void CopyTo(T[] array, Int32 arrayIndex) {
            InternalList.CopyTo(array, arrayIndex);
        }
        /// <inheritdoc />
        /// <exception cref="AccessViolationException">A collection is read-only.</exception>
        public virtual Boolean Remove(T item) {
            if (IsReadOnly) {
                throw new AccessViolationException(E_COLLECTIONCLOSED);
            }
            return InternalList.Remove(item);
        }
        /// <inheritdoc />
        public Int32 IndexOf(T item) {
            return InternalList.IndexOf(item);
        }
        /// <inheritdoc />
        /// <exception cref="AccessViolationException">A collection is read-only.</exception>
        public virtual void Insert(Int32 index, T item) {
            if (IsReadOnly) {
                throw new AccessViolationException(E_COLLECTIONCLOSED);
            }
            InternalList.Insert(index, item);
        }
        /// <inheritdoc />
        /// <exception cref="AccessViolationException">A collection is read-only.</exception>
        public virtual void RemoveAt(Int32 index) {
            if (IsReadOnly) {
                throw new AccessViolationException(E_COLLECTIONCLOSED);
            }
            InternalList.RemoveAt(index);
        }
    }
}
