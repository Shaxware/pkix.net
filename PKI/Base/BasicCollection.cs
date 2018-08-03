using System;
using System.Collections;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.ComponentModel;
using System.Linq;
using PKI.Utils;

namespace SysadminsLV.PKI {
    /// <summary>
    /// Represents a strongly-typed collection of <see cref="T"/> objects.
    /// </summary>
    /// <typeparam name="T">The type of elements in the list.</typeparam>
    /// <remarks>This class is abstract and cannot be used directly. Inherit from this class instead.</remarks>
    public abstract class BasicCollection<T> : IList<T>, INotifyCollectionChanged, INotifyPropertyChanged {
        protected readonly List<T> InternalList;

        /// <summary>
        /// Initializes a new instance of the <see cref="T"/> class.
        /// </summary>
        /// <param name="isNotifying">
        /// A value that indiciates whether the collection will fire <see cref="CollectionChanged"/> event. Default is <strong>False</strong>.
        /// </param>
        protected BasicCollection(Boolean isNotifying = false) {
            InternalList = new List<T>();
            IsNotifying = isNotifying;
        }
        /// <summary>
        /// Initializes a new instance of the <see cref="BasicCollection{T}"/> class that contains elements copied
        /// from the specified collection and has sufficient capacity to accommodate the number of elements copied.
        /// </summary>
        /// <param name="collection">The collection whose elements are copied to the new list.</param>
        /// <param name="isNotifying">
        /// A value that indiciates whether the collection will fire <see cref="CollectionChanged"/> event.  Default is <strong>False</strong>.
        /// </param>
        /// <exception cref="ArgumentNullException"><strong>collection</strong> is null.</exception>
        protected BasicCollection(IEnumerable<T> collection, Boolean isNotifying = false) {
            IEnumerable<T> items = collection as T[] ?? collection.ToArray();
            if (isNotifying) {
                addHandler(items.ToArray());
            }
            InternalList = new List<T>(items);
            IsNotifying = isNotifying;
        }

        /// <summary>
        /// A value that indiciates whether the collection will fire <see cref="CollectionChanged"/> event.
        /// </summary>
        public Boolean IsNotifying { get; }

        /// <summary>
        /// Returns an enumerator that iterates through the collection
        /// </summary>
        /// <returns>Enumerator for current collection</returns>
        public IEnumerator<T> GetEnumerator() {
            return InternalList.GetEnumerator();
        }
        /// <internalonly />
        IEnumerator IEnumerable.GetEnumerator() {
            return GetEnumerator();
        }

        /// <summary>
        /// Gets the number of elements contained in the current collection.
        /// </summary>
        public Int32 Count => InternalList.Count;
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
            get => InternalList[index];
            set {
                T oldValue = InternalList[index];
                removeHandler(oldValue);
                addHandler(value);
                var e = new NotifyCollectionChangedEventArgs(NotifyCollectionChangedAction.Replace, value, oldValue);
                OnCollectionChanged(e);
            }
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
            addHandler(item);
            InternalList.Add(item);
            var e = new NotifyCollectionChangedEventArgs(NotifyCollectionChangedAction.Add, item);
            OnCollectionChanged(e);
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
            T[] array = collection as T[] ?? collection.ToArray();
            addHandler(array);
            InternalList.AddRange(array);
            var e = new NotifyCollectionChangedEventArgs(NotifyCollectionChangedAction.Add, new List<T>(array));
            OnCollectionChanged(e);
        }
        /// <summary>
        /// Removes all elements from the current collection and resets <see cref="IsReadOnly"/> member to
        /// <strong>False</strong>.
        /// </summary>
        public void Clear() {
            removeHandler(InternalList.ToArray());
            InternalList.Clear();
            IsReadOnly = false;
            var e = new NotifyCollectionChangedEventArgs(NotifyCollectionChangedAction.Reset);
            OnCollectionChanged(e);
            OnPropertyChanged(nameof(IsReadOnly));
        }
        /// <summary>
        /// Determines whether an element is in the current collection.
        /// </summary>
        /// <param name="item">The object to locate in the current collection.</param>
        /// <returns><strong>True</strong> if item is found in the collection, otherwise <strong>False</strong>.</returns>
        public Boolean Contains(T item) {
            return InternalList.Contains(item);
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
            InternalList.CopyTo(array, arrayIndex);
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
            Boolean status = InternalList.Remove(item);
            if (status) {
                removeHandler(item);
                var e = new NotifyCollectionChangedEventArgs(NotifyCollectionChangedAction.Remove, item);
                OnCollectionChanged(e);
            }
            return status;
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
            return InternalList.IndexOf(item);
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
            addHandler(item);
            InternalList.Insert(index, item);
            var e = new NotifyCollectionChangedEventArgs(NotifyCollectionChangedAction.Add, item);
            OnCollectionChanged(e);
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
            T backup = this[index];
            removeHandler(backup);
            InternalList.RemoveAt(index);
            var e = new NotifyCollectionChangedEventArgs(NotifyCollectionChangedAction.Remove, backup);
            OnCollectionChanged(e);
        }

        void addHandler(params T[] items) {
            foreach (T item in items) {
                if (IsNotifying && item is INotifyPropertyChanged) {
                    ((INotifyPropertyChanged)item).PropertyChanged += OnChildPropertyChanged;
                }
            }
        }
        void removeHandler(params T[] items) {
            foreach (T item in items) {
                if (IsNotifying && item is INotifyPropertyChanged) {
                    ((INotifyPropertyChanged)item).PropertyChanged -= OnChildPropertyChanged;
                }
            }
        }

        protected void OnCollectionChanged(NotifyCollectionChangedEventArgs e) {
            if (IsNotifying && CollectionChanged != null) {
                try {
                    CollectionChanged(this, e);
                    OnPropertyChanged(nameof(Count));
                } catch (NotSupportedException) {
                    var alternativeEventArgs = new NotifyCollectionChangedEventArgs(NotifyCollectionChangedAction.Reset);
                    OnCollectionChanged(alternativeEventArgs);
                }
            }
        }
        void OnChildPropertyChanged(Object s, PropertyChangedEventArgs e) {
            OnPropertyChanged("child");
        }
        protected void OnPropertyChanged(String propertyName) {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }
        public event PropertyChangedEventHandler PropertyChanged;
        public event NotifyCollectionChangedEventHandler CollectionChanged;

    }
}
