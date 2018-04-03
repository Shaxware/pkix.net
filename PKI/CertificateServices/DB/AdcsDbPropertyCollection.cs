using System;
using System.Collections;
using System.Collections.Generic;

namespace PKI.CertificateServices.DB {
    /// <summary>
    /// Contains a collection of ADCS database entry properties.
    /// </summary>
    public class AdcsDbPropertyCollection : IDictionary<String, Object> {
        readonly IDictionary<String, Object> _dictionary = new Dictionary<String, Object>();
        /// <inheritdoc />
        public IEnumerator<KeyValuePair<String, Object>> GetEnumerator() {
            return _dictionary.GetEnumerator();
        }
        /// <inheritdoc />
        IEnumerator IEnumerable.GetEnumerator() {
            return GetEnumerator();
        }
        /// <inheritdoc />
        public void Add(KeyValuePair<String, Object> item) {
            _dictionary.Add(item);
        }
        /// <inheritdoc />
        public void Clear() {
            _dictionary.Clear();
        }
        /// <inheritdoc />
        public Boolean Contains(KeyValuePair<String, Object> item) {
            return _dictionary.Contains(item);
        }
        /// <inheritdoc />
        public void CopyTo(KeyValuePair<String, Object>[] array, Int32 arrayIndex) {
            _dictionary.CopyTo(array, arrayIndex);
        }
        /// <inheritdoc />
        public Boolean Remove(KeyValuePair<String, Object> item) {
            return _dictionary.Remove(item);
        }
        /// <inheritdoc />
        public Int32 Count => _dictionary.Count;
        /// <inheritdoc />
        public Boolean IsReadOnly => _dictionary.IsReadOnly;
        /// <inheritdoc />
        public Boolean ContainsKey(String key) {
            return _dictionary.ContainsKey(key);
        }
        /// <inheritdoc />
        public void Add(String key, Object value) {
            _dictionary.Add(key, value);
        }
        /// <inheritdoc />
        public Boolean Remove(String key) {
            return _dictionary.Remove(key);
        }
        /// <inheritdoc />
        public Boolean TryGetValue(String key, out Object value) {
            return _dictionary.TryGetValue(key, out value);
        }
        /// <inheritdoc />
        public Object this[String key] {
            get => _dictionary[key];
            set => _dictionary[key] = value;
        }
        /// <inheritdoc />
        public ICollection<String> Keys => _dictionary.Keys;
        /// <inheritdoc />
        public ICollection<Object> Values => _dictionary.Values;
    }
}
