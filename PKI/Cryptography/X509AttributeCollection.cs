using System.Collections.Generic;
using PKI.Base;

namespace System.Security.Cryptography {
    /// <summary>
    /// Represents a collection of <see cref="X509Attribute"/> objects.
    /// </summary>
    public class X509AttributeCollection : BasicCollection<X509Attribute> {

        /// <summary>
        /// Initializes a new instance of the <see cref="X509AttributeCollection"/> class without any <see cref="X509Attribute"/> information.
        /// </summary>
        public X509AttributeCollection() { }
        /// <summary>
        /// Initializes a new instance of the <see cref="X509AttributeCollection"/> class from an array of <see cref="X509Attribute"/> objects.
        /// </summary>
        /// <param name="attributes">An array of <see cref="X509Attribute"/> objects.</param>
        public X509AttributeCollection(IEnumerable<X509Attribute> attributes) : base(attributes) { }

        /// <summary>
        /// Gets an <see cref="X509Attribute"/> object from the <see cref="X509AttributeCollection"/> object by attributes object identifier.
        /// </summary>
        /// <param name="oid">A string that represents an attribute's object identifier.</param>
        /// <remarks>Use this property to retrieve an <see cref="X509Attribute"/> object from an <see cref="X509AttributeCollection"/>
        /// object if you know the value of the object identifier the <see cref="X509Attribute"/>
        /// object. You can use the <see cref="this[string]"/> property to retrieve an <see cref="X509Attribute"/> object if you know
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
    }
}
