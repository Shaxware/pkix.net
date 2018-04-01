using System;

namespace PKI.ServiceProviders {
    /// <summary>
    /// This class is used to store information about particular cryptographic algorithm.
    /// </summary>
    [Obsolete("Use 'CspProviderAlgorithmInfo' class")]
    public class ALG_ID {
        internal ALG_ID(String name, String fullname, String[] protocols, UInt32 defkey, UInt32 minkey, UInt32 maxkey, UInt32 id) {
            Name = name;
            FullName = fullname;
            Protocols = protocols;
            DefaultKeyLength = defkey;
            MinKeyLength = minkey;
            MaxKeyLength = maxkey;
            ID = id;
        }

        /// <summary>
        /// Gets supported algorithm name.
        /// </summary>
        public String Name { get; }
        /// <summary>
        /// Gets supported algorithm full name.
        /// </summary>
        public String FullName { get; }
        /// <summary>
        /// Gets protocol list supported by the current algorithm.
        /// </summary>
        public String[] Protocols { get; }
        /// <summary>
        /// Gets default key length for current algorithm.
        /// </summary>
        public UInt32 DefaultKeyLength { get; }
        /// <summary>
        /// Gets minimum key length supported by the current algorithm.
        /// </summary>
        public UInt32 MinKeyLength { get; }
        /// <summary>
        /// Gets maximum key length supported by the current algorithm. 
        /// </summary>
        public UInt32 MaxKeyLength { get; }
        /// <summary>
        /// Gets algorithm ID (CryptoAPI internal algorithm code).
        /// </summary>
        public UInt32 ID { get; }
    }
}
