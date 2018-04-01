using System;

namespace PKI.ServiceProviders {
    /// <summary>
    /// This class is used to store information about cryptographic algorithm.
    /// </summary>
    [Obsolete("Use 'CspProviderAlgorithmInfo' class")]
    public class ALG_ID_CNG {
        internal ALG_ID_CNG(String name, String pinterface, String[] operations) {
            Name = name;
            Interface = pinterface;
            Operations = operations;
        }

        /// <summary>
        /// Gets algorithm name.
        /// </summary>
        public String Name { get; }

        /// <summary>
        /// Gets interface type supported by the algorithm.
        /// </summary>
        public String Interface { get; }

        /// <summary>
        /// Gets optations for which the current algorithm is intended.
        /// </summary>
        public String[] Operations { get; }
    }
}
