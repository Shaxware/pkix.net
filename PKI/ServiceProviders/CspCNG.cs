using System;

namespace PKI.ServiceProviders {
    /// <summary>
    /// Represents single KSP (Key Storage Provider) information.
    /// </summary>
    [Obsolete("Use 'CspProviderInfo' class.")]
    public class CspCNG {
        String pname, pcomments;
        ALG_ID_CNGCollection algs;
        internal CspCNG(String name, String comments, ALG_ID_CNGCollection supportedAlgorithms) {
            pname = name;
            pcomments = comments;
            algs = supportedAlgorithms;
        }
        /// <summary>
        /// Gets provider name.
        /// </summary>
        public String Name => pname;

        /// <summary>
        /// Gets optional comments about the provider.
        /// </summary>
        public String Comments => pcomments;

        /// <summary>
        /// Gets algorithms supported by the provider.
        /// </summary>
        public ALG_ID_CNGCollection SupportedAlgorithms => algs;
    }
}
