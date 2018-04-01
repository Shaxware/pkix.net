using System;
using System.Text;

namespace PKI.ServiceProviders {
    /// <summary>
    /// Represents single CSP information.
    /// </summary>
    [Obsolete("Use 'CspProviderInfo' class instead.")]
    public class CspLegacy {
        readonly ALG_ID[] _algs;
        internal CspLegacy(String name, String type, ALG_IDCollection supportedAlgorithms) {
            Name = name;
            Type = type;
            if (supportedAlgorithms.Count > 0) {
                _algs = new ALG_ID[supportedAlgorithms.Count];
                supportedAlgorithms.CopyTo(_algs, 0);
            }
        }

        /// <summary>
        /// Gets provider name.
        /// </summary>
        public String Name { get; }
        /// <summary>
        /// Gets provider type.
        /// </summary>
        public String Type { get; private set; }
        /// <summary>
        /// Gets provider parameters. This information includes supported keys, algorithms and intended usage.
        /// </summary>
        public ALG_IDCollection SupportedAlgorithms {
            get {
                ALG_IDCollection output = new ALG_IDCollection();
                foreach (ALG_ID alg in _algs) { output.Add(alg); }
                return output;
            }
        }

        /// <summary>
        /// Returns a string that represents the current object.
        /// </summary>
        /// <returns>A string that represents the current object.</returns>
        public override String ToString() {
            StringBuilder SB = new StringBuilder();
            SB.Append("Provider: " + Name + Environment.NewLine);
            SB.Append("Algorithms: " + Environment.NewLine);
            if (_algs != null) {
                foreach (ALG_ID alg in _algs) {
                    SB.Append("  Name:" + alg.Name + "; ");
                    SB.Append("Default:" + alg.DefaultKeyLength + "; ");
                    SB.Append("Min:" + alg.MinKeyLength + "; ");
                    SB.Append("Max:" + alg.MaxKeyLength + "; ");
                    SB.Append("Protocols:");
                    if (alg.Protocols != null) {
                        foreach (String str in alg.Protocols) {
                            SB.Append(str + ",");
                        }
                    }
                    SB.Append(Environment.NewLine);
                }
            }
            return SB.ToString();
        }
    }
}
