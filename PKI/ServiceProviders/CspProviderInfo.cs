using System;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using CERTENROLLLib;
using PKI.Utils;

namespace PKI.ServiceProviders {
    /// <summary>
    /// The <strong>CspProviderInfo</strong> class provides access to general information about a cryptographic provider.
    /// </summary>
    /// <remarks>
    ///		This class has no public constructors. Instead, use <see cref="CspProviderInfoCollection.GetProviderInfo()"/> method to access this object.
    /// </remarks>
    public class CspProviderInfo {
        internal CspProviderInfo(ICspInformation csp) {
            Name = csp.Name;
            Type = (ProviderTypeEnum)csp.Type;
            //Algorithms = new ProviderAlgorithm(csp.CspAlgorithms);
            IsHardware = csp.IsHardwareDevice;
            IsSoftware = csp.IsSoftwareDevice;
            IsRemovable = csp.IsRemovable;
            IsSmartCard = csp.IsSmartCard;
            IsLegacy = csp.LegacyCsp;
            HardwareRNG = csp.HasHardwareRandomNumberGenerator;
            KeyContainerLength = csp.MaxKeyContainerNameLength;
            KeySpec = (X509KeySpecFlags)csp.KeySpec;
            Version = csp.Version;
            IsValid = csp.Valid;
            Algorithms = new CspProviderAlgorithmInfoCollection();
            Algorithms.AddRange(from ICspAlgorithm alg in csp.CspAlgorithms select new CspProviderAlgorithmInfo(alg));
            CryptographyUtils.ReleaseCom(csp);
        }

        /// <summary>
        /// Gets the name of the provider.
        /// </summary>
        public String Name { get; }
        /// <summary>
        /// Gets the type of the provider.
        /// </summary>
        public ProviderTypeEnum Type { get; }
        /// <summary>
        /// Gets a collection of <see cref="CspProviderAlgorithmInfo"/> objects that contains information about the algorithms
        /// supported by the provider.
        /// </summary>
        public CspProviderAlgorithmInfoCollection Algorithms { get; }
        /// <summary>
        /// Gets a Boolean value that determines whether the provider is implemented in a hardware device.
        /// </summary>
        public Boolean IsHardware { get; }
        /// <summary>
        /// Gets a Boolean value that specifies whether the provider is implemented in software.
        /// </summary>
        public Boolean IsSoftware { get; }
        /// <summary>
        /// Gets a Boolean value that specifies whether the token that contains the key can be removed.
        /// </summary>
        public Boolean IsRemovable { get; }
        /// <summary>
        /// Gets a Boolean value that specifies whether the provider is a smart card provider.
        /// </summary>
        public Boolean IsSmartCard { get; }
        /// <summary>
        /// Gets a Boolean value that specifies whether the provider is a Cryptography API: Next Generation (CNG)
        /// provider or a CryptoAPI (legacy) CSP.
        /// </summary>
        public Boolean IsLegacy { get; }
        /// <summary>
        /// Gets a Boolean value that specifies whether the provider supports a hardware random number generator
        /// that can be used to create random bytes for cryptographic operations.
        /// </summary>
        public Boolean HardwareRNG { get; }
        /// <summary>
        /// Gets the maximum supported length for the name of the private key container associated with the provider.
        /// </summary>
        public Int32 KeyContainerLength { get; }
        /// <summary>
        /// Gets a value that specifies the intended use of the algorithms supported by the provider.
        /// </summary>
        public X509KeySpecFlags KeySpec { get; }
        /// <summary>
        /// Gets the version number of the provider.
        /// </summary>
        public Int32 Version { get; }
        /// <summary>
        /// Gets a Boolean value that specifies whether the provider is installed on the client computer.
        /// </summary>
        public Boolean IsValid { get; }
    }
}
