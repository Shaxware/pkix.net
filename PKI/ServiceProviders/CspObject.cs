using CERTENROLLLib;
using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;

namespace PKI.ServiceProviders {
	/// <summary>
	/// The <strong>CspObject</strong> class provides access to general information about a cryptographic provider.
	/// </summary>
	/// <remarks>
	///		This class has no public constructors. Instead, use <see cref="Csp.EnumProviders"/> method to access this object.
	/// </remarks>
	public class CspObject {
		internal CspObject(ICspInformation csp) {
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
			List<ProviderAlgorithm> algs = new List<ProviderAlgorithm>();
			foreach (ICspAlgorithm alg in csp.CspAlgorithms) {
				algs.Add(new ProviderAlgorithm(alg));
			}
			Algorithms = algs.ToArray();
		}

		/// <summary>
		/// Gets the name of the provider.
		/// </summary>
		public String Name { get; private set; }
		/// <summary>
		/// Gets the type of the provider.
		/// </summary>
		public ProviderTypeEnum Type { get; private set; }
		/// <summary>
		/// Gets an array of <see cref="ProviderAlgorithm"/> objects that contains information about the algorithms
		/// supported by the provider.
		/// </summary>
		public ProviderAlgorithm[] Algorithms { get; private set; }
		/// <summary>
		/// Gets a Boolean value that determines whether the provider is implemented in a hardware device.
		/// </summary>
		public Boolean IsHardware { get; private set; }
		/// <summary>
		/// Gets a Boolean value that specifies whether the provider is implemented in software.
		/// </summary>
		public Boolean IsSoftware { get; private set; }
		/// <summary>
		/// Gets a Boolean value that specifies whether the token that contains the key can be removed.
		/// </summary>
		public Boolean IsRemovable { get; private set; }
		/// <summary>
		/// Gets a Boolean value that specifies whether the provider is a smart card provider.
		/// </summary>
		public Boolean IsSmartCard { get; private set; }
		/// <summary>
		/// Gets a Boolean value that specifies whether the provider is a Cryptography API: Next Generation (CNG)
		/// provider or a CryptoAPI (legacy) CSP.
		/// </summary>
		public Boolean IsLegacy { get; private set; }
		/// <summary>
		/// Gets a Boolean value that specifies whether the provider supports a hardware random number generator
		/// that can be used to create random bytes for cryptographic operations.
		/// </summary>
		public Boolean HardwareRNG { get; private set; }
		/// <summary>
		/// Gets the maximum supported length for the name of the private key container associated with the provider.
		/// </summary>
		public Int32 KeyContainerLength { get; private set; }
		/// <summary>
		/// Gets a value that specifies the intended use of the algorithms supported by the provider.
		/// </summary>
		public X509KeySpecFlags KeySpec { get; private set; }
		/// <summary>
		/// Gets the version number of the provider.
		/// </summary>
		public Int32 Version { get; private set; }
		/// <summary>
		/// Gets a Boolean value that specifies whether the provider is installed on the client computer.
		/// </summary>
		public Boolean IsValid { get; private set; }
	}
}
