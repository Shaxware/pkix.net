using CERTENROLLLib;
using System;

namespace PKI.ServiceProviders {
	/// <summary>
	/// The ProviderAlgorithm interface represents an algorithm implemented by a cryptographic provider. Providers
	/// are separate modules that implement encryption, hashing, signing, and key exchange (archival) algorithms.
	/// Similar providers are grouped together in a type.
	/// </summary>
	/// <remarks>
	///		This class has no public constructors. Instead, use <see cref="Csp.EnumProviders"/> method to access this object.
	/// </remarks>
	public class ProviderAlgorithm {
		internal ProviderAlgorithm(ICspAlgorithm alg) {
			Name = alg.Name;
			LongName = alg.LongName;
			AlgorithmType = (AlgorithmTypeEnum)alg.Type;
			AlgorithmOperations = (AlgorithmOperationsEnum)alg.Operations;
			DefaultLength = alg.DefaultLength;
			MinLength = alg.MinLength;
			MaxLength = alg.MaxLength;
			IncrementLength = alg.IncrementLength;
			IsValid = alg.Valid;
		}

		/// <summary>
		/// Gets the abbreviated algorithm name.
		/// </summary>
		public String Name { get; private set; }
		/// <summary>
		/// Gets the full name of the algorithm.
		/// </summary>
		public String LongName { get; private set; }
		/// <summary>
		/// Gets the algorithm type.
		/// </summary>
		public AlgorithmTypeEnum AlgorithmType { get; private set; }
		/// <summary>
		/// Gets the operations that can be performed by the algorithm.
		/// </summary>
		public AlgorithmOperationsEnum AlgorithmOperations { get; private set; }
		/// <summary>
		/// Gets the default length of a key.
		/// </summary>
		public Int32 DefaultLength { get; private set; }
		/// <summary>
		/// Gets the minimum permitted length for a key.
		/// </summary>
		public Int32 MinLength { get; private set; }
		/// <summary>
		/// Gets the maximum permitted length for a key.
		/// </summary>
		public Int32 MaxLength { get; private set; }
		/// <summary>
		/// Gets a value, in bits, that can be used to determine valid incremental key lengths for algorithms that
		/// support multiple key sizes.
		/// </summary>
		public Int32 IncrementLength { get; private set; }
		/// <summary>
		/// Gets a Boolean value that specifies whether the algorithm object is valid.
		/// </summary>
		public Boolean IsValid { get; private set; }
	}
}
