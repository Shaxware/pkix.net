using System;

namespace PKI.ServiceProviders {
	/// <summary>
	/// This class is used to store information about cryptographic algorithm.
	/// </summary>
	public class ALG_ID_CNG {
		internal ALG_ID_CNG(String name, String pinterface, String[] operations) {
			Name = name;
			Interface = pinterface;
			Operations = operations;
		}

		/// <summary>
		/// Gets algorithm name.
		/// </summary>
		public string Name { get; private set; }

		/// <summary>
		/// Gets interface type supported by the algorithm.
		/// </summary>
		public string Interface { get; private set; }

		/// <summary>
		/// Gets optations for which the current algorithm is intended.
		/// </summary>
		public string[] Operations { get; private set; }
	}
}
