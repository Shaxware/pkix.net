using System;

namespace PKI.ServiceProviders {
	/// <summary>
	/// This class is used to store information about particular cryptographic algorithm.
	/// </summary>
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
		public string Name { get; private set; }
		/// <summary>
		/// Gets supported algorithm full name.
		/// </summary>
		public string FullName { get; private set; }
		/// <summary>
		/// Gets protocol list supported by the current algorithm.
		/// </summary>
		public string[] Protocols { get; private set; }
		/// <summary>
		/// Gets default key length for current algorithm.
		/// </summary>
		public uint DefaultKeyLength { get; private set; }
		/// <summary>
		/// Gets minimum key length supported by the current algorithm.
		/// </summary>
		public uint MinKeyLength { get; private set; }
		/// <summary>
		/// Gets maximum key length supported by the current algorithm. 
		/// </summary>
		public uint MaxKeyLength { get; private set; }
		/// <summary>
		/// Gets algorithm ID (CryptoAPI internal algorithm code).
		/// </summary>
		public uint ID { get; private set; }
	}
}
