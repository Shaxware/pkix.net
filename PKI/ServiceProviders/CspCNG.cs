using System;

namespace PKI.ServiceProviders {
	/// <summary>
	/// Represents single KSP (Key Storage Provider) information.
	/// </summary>
	public class CspCNG {
		string pname, pcomments;
		ALG_ID_CNGCollection algs;
		internal CspCNG(String name, String comments, ALG_ID_CNGCollection supportedAlgorithms) {
			pname = name;
			pcomments = comments;
			algs = supportedAlgorithms;
		}
		/// <summary>
		/// Gets provider name.
		/// </summary>
		public string Name {
			get { return pname; }
		}
		/// <summary>
		/// Gets optional comments about the provider.
		/// </summary>
		public string Comments {
			get { return pcomments; }
		}
		/// <summary>
		/// Gets algorithms supported by the provider.
		/// </summary>
		public ALG_ID_CNGCollection SupportedAlgorithms {
			get { return algs; }
		}
	}
}
