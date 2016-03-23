namespace System.Security.Cryptography.X509Certificates {
	/// <summary>
	///		<strong>X509SubjectAlternativeNamesExtension</strong> represents a X.509 alternative names extension.
	///		The subject alternative name extension allows identities to be bound to the subject of the certificate.
	///		These identities may be included in addition to or in place of the identity in the subject field of
	///		the certificate.
	/// </summary>
	public sealed class X509SubjectAlternativeNamesExtension : X509Extension {
		readonly Oid oid = new Oid("2.5.29.17");
		X509AlternativeNameCollection alternativeNames = new X509AlternativeNameCollection();

		internal X509SubjectAlternativeNamesExtension(Byte[] rawData, Boolean critical)
            : base("2.5.29.17", rawData, critical) {
			if (rawData == null) { throw new ArgumentNullException("rawData"); }
			m_decode(rawData);
		}

		/// <summary>
		///		Initializes a new instance of the <strong>X509SubjectAlternativeNamesExtension</strong> class using an
		///		<see cref="AsnEncodedData"/> object and a value that identifies whether the extension is critical.
		/// </summary>
		/// <param name="altNames">The encoded data to use to create the extension.</param>
		/// <param name="critical">
		///		<strong>True</strong> if the extension is critical; otherwise, <strong>False</strong>.
		/// </param>
		public X509SubjectAlternativeNamesExtension(AsnEncodedData altNames, Boolean critical) : this(altNames.RawData, critical) { }
		/// <summary>
		///		Initializes a new instance of the <strong>X509SubjectAlternativeNamesExtension</strong> class using a
		///		collection of alternative names and a value that identifies whether the extension is critical.
		/// </summary>
		/// <param name="altNames">A collection of alternative name objects.</param>
		/// <param name="critical">
		///		<strong>True</strong> if the extension is critical; otherwise, <strong>False</strong>.
		/// </param>
		public X509SubjectAlternativeNamesExtension(X509AlternativeNameCollection altNames, Boolean critical) {
			if (altNames.Count == 0) { throw new ArgumentException("Empty arrays are not supported."); }
			m_initizlize(altNames, critical);
		}
		
		/// <summary>
		/// Gets an array of alternative names.
		/// </summary>
		public X509AlternativeNameCollection AlternativeNames {
			get {
				X509AlternativeNameCollection retValue = new X509AlternativeNameCollection();
				foreach (X509AlternativeName item in alternativeNames) {
					retValue.Add(item);
				}
				return retValue;
			}
		}

		void m_initizlize(X509AlternativeNameCollection altNames, Boolean critical) {
			Critical = critical;
			Oid = oid;
			RawData = altNames.Encode();
			alternativeNames = altNames;
		}
		void m_decode(Byte[] rawData) {
            alternativeNames.Decode(rawData);
        }
	}
}
