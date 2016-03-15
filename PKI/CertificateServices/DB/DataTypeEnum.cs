namespace PKI.CertificateServices.DB {
	/// <summary>
	/// Contains possible datatypes to store the data in Certification Authority's database.
	/// </summary>
	public enum DataTypeEnum {
		/// <summary>
		/// Signed long data
		/// </summary>
		Long		= 1,
		/// <summary>
		/// Date/time
		/// </summary>
		DateTime	= 2,
		/// <summary>
		/// Binary data
		/// </summary>
		Binary		= 3,
		/// <summary>
		/// Unicode string data
		/// </summary>
		String		= 4
	}
}
