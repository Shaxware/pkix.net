using System;

namespace PKI.CertificateServices.DB {
	/// <summary>
	/// Represents Certificate Authority database column value.
	/// </summary>
	class AdcsDbValue {
		/// <summary>
		/// Gets or sets the data type associated with the value. The following type mapping is used:
		/// <list type="table">
		/// <listheader>
		///		<term>Db Data Type</term>
		///		<description>CLR Type</description>
		/// </listheader>
		/// <item>
		///		<term>Long</term>
		///		<description>System.Int32</description>
		/// </item>
		/// <item>
		///		<term>DateTime</term>
		///		<description>System.DateTime</description>
		/// </item>
		/// <item>
		///		<term>Binary</term>
		///		<description>System.Byte[]</description>
		/// </item>
		/// <item>
		///		<term>String</term>
		///		<description>System.String</description>
		/// </item>
		/// </list>
		/// </summary>
		public DataTypeEnum Type { get; set; }
		/// <summary>
		/// Gets or sets column value.
		/// </summary>
		public Object Value { get; set; }
	}
}
