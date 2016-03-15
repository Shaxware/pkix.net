using System;

namespace PKI.CertificateServices.DB {
	/// <summary>
	/// Represents Certification Authority database's table.
	/// </summary>
	public class Schema {

		internal Schema(String name, String displayname, DataTypeEnum datatype, Int32 maxlength, Boolean isindexed) {
			Name = name;
			DisplayName = displayname;
			DataType = datatype;
			MaxLength = maxlength;
			IsIndexed = isindexed;
		}

		/// <summary>
		/// Gets column name.
		/// </summary>
		public String Name { get; private set; }
		/// <summary>
		/// Gets column localized name.
		/// </summary>
		public String DisplayName { get; private set; }
		/// <summary>
		/// Gets data type for the data stored in the column.
		/// </summary>
		public DataTypeEnum DataType { get; private set; }
		/// <summary>
		/// Gets maximum data capacity for the column.
		/// </summary>
		public Int32 MaxLength { get; private set; }
		/// <summary>
		/// Indiciates whether the column is indexed (contains multiple items).
		/// </summary>
		public Boolean IsIndexed { get; private set; }
	}
}
