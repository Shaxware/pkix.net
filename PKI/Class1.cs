using System;
using System.Collections.Generic;
using System.Text;

namespace PKI {
	/// <remarks/>
	[System.Xml.Serialization.XmlTypeAttribute(AnonymousType = true)]
	[System.Xml.Serialization.XmlRootAttribute(Namespace = "", IsNullable = false)]
	public partial class FCIV {

		private FCIVFILE_ENTRY[] fILE_ENTRYField;

		/// <remarks/>
		[System.Xml.Serialization.XmlElementAttribute("FILE_ENTRY")]
		public FCIVFILE_ENTRY[] FILE_ENTRY {
			get {
				return this.fILE_ENTRYField;
			}
			set {
				this.fILE_ENTRYField = value;
			}
		}
	}

	/// <remarks/>
	[System.Xml.Serialization.XmlTypeAttribute(AnonymousType = true)]
	public partial class FCIVFILE_ENTRY {

		private string nameField;

		private uint sizeField;

		private string timeStampField;

		private object mD5Field;

		private string sHA1Field;

		private object sHA256Field;

		private object sHA384Field;

		private object sHA512Field;

		/// <remarks/>
		public string name {
			get {
				return this.nameField;
			}
			set {
				this.nameField = value;
			}
		}

		/// <remarks/>
		public uint Size {
			get {
				return this.sizeField;
			}
			set {
				this.sizeField = value;
			}
		}

		/// <remarks/>
		public string TimeStamp {
			get {
				return this.timeStampField;
			}
			set {
				this.timeStampField = value;
			}
		}

		/// <remarks/>
		public object MD5 {
			get {
				return this.mD5Field;
			}
			set {
				this.mD5Field = value;
			}
		}

		/// <remarks/>
		public string SHA1 {
			get {
				return this.sHA1Field;
			}
			set {
				this.sHA1Field = value;
			}
		}

		/// <remarks/>
		public object SHA256 {
			get {
				return this.sHA256Field;
			}
			set {
				this.sHA256Field = value;
			}
		}

		/// <remarks/>
		public object SHA384 {
			get {
				return this.sHA384Field;
			}
			set {
				this.sHA384Field = value;
			}
		}

		/// <remarks/>
		public object SHA512 {
			get {
				return this.sHA512Field;
			}
			set {
				this.sHA512Field = value;
			}
		}
	}
}
