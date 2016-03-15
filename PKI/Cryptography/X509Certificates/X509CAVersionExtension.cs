namespace System.Security.Cryptography.X509Certificates {
	sealed class X509CAVersionExtension : X509Extension {

		public X509CAVersionExtension() { }
		public X509CAVersionExtension(UInt32 caVersion, UInt32 keyVersion) {
			if (caVersion > 65535) { throw new ArgumentException("The 'caVersion' value is too big."); }
			if (keyVersion > 65535) { throw new ArgumentException("The 'keyVersion' value is too big."); }
			if (keyVersion > caVersion) { throw new ArgumentException("Key version must be less or equals to CA version."); }
			m_initialize(caVersion, keyVersion);
		}
		public X509CAVersionExtension(Byte[] rawData) { }

		public UInt32 CACertificateVersion { get; private set; }
		public UInt32 CAKeyVersion { get; private set; }

		void m_initialize(UInt32 caVersion, UInt32 keyVersion) {
			Oid = new Oid("1.3.6.1.4.1.311.21.1");
			CACertificateVersion = caVersion;
			CAKeyVersion = keyVersion;
			Critical = false;
			if (keyVersion == 0) {
				if (caVersion < 256) {
					RawData = new Byte[] { 2, 1, (Byte)caVersion };
				} else {
					Int32 padding = Convert.ToInt32(Math.Floor(caVersion / 256.0));
					Int32 value = (Int32)caVersion - padding * 256;
					RawData = padding > 127
						? new Byte[] { 2, 3, 0, (Byte)padding, (Byte)value }
						: new Byte[] { 2, 2, (Byte)padding, (Byte)value };
				}
			}
		}
		void m_decode(Byte[] rawData) {
			Oid = new Oid("1.3.6.1.4.1.311.21.1");
			RawData = rawData;
		}
	}
}
