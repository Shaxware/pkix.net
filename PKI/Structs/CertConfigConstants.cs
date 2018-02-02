using System;

namespace PKI.Structs {
	class CertConfigConstants {
		#region ICertConfig.GetConfig Types
		public const Int32 CcDefaultConfig				= 0;
		public const Int32 CcUIpickConfig				= 1;
		public const Int32 CcFirstConfig				= 2;
		public const Int32 CcLocalConfig				= 3;
		public const Int32 CcLocalActiveConfig			= 4;
		public const Int32 CcUIpickSkipLocalCaConfig	= 5;
		#endregion

		#region ICertConfig.GetField 
		public const String FieldAuthority			= "Authority";
		public const String FieldCommonName			= "CommonName";
		public const String FieldConfig				= "Config";
		public const String FieldCountry			= "Country";
		public const String FieldDescription		= "Description";
		public const String FieldExchangeCert		= "ExchangeCertificate";
		public const String FieldFlags				= "Flags";
		public const String FieldLocality			= "Locality";
		public const String FieldOrganization		= "Organization";
		public const String FieldOrgUnit			= "OrgUnit";
		public const String FieldSanitizedName		= "SanitizedName";
		public const String FieldSanitizedShortName	= "SanitizedShortName";
		public const String FieldServer				= "Server";
		public const String FieldShortName			= "ShortName";
		public const String FieldSigningCert		= "SignatureCertificate";
		public const String FieldProvince			= "State";
		public const String FieldEnrollmentServers	= "WebEnrollmentServers";
		#endregion

		#region ICertConfig Flags
		public const Int32 CAIF_DSENTRY				= 0x00000001; // bit set for CA from DS
		public const Int32 CAIF_SHAREDFOLDERENTRY	= 0x00000002; // CA from shared folder
		public const Int32 CAIF_REGISTRY			= 0x00000004; // CA from local registry
		public const Int32 CAIF_LOCAL				= 0x00000008; // local CA
		public const Int32 CAIF_REGISTRYPARENT		= 0x00000010; // CA parent from registry
		#endregion
	}
}
