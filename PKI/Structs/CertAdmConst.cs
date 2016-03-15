using System;

namespace PKI.Structs {
	class CertAdmConst {
		#region ICertAdmin2 PropID
		public const Int32 CR_PROP_FILEVERSION				= 0x00000001; // CA File Version
		public const Int32 CR_PROP_PRODUCTVERSION			= 0x00000002; // CA Product Version
		public const Int32 CR_PROP_EXITCOUNT				= 0x00000003; // Exit Count
		public const Int32 CR_PROP_EXITDESCRIPTION			= 0x00000004; // Exit Description
		public const Int32 CR_PROP_POLICYDESCRIPTION		= 0x00000005; // Policy Description
		public const Int32 CR_PROP_CANAME					= 0x00000006; // Certification Authority Name
		public const Int32 CR_PROP_SANITIZEDCANAME			= 0x00000007; // Sanitized CA Name
		public const Int32 CR_PROP_SHAREDFOLDER				= 0x00000008; // Shared Folder Path
		public const Int32 CR_PROP_PARENTCA					= 0x00000009; // Parent CA Name
		public const Int32 CR_PROP_CATYPE					= 0x0000000A; // CA Type
		public const Int32 CR_PROP_CASIGCERTCOUNT			= 0x0000000B; // CA Signature Certificate Count
		public const Int32 CR_PROP_CASIGCERT				= 0x0000000C; // CA Signature Certificate
		public const Int32 CR_PROP_CASIGCERTCHAIN			= 0x0000000D; // CA signing certificate Chain
		public const Int32 CR_PROP_CAXCHGCERTCOUNT			= 0x0000000E; // CA Exchange Certificate Count
		public const Int32 CR_PROP_CAXCHGCERT				= 0x0000000F; // CA Exchange Certificate
		public const Int32 CR_PROP_CAXCHGCERTCHAIN			= 0x00000010; // CA Exchange Certificate Chain
		public const Int32 CR_PROP_BASECRL					= 0x00000011; // Base CRL
		public const Int32 CR_PROP_DELTACRL					= 0x00000012; // Delta CRL
		public const Int32 CR_PROP_CACERTSTATE				= 0x00000013; // CA Signing Certificates State
		public const Int32 CR_PROP_CRLSTATE					= 0x00000014; // CA CRL State
		public const Int32 CR_PROP_CAPROPIDMAX				= 0x00000015; // Maximum Property ID
		public const Int32 CR_PROP_DNSNAME					= 0x00000016; // CA Fully Qualified DNS
		public const Int32 CR_PROP_ROLESEPARATIONENABLED	= 0x00000017; // Role Separated Enabled
		public const Int32 CR_PROP_KRACERTUSEDCOUNT			= 0x00000018; // Count Of Required KRAs For Archival
		public const Int32 CR_PROP_KRACERTCOUNT				= 0x00000019; // Count Of Registered KRAs
		public const Int32 CR_PROP_KRACERT					= 0x0000001A; // KRA Certificate
		public const Int32 CR_PROP_KRACERTSTATE				= 0x0000001B; // KRA Certificates State
		public const Int32 CR_PROP_ADVANCEDSERVER			= 0x0000001C; // Advanced Server
		public const Int32 CR_PROP_TEMPLATES				= 0x0000001D; // Configured Certificate Templates
		public const Int32 CR_PROP_BASECRLPUBLISHSTATUS		= 0x0000001E; // Base CRL Publishing Status
		public const Int32 CR_PROP_DELTACRLPUBLISHSTATUS	= 0x0000001F; // Delta CRL Publishing State
		public const Int32 CR_PROP_CASIGCERTCRLCHAIN		= 0x00000020; // CA Signing Certificate Chain and CRL
		public const Int32 CR_PROP_CAXCHGCERTCRLCHAIN		= 0x00000021; // CA Exchange Certificate Chain and CRL
		public const Int32 CR_PROP_CACERTSTATUSCODE			= 0x00000022; // CA Signing Certificate Status
		public const Int32 CR_PROP_CAFORWARDCROSSCERT		= 0x00000023; // CA Forward Cross Certificate
		public const Int32 CR_PROP_CABACKWARDCROSSCERT		= 0x00000024; // CA Backward Cross Certificate
		public const Int32 CR_PROP_CAFORWARDCROSSCERTSTATE	= 0x00000025; // CA Forward Cross Certificate State
		public const Int32 CR_PROP_CABACKWARDCROSSCERTSTATE	= 0x00000026; // CA Backward Cross Certificate State
		public const Int32 CR_PROP_CACERTVERSION			= 0x00000027; // CA Signing Certificates Revisions
		public const Int32 CR_PROP_SANITIZEDCASHORTNAME		= 0x00000028; // CA Sanitized Short Name
		public const Int32 CR_PROP_CERTCDPURLS				= 0x00000029; // CRL Distribution Points
		public const Int32 CR_PROP_CERTAIAURLS				= 0x0000002A; // Authority Information Access
		public const Int32 CR_PROP_CERTAIAOCSPRLS			= 0x0000002B; // OCSP URLs
		public const Int32 CR_PROP_LOCALENAME				= 0x0000002C; // CA Locale Name
		public const Int32 CR_PROP_SUBJECTTEMPLATE_OIDS		= 0x0000002D; // Subject Template
		#endregion

		#region ICertAdmin2 PropType
		public const Int32 PROPTYPE_LONG	= 1;
		public const Int32 PROPTYPE_DATE	= 2;
		public const Int32 PROPTYPE_BINARY	= 3;
		public const Int32 PROPTYPE_STRING	= 4;
		#endregion

		#region KRA disposition
		public const Int32 KRA_DISP_EXPIRED		= 0x00000000; // The certificate has expired
		public const Int32 KRA_DISP_NOTFOUND	= 0x00000001; // The certificate was not found
		public const Int32 KRA_DISP_REVOKED		= 0x00000002; // The certificate has been revoked
		public const Int32 KRA_DISP_VALID		= 0x00000003; // The certificate is valid
		public const Int32 KRA_DISP_NOTLOADED	= 0x00000004; // The certificate is not loaded
		public const Int32 KRA_DISP_INVALID		= 0x00000005; // The certificate is invalid
		#endregion
	}
}
