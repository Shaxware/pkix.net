using CERTENROLLLib;
using PKI.Utils;
using System;
using System.DirectoryServices;
using System.Globalization;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace PKI.CertificateTemplates {
	/// <summary>
	/// Represents a certificate template object.
	/// </summary>
	public class CertificateTemplate {
		Int32 major, minor, flags;
		static readonly String _baseDsPath = $"CN=Certificate Templates, CN=Public Key Services, CN=Services,{ActiveDirectory.ConfigContext}";

		internal CertificateTemplate(IX509CertificateTemplate template) {
			initializeCom(template);
			Settings = new CertificateTemplateSettings(template);
		}
		/// <param name="name">Specifies the certificate template name.</param>
		public CertificateTemplate(String name) : this("Name", name) { }
		/// <param name="findType">
		/// Specifies certificate template search type. The search type can be either:
		/// Name, DisplayName or OID.
		/// </param>
		/// <param name="findValue">
		/// Specifies search pattern for a type specifed in <strong>findType</strong> argument.
		/// </param>
		/// <remarks>Wildcards are not allowed.</remarks>
		public CertificateTemplate(String findType, String findValue) {
			if (!ActiveDirectory.Ping()) { throw new Exception(Error.E_DCUNAVAILABLE); }
			m_initialize(findType, findValue);
		}

		/// <summary>
		/// Gets certificate template common name. Common names cannot contain the following characters: " + , ; &lt; = &gt;
		/// </summary>
		public String Name { get; private set; }
		/// <summary>
		/// Gets certificate template display name. Display name has no character restrictions.
		/// </summary>
		public String DisplayName { get; private set; }
		/// <summary>
		/// Gets certificate template internal version. The version consist of two values separated by dot: major version and minor version.
		/// Any template changes causes internal version change.
		/// </summary>
		/// <remarks>Template internal version is not changed if you modify template ACL only.</remarks>
		public String Version => $"{major}.{minor}";

		/// <summary>
		/// Gets certificate template schema version (also known as template version). The value can be either 1, 2, 3 or 4. For template support
		/// by CA version see <see cref="SupportedCA"/> property description.
		/// </summary>
		public Int32 SchemaVersion { get; private set; }
		/// <summary>
		/// This flag indicates whether clients can perform autoenrollment for the specified template.
		/// </summary>
		public Boolean AutoenrollmentAllowed => SchemaVersion > 1 && (flags & (Int32)CertificateTemplateFlags.Autoenrollment) > 0;

		/// <summary>
		/// Gets certificate template's object identifier. Object identifiers are used to uniquely identify certificate template. While
		/// certificate template common and display names can be changed, OID remains the same. Once template is deleted from
		/// Active Directory, associated OID is removed too. Any new template (even if with the same name values) will have differen
		/// OID value.
		/// </summary>
		public Oid OID { get; private set; }
		/// <summary>
		/// Gets the timestamp when certificate template was edited last time. The value can be used for audit purposes.
		/// </summary>
		public DateTime LastWriteTime { get; private set; }
		/// <summary>
		/// Gets certificate template's full distinguished name (location address) in Active Directory.
		/// </summary>
		public String DistinguishedName { get; private set; }
		/// <summary>
		/// Gets the minimum version of the Certification Authority that can use this template to issue certificates. The following table
		/// describes template support by CA version:
		/// <list type="table">
		/// <listheader>
		/// <term>Schema version</term>
		/// <description>Supported CA versions</description>
		/// </listheader>
		/// <item><term>1</term>
		/// <description><list type="bullet">
		/// <item>Windows 2000 Server</item>
		/// <item>Windows Server 2003 Standard, Enterprise, Datacenter editions</item>
		/// <item>Windows Server 2008 Standard, Enterprise, Datacenter editions</item>
		/// <item>Windows Server 2008 R2 Standard, Enterprise, Datacenter editions</item>
		/// <item>Windows Server 2012 Foundation, Essentials, Standard, Datacenter editions</item>
		/// </list></description>
		/// </item>
		/// <item><term>2</term>
		/// <description><list type="bullet">
		/// <item>Windows Server 2003 Enterprise, Datacenter editions</item>
		/// <item>Windows Server 2008 Enterprise, Datacenter editions</item>
		/// <item>Windows Server 2008 R2 Standard, Enterprise, Datacenter editions</item>
		/// <item>Windows Server 2012 Foundation, Essentials, Standard, Datacenter editions</item>
		/// </list></description>
		/// </item>
		/// <item><term>3</term>
		/// <description><list type="bullet">
		/// <item>Windows Server 2008 Enterprise, Datacenter editions</item>
		/// <item>Windows Server 2008 R2 Standard, Enterprise, Datacenter editions</item>
		/// <item>Windows Server 2012 Foundation, Essentials, Standard, Datacenter editions</item>
		/// </list></description>
		/// </item>
		/// <item><term>4</term>
		/// <description><list type="bullet">
		/// <item>Windows Server 2012 Foundation, Essentials, Standard, Datacenter editions</item>
		/// </list></description>
		/// </item>
		/// </list>
		/// </summary>
		public String SupportedCA {
			get {
				switch (SchemaVersion) {
					case 1: return "Windows 2000 Server";
					case 2: return "Windows Server 2003 Enterprise Edition";
					case 3: return "Windows Server 2008 Enterprise Edition";
					case 4: return "Windows Server 2012";
					default: return null;
				}
			}
		}
		/// <summary>
		/// Gets or sets certificate template extended settings.
		/// </summary>
		public CertificateTemplateSettings Settings { get; private set; }

		void m_initialize(String findType, String findValue) {
			switch (findType.ToLower()) {
				case "name":
					String cn = $"CN={escapeChars(findValue)},{_baseDsPath}";
					DirectoryEntry entry = new DirectoryEntry("LDAP://" + cn);
					m_fillproperties(entry);
					break;
				case "displayname":
					cn = _baseDsPath;
					DirectoryEntries entries = ActiveDirectory.GetChildItems(cn);
					foreach (DirectoryEntry item in entries.Cast<DirectoryEntry>().Where(item => String.Equals((String)item.Properties["displayName"].Value, findValue, StringComparison.CurrentCultureIgnoreCase))) {
						m_fillproperties(item);
					}
					break;
				case "oid":
					cn = _baseDsPath;
					entries = ActiveDirectory.GetChildItems(cn);
					foreach (DirectoryEntry item in entries.Cast<DirectoryEntry>().Where(item => (String)item.Properties["msPKI-Cert-Template-OID"].Value == findValue)) {
						m_fillproperties(item);
					}
					break;
				default: throw new Exception("The value for 'findType' must be either 'Name', 'DisplayName' or 'OID'.");
			}
		}
		void m_fillproperties(DirectoryEntry entry) {
			flags = (Int32)entry.Properties["flags"].Value;
			Name = (String)entry.Properties["cn"].Value;
			DisplayName = (String)entry.Properties["displayName"].Value;
			major = (Int32)entry.Properties["Revision"].Value;
			minor = (Int32)entry.Properties["msPKI-Template-Minor-Revision"].Value;
			SchemaVersion = (Int32)entry.Properties["msPKI-Template-Schema-Version"].Value;
			OID = new Oid((String)entry.Properties["msPKI-Cert-Template-OID"].Value);
			LastWriteTime = (DateTime)entry.Properties["WhenChanged"].Value;
			DistinguishedName = (String)entry.Properties["distinguishedName"].Value;
			Settings = new CertificateTemplateSettings(entry);
		}
		void initializeCom(IX509CertificateTemplate template) {
			Name = (String)template.Property[EnrollmentTemplateProperty.TemplatePropCommonName];
			DisplayName = (String)template.Property[EnrollmentTemplateProperty.TemplatePropFriendlyName];
			OID = new Oid(((IObjectId)template.Property[EnrollmentTemplateProperty.TemplatePropOID]).Value);
			if (CryptographyUtils.TestOleCompat()) {
				major = (Int32)template.Property[EnrollmentTemplateProperty.TemplatePropMajorRevision];
				minor = (Int32)template.Property[EnrollmentTemplateProperty.TemplatePropMinorRevision];
				SchemaVersion = (Int32)template.Property[EnrollmentTemplateProperty.TemplatePropSchemaVersion];
			} else {
				major = Convert.ToInt32((UInt32)template.Property[EnrollmentTemplateProperty.TemplatePropMajorRevision]);
				minor = Convert.ToInt32((UInt32)template.Property[EnrollmentTemplateProperty.TemplatePropMinorRevision]);
				SchemaVersion = Convert.ToInt32((UInt32)template.Property[EnrollmentTemplateProperty.TemplatePropSchemaVersion]);
			}
		}
		static String escapeChars(String inputStr) {
			return inputStr
				.Replace(@"\", @"\\")
				.Replace(",", @"\,")
				.Replace("/",@"\/")
				.Replace("#", @"\#")
				.Replace("+", @"\+")
				.Replace("<", @"\<")
				.Replace(">", @"\>")
				.Replace(";", @"\;")
				.Replace("\"", "\\\"")
				.Replace("=", @"\=");
		}

		/// <summary>
		/// Enumerates certificate templates registered in Active Directory.
		/// </summary>
		/// <returns>An array of certificate templates.</returns>
		public static CertificateTemplate[] EnumTemplates() {
			if (ActiveDirectory.Ping()) {
				String cn = _baseDsPath;
				DirectoryEntries entries = ActiveDirectory.GetChildItems(cn);
				return (from DirectoryEntry item in entries select new CertificateTemplate("name", (String) item.Properties["cn"].Value)).ToArray();
			}
			throw new Exception(Error.E_DCUNAVAILABLE);
		}

		/// <summary>
		/// Compares two <strong>CertificateTemplate</strong> objects for equality.
		/// </summary>
		/// <param name="other">An <strong>CertificateTemplate</strong> object to compare to the current object.</param>
		/// <returns>
		/// <strong>True</strong> if the current <strong>CertificateTemplate</strong> object is equal to the object specified by the other parameter;
		/// otherwise, <strong>False</strong>.
		/// </returns>
		/// <remarks>
		/// Two objects are considered equal if they are <strong>CertificateTemplate</strong> objects and they have the same
		/// name and OID values.
		/// </remarks>
		public override Boolean Equals(Object other) {
			if (ReferenceEquals(null, other) || other.GetType() != GetType()) { return false; }
			return ReferenceEquals(this, other) || Equals((CertificateTemplate) other);
		}
		/// <summary>
		/// Compares two <strong>CertificateTemplate</strong> objects for equality.
		/// </summary>
		/// <param name="other">An <strong>CertificateTemplate</strong> object to compare to the current object.</param>
		/// <returns>
		/// <strong>True</strong> if the current <strong>CertificateTemplate</strong> object is equal to the object specified by the other parameter;
		/// otherwise, <strong>False</strong>.
		/// </returns>
		/// <remarks>
		/// Two objects are considered equal if they are <strong>CertificateTemplate</strong> objects and they have the same
		/// name and OID values.
		/// </remarks>
		protected bool Equals(CertificateTemplate other) {
			return String.Equals(Name, other.Name) && OID.Equals(other.OID);
		}
		/// <summary>
		/// Serves as a hash function for a particular type.
		/// </summary>
		/// <returns>The hash code for the certificate template as an integer.</returns>
		public override Int32 GetHashCode() {
			unchecked { return (Name.GetHashCode() * 397) ^ OID.GetHashCode(); }
		}
		/// <summary>
		/// Gets certificate template textual representation.
		/// </summary>
		/// <returns>Certificate template textual representation.</returns>
		public String Format() {
			String nl = Environment.NewLine;
			StringBuilder SB = new StringBuilder();
			SB.Append($"[General Settings]{nl}");
			SB.Append($"  Common name: {Name}{nl}");
			SB.Append($"  Display name: {DisplayName}{nl}");
			SB.Append($"  Version: {Version}{nl}");
			SB.Append($"  Supported CA: {SupportedCA}{nl}");
			SB.Append($"  Subject type: {Settings.SubjectType}{nl}");
			SB.Append((Settings.EnrollmentOptions & (Int32) CertificateTemplateEnrollmentFlags.DsPublish) > 0
				? $"  Publish to DS: True{nl}"
				: $"  Publish to DS: False{nl}");
			SB.Append((Settings.EnrollmentOptions & (Int32) CertificateTemplateEnrollmentFlags.AutoenrollmentCheckDsCert) > 0
				? $"  Check for existing certificate in DS: True{nl}"
				: $"  Check for existing certificate in DS: False{nl}");
			SB.Append((Settings.EnrollmentOptions & (Int32) CertificateTemplateEnrollmentFlags.ReuseKeyTokenFull) > 0
				? $"  Reuse key when tokein is full: True{nl}"
				: $"  Reuse key when tokein is full: False{nl}");
			SB.Append($"[Subject]{nl}");
			SB.Append($"  {Settings.SubjectName}{nl}");
			SB.Append(Settings.Cryptography + nl);
			SB.Append(Settings.RegistrationAuthority + nl);
			SB.Append(Settings.KeyArchivalSettings + nl);
			SB.Append($"[Superseded Templates]{nl}");
			if (Settings.SupersededTemplates == null) {
				SB.Append($"  None{nl}");
			} else {
				foreach(String template in Settings.SupersededTemplates) {
					SB.Append($"  {template}{nl}");
				}
			}
			SB.Append($"[Extensions]{nl}");
			foreach (X509Extension ext in Settings.Extensions) {
				SB.Append($"  Extension name:{nl}    {ext.Oid.FriendlyName}{nl}");
				SB.Append($"  Extension value:{nl}    {ext.Format(true).Replace("\r\n","\r\n    ")}{nl}");
			}
			SB.Append(nl);
			return SB.ToString();
		}
	}
}
