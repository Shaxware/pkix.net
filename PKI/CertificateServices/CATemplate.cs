using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using CERTADMINLib;
using PKI.CertificateTemplates;
using PKI.Exceptions;
using PKI.Structs;
using PKI.Utils;

namespace PKI.CertificateServices {
	/// <summary>
	/// Represents Certification Authority object with assigned certificate templates.
	/// </summary>
	public class CATemplate {
		String Version, ConfigString;

		/// <param name="certificateAuthority">Specifies an existing <see cref="CertificateServices"/> object.</param>
		/// <exception cref="UninitializedObjectException">An object in the <strong>certificateAuthority</strong> parameter is not initialized.</exception>
		/// <exception cref="ServerUnavailableException">The CA server specified in the <strong>certificateAuthority</strong> parameter could not be contacted via RPC/DCOM protocol.</exception>
		/// <exception cref="PlatformNotSupportedException">The CA server is not <strong>Enterprise  CA</strong>. Only Enterprise CAs support certificate templates.</exception>
		public CATemplate(CertificateAuthority certificateAuthority) {
			if (String.IsNullOrEmpty(certificateAuthority.Name)) { throw new UninitializedObjectException(); }
			m_initialize(certificateAuthority);
		}

		/// <summary>
		/// Gets the common name of the Certification Authority in a sanitized form as specified in
		/// <see href="http://msdn.microsoft.com/en-us/library/cc249826(PROT.10).aspx">MS-WCCE §3.1.1.4.1.1</see>.
		/// </summary>
		public String Name { get; private set; }
		/// <summary>
		/// Gets the display name of the Certification Authority (sanitized characters are decoded to textual characters).
		/// </summary>
		public String DisplayName { get; private set; }
		/// <summary>
		/// Gets the host fully qualified domain name (FQDN) of the server where Certification Authority is installed.
		/// </summary>
		public String ComputerName { get; private set; }
		/// <summary>
		/// Gets a list of assigned to the Certification Authority certificate templates.
		/// </summary>
		public CertificateTemplate[] Templates { get; private set; }
		/// <summary>
		/// Indiciates whether the object was modified after it was instantiated.
		/// </summary>
		public Boolean IsModified { get; private set; }

		void m_initialize(CertificateAuthority certificateAuthority) {
			if (!certificateAuthority.IsEnterprise) { throw new PlatformNotSupportedException(); }
			if (!certificateAuthority.Ping()) {
				ServerUnavailableException e = new ServerUnavailableException(certificateAuthority.DisplayName);
				e.Data.Add(nameof(e.Source), OfflineSource.DCOM);
				throw e;
			}
			Name = certificateAuthority.Name;
			DisplayName = certificateAuthority.DisplayName;
			ComputerName = certificateAuthority.ComputerName;
			Version = certificateAuthority.Version;
			ConfigString = certificateAuthority.ConfigString;

			CCertAdmin CertAdmin = new CCertAdmin();
			String templates = (String)CertAdmin.GetCAProperty(certificateAuthority.ConfigString, CertAdmConstants.CrPropTemplates, 0, CertAdmConstants.ProptypeString, 0);
			List<CertificateTemplate> tobeadded = new List<CertificateTemplate>();
			if (templates != String.Empty) {
				String[] SplitString = { "\n" };
				String[] TempArray = templates.Split(SplitString, StringSplitOptions.RemoveEmptyEntries);
				for (Int32 index = 0; index < TempArray.Length; index += 2) {
					tobeadded.Add(new CertificateTemplate("Name", TempArray[index]));
				}
				Templates = tobeadded.ToArray();
			} else {
				Templates = null;
			}
		}
		Boolean IsSupported(Int32 schemaVersion) {
			switch (Version) {
				case "2003":
					switch (schemaVersion) {
						case 1: return true;
						case 2:
							if (Version == "Enterprise" || Version == "Datacenter") { return true; }
							break;
					}
					break;
				case "2008":
					switch (schemaVersion) {
						case 1: return true;
						case 2:
							if (Version == "Enterprise" || Version == "Datacenter") { return true; }
							break;
						case 3:
							if (Version == "Enterprise" || Version == "Datacenter") { return true; }
							break;
					}
					break;
				case "2008R2" :
					if (schemaVersion < 4) { return true; }
					break;
				default: return true;
			}
			return false;
		}

		/// <summary>
		/// Adds certificate template to issue by a specified Certification Authority server. The method do not writes newly assigned
		/// templates to Certification Authority.
		/// </summary>
		/// <param name="template">An <see cref="CertificateTemplate"/> object to add.</param>
		/// <exception cref="ArgumentNullException">The <strong>template</strong> parameter is null reference.</exception>
		/// <exception cref="UninitializedObjectException">The object in the <strong>template</strong> parameter is not initialized.</exception>
		/// <returns><strong>True</strong> if certificate template is added; otherwise <strong>False</strong>.</returns>
		/// <remarks>
		/// This method returns <strong>False</strong> in the following circumstances:
		/// <list type="bullet">
		/// <item>Current CA server already contains specified certificate template in the issuance list.</item>
		/// <item>Specified certificate template is not supported by this CA version.</item>
		/// </list>
		/// If the method returns <strong>True</strong>, a <see cref="IsModified"/> property is set to <strong>True</strong>.
		/// </remarks>
		public Boolean Add(CertificateTemplate template) {
			if (template == null) { throw new ArgumentNullException(nameof(template)); }
			if (String.IsNullOrEmpty(template.Name)) { throw new UninitializedObjectException(); }
			List<CertificateTemplate> extemplates = new List<CertificateTemplate>(Templates);
			if (extemplates.Contains(template)) { return false; }
			if (!IsSupported(template.SchemaVersion)) { return false; }
			extemplates.Add(template);
			IsModified = true;
			Templates = extemplates.ToArray();
			return true;
		}
		/// <summary>
		/// Adds certificate templates to issue by a specified Certification Authority server. The method do not writes newly assigned
		/// templates to Certification Authority.
		/// </summary>
		/// <param name="templates">One or more <see cref="CertificateTemplate"/> objects to add.</param>
		/// <exception cref="ArgumentNullException">The <strong>templates</strong> parameter is a null reference.</exception>
		/// <exception cref="NotSupportedException">One or more certificate templates are not supported by this CA version.</exception>
		/// <remarks>If <see cref="Templates"/> property already contains certificate template object, the template is silently skipped.</remarks>
		public void AddRange(CertificateTemplate[] templates) {
			if (templates == null) { throw new ArgumentNullException(nameof(templates)); }
			List<CertificateTemplate> extemplates = new List<CertificateTemplate>(Templates);
			foreach (CertificateTemplate item in templates.Where(item => !extemplates.Contains(item))) {
				if (IsSupported(item.SchemaVersion)) {
					extemplates.Add(item);
					IsModified = true;
					Templates = extemplates.ToArray();
				} else { throw new NotSupportedException(Error.GetMessage(Error.TemplateNotSupportedException)); }
			}
		}
		/// <summary>
		/// Removes specified certificate template from CA server. This method do not remove certificate template itself.
		/// </summary>
		/// <param name="template">The template to remove.</param>
		/// <exception cref="ArgumentNullException">The <strong>template</strong> parameter is null reference.</exception>
		/// <exception cref="UninitializedObjectException">An object in the <strong>template</strong> parameter is not initialized.</exception>
		/// <returns><strong>True</strong> if the specified template was found and successfully removed, otherwise <strong>False</strong>.</returns>
		public Boolean Remove(CertificateTemplate template) {
			if (template == null) { throw new ArgumentNullException(nameof(template)); }
			if (String.IsNullOrEmpty(template.Name)) { throw new UninitializedObjectException(); }
			List<CertificateTemplate> extemplates = new List<CertificateTemplate>(Templates);
			if (!extemplates.Contains(template)) { return false; }
			extemplates.Remove(template);
			IsModified = true;
			Templates = extemplates.ToArray();
			return true;
		}
		/// <summary>
		/// Removes certificate templates from issuance by a specified Certification Authority server. The method do not writes updated
		/// template list to Certification Authority.
		/// </summary>
		/// <param name="templates">One or more <see cref="CertificateTemplates"/> objects to remove.</param>
		/// <exception cref="ArgumentNullException">The <strong>template</strong> parameter is null reference.</exception>
		/// <exception cref="UninitializedObjectException">An object in the <strong>template</strong> parameter is not initialized.</exception>
		/// <remarks>If the <see cref="Templates"/> property do not contains certificate template object, the template is silently skipped.</remarks>
		public void RemoveRange(CertificateTemplate[] templates) {
			if (templates == null) { throw new ArgumentNullException(nameof(templates)); }
			if (String.IsNullOrEmpty(Name)) { throw new UninitializedObjectException(); }
			List<CertificateTemplate> extemplates = new List<CertificateTemplate>(Templates);
			foreach (CertificateTemplate item in templates.Where(extemplates.Contains)) {
				extemplates.Remove(item);
				IsModified = true;
			}
			Templates = extemplates.ToArray();
		}
		/// <summary>
		/// Removes all certificate templates from issuance on current CA server.
		/// </summary>
		public void Clear() {
			Templates = new CertificateTemplate[0];
			IsModified = true;
		}
		/// <summary>
		/// Updates certificate template list issud by a Certification Authority. The method writes all certificates templates contained in
		/// <see cref="Templates"/> property.
		/// </summary>
		/// <exception cref="UnauthorizedAccessException">
		/// The caller do not have sufficient permissions to make changes in the CA configuration.
		/// </exception>
		/// <exception cref="ServerUnavailableException">
		/// The target CA server could not be contacted via RPC/DCOM transport.
		/// </exception>
		/// <exception cref="NotSupportedException">One or more certificate templates are not supported by this CA version.</exception>
		/// <remarks>
		/// For this method to succeed, the caller must be granted CA <strong>Administrator</strong> permissions.
		/// </remarks>
		/// <returns>
		/// <strong>True</strong> if configuration was changed. If an object was not modified since it was instantiated, configuration is not updated
		/// and the method returns <strong>False</strong>.
		/// </returns>
		/// <remarks>The caller must have <strong>Administrator</strong> permissions on the target CA server.</remarks>
		public Boolean SetInfo() {
			if (!IsModified) { return false; }
			if (!CertificateAuthority.Ping(ComputerName)) {
				ServerUnavailableException e = new ServerUnavailableException(DisplayName);
				e.Data.Add(nameof(e.Source), OfflineSource.DCOM);
				throw e;
			}
			CCertAdmin CertAdmin = new CCertAdmin();
			StringBuilder SB = new StringBuilder();
			if (Templates.Length > 0) {
				foreach (CertificateTemplate item in Templates) {
					SB.Append(item.Name + "\n");
					SB.Append(item.OID.Value + "\n");
				}
			}
			try {
				CertAdmin.SetCAProperty(ConfigString, CertAdmConstants.CrPropTemplates, 0, CertAdmConstants.ProptypeString, SB.ToString());
			} catch (Exception e) {
				throw Error.ComExceptionHandler(e);
			}
			IsModified = false;
			return true;
		}
	}
}
