using CERTADMINLib;
using PKI.Exceptions;
using PKI.Utils;
using System;
using System.ComponentModel;
using System.Security.Cryptography.X509Certificates;

namespace PKI.OCSP.Server {
	/// <summary>
	/// Represents a single revocation configuration assigned to Online Responder.
	/// </summary>
	public class OcspConfiguration : IDisposable {
		String configString, template;
		X509Certificate2 signingCertificate;
		OcspSigningFlags flags;
		readonly OnlineResponder _responder;
		readonly IOCSPAdmin _ocspAdmin;
		IOCSPCAConfiguration OcspConfig;

		internal OcspConfiguration(IOCSPCAConfiguration ocspconfig, OnlineResponder responder, IOCSPAdmin admin) {
			OcspConfig = ocspconfig;
			_responder = responder;
			_ocspAdmin = admin;
			IsDisposed = false;
			m_initialize();
		}

		/// <summary>
		/// Gets or sets revocation confguration display name.
		/// </summary>
		public String Name { get; private set; }
		/// <summary>
		/// Gets or sets configuration string for CA server associated with this configuration. Configuration string is composed in
		/// the form: ComputerName\SanitizedName.
		/// </summary>
		public String ConfigString {
			get { return configString; }
			set {
				if (OcspConfig == null || _responder == null) { throw new InvalidOperationException(); }
				OcspConfig.CAConfig = value;
				IsModified = true;
			}
		}
		/// <summary>
		/// Gets or sets CA certificate associated with this configuration.
		/// </summary>
		public X509Certificate2 CACertificate { get; private set; }
		/// <summary>
		/// Gets or sets signing certificate that is used to sign OCSP responses.
		/// </summary>
		public X509Certificate2 SigningCertificate {
			get { return signingCertificate; }
			set {
				if (OcspConfig == null || _responder == null) { throw new InvalidOperationException(); }
				if (signingCertificate.Thumbprint == value.Thumbprint) { return; }
				OcspConfig.SigningCertificate = value;
				signingCertificate = value;
				IsModified = true;
			}
		}
		/// <summary>
		/// Gets or sets signing certificate template.
		/// </summary>
		public String SigningCertificateTemplate {
			get { return template; }
			set {
				if (OcspConfig == null || _responder == null) { throw new InvalidOperationException(); }
				if (String.Equals(template, value, StringComparison.CurrentCultureIgnoreCase)) { return; }
				OcspConfig.SigningCertificateTemplate = value;
				template = value;
				IsModified = true;
			}
		}
		/// <summary>
		/// Gets the cryptographic service provider name used for this configuration.
		/// </summary>
		public String CSP { get; private set; }
		/// <summary>
		/// Gets KeySpec for the cryptographic service provider identified in the <see cref="CSP"/> property.
		/// </summary>
		public X509KeySpecFlags KeySpec { get; private set; }
		/// <summary>
		/// Gets or sets revocation provider and provider settings for the current configuration.
		/// </summary>
		public OcspRevocationProvider RevocationProvider { get; private set; }
		/// <summary>
		/// The <strong>SigningFlags</strong> property gets or sets a combination of flag values. These values specify the management
		///  of signing certificates that belong to a certification authority (CA) configuration.
		/// </summary>
		public OcspSigningFlags Signingflags {
			get { return flags; }
			set {
				if (OcspConfig == null) { throw new UninitializedObjectException(); }
				if (flags == value) { return; }
				OcspConfig.SigningFlags = (UInt32)value;
				flags = value;
				IsModified = true;
			}
		}
		/// <summary>
		/// Gets the status of the configuration. A zero value means good status and any non-zero value indicates an
		/// issue with the configuration. Refer to <see cref="StatusMessage"/> property for the issue reason.
		/// </summary>
		public Int32 StatusCode => unchecked((Int32)OcspConfig.ErrorCode);

		/// <summary>
		/// Gets the textual representation of the configuration status.
		/// </summary>
		public String StatusMessage => new Win32Exception(StatusCode).Message;

		/// <summary>
		/// Indicates whether the current object was changed after it was instantiated.
		/// </summary>
		public Boolean IsModified { get; private set; }
		/// <summary>
		/// Indicates whether the object is disposed.
		/// </summary>
		public Boolean IsDisposed { get; private set; }

		void m_initialize() {
			Name = OcspConfig.Identifier;
			try { configString = OcspConfig.CAConfig; }
			catch { configString = null; }
			CACertificate = new X509Certificate2((Byte[])OcspConfig.CACertificate);
			try { signingCertificate = new X509Certificate2((Byte[])OcspConfig.SigningCertificate); }
			catch { signingCertificate = null; }
			try { template = OcspConfig.SigningCertificateTemplate; }
			catch { template = null; }
			flags = (OcspSigningFlags)OcspConfig.SigningFlags;
			RevocationProvider = new OcspRevocationProvider(OcspConfig);
		}

		/// <summary>
		/// Writes configuration changes to the registry.
		/// </summary>
		public void SetInfo() {
			if (IsDisposed || _responder.IsDisposed) { throw new InvalidOperationException(); }
			try {
				_ocspAdmin.SetConfiguration(_responder.ComputerName, true);
			} catch (Exception e) {
				throw Error.ComExceptionHandler(e);
			}
		}
		/// <summary>
		/// Releases unmanaged resources held by the object.
		/// </summary>
		public void Dispose() {
			Name = null;
			configString = null;
			CACertificate = null;
			SigningCertificate = null;
			if (OcspConfig != null) {
				CryptographyUtils.ReleaseCom(OcspConfig);
				OcspConfig = null;
				IsDisposed = true;
			}
		}
	}
}
