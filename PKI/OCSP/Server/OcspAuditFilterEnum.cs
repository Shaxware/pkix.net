using System;

namespace PKI.OCSP.Server {
	/// <summary>
	/// Containts enumeration of possible Online Responder audit options.
	/// <para>This enumeration has a <see cref="FlagsAttribute"/> attribute that allows a bitwise combination of its member values.</para>
	/// </summary>
	[Flags]
	public enum OcspAuditFilterEnum {
		/// <summary>
		/// Nothing is audited.
		/// </summary>
		None				= 0,
		/// <summary>
		/// Audit OCSP service start/stop.
		/// </summary>
		ServiceStartStop	= 1,
		/// <summary>
		/// Audit changes to the OCSP configuration.
		/// </summary>
		ConfigurationChange	= 2,
		/// <summary>
		/// Autdit requests submitted to the OCSP.
		/// </summary>
		IncomingRequest		= 4,
		/// <summary>
		/// Audit changes to the OCSP security settings.
		/// </summary>
		SecurityChange		= 8
	}
}
