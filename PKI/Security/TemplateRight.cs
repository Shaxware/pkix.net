using System;

namespace PKI.Security {
	/// <summary>
	/// Contains certificate template permission enumeration.
	/// <para>This enumeration has a <see cref="FlagsAttribute"/> attribute that allows a bitwise combination of its member values.</para>
	/// </summary>
	[Flags]
	public enum TemplateRight {
		/// <summary>
		/// The caller has all permissions on the object.
		/// </summary>
		FullControl,
		/// <summary>
		/// The caller has read-only permissions on the object.
		/// </summary>
		Read,
		/// <summary>
		/// The caller has write permissions on the object. This includes object deletion permissions.
		/// </summary>
		Write,
		/// <summary>
		/// The caller can enroll a certificate.
		/// </summary>
		Enroll,
		/// <summary>
		/// The caller can autoenroll a certificate.
		/// </summary>
		Autoenroll
	}
}
