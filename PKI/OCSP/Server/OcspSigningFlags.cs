using System;

namespace PKI.OCSP.Server {
	/// <summary>
	/// Contains flags 
	/// </summary>
	[Flags]
	public enum OcspSigningFlags : uint {
		/// <summary>
		/// Acquire a private key silently.
		/// </summary>
		Silent						= 0x00000001,
		/// <summary>
		/// Use a CA certificate in this configuration for signing an OCSP response. This option is available only if the
		/// responder service is installed on the CA computer.
		/// </summary>
		UseCaCert					= 0x00000002,
		/// <summary>
		/// Enable a responder service to automatically transition to a renewed signing certificate.
		/// </summary>
		AllowSigningAutoenrenewal	= 0x00000004,
		/// <summary>
		/// Force a delegated signing certificate to be signed by the CA.
		/// </summary>
		ForceDelegatedCA			= 0x00000008,
		/// <summary>
		/// Automatically discover a delegated signing certificate.
		/// </summary>
		Autodiscover				= 0x00000010,
		/// <summary>
		/// Manually assign a signing certificate.
		/// </summary>
		ManualAssignCert			= 0x00000020,
		/// <summary>
		/// A responder ID includes a hash of the public key of the signing certificate (default).
		/// </summary>
		IdentifyByHash				= 0x00000040,
		/// <summary>
		/// A responder ID includes the name of the subject in a signing certificate.
		/// </summary>
		IdentifyByName				= 0x00000080,
		/// <summary>
		/// Enable NONCE extension to be processed by a responder service.
		/// </summary>
		AllowNonce					= 0x00000100,
		/// <summary>
		/// A responder service can enroll for a signing certificate.
		/// </summary>
		AllowSigningAutoenrollment	= 0x00000200
	}
}
