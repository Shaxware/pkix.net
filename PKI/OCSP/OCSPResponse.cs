using System.Linq;
using PKI.Utils;
using System;
using System.Collections.Generic;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using PKI.ManagedAPI;
using PKI.ManagedAPI.StructClasses;
using SysadminsLV.Asn1Parser;

namespace PKI.OCSP {
#region Oids
//id-kp-OCSPSigning				OBJECT IDENTIFIER ::= { id-kp 9 }
//id-pkix-ocsp					OBJECT IDENTIFIER ::= { id-ad-ocsp }
//id-pkix-ocsp-basic			OBJECT IDENTIFIER ::= { 1.3.6.1.5.5.7.48.1.1 }
//id-pkix-ocsp-nonce			OBJECT IDENTIFIER ::= { 1.3.6.1.5.5.7.48.1.2 }
//id-pkix-ocsp-crl				OBJECT IDENTIFIER ::= { 1.3.6.1.5.5.7.48.1.3 }
//id-pkix-ocsp-response			OBJECT IDENTIFIER ::= { 1.3.6.1.5.5.7.48.1.4 }
//id-pkix-ocsp-nocheck			OBJECT IDENTIFIER ::= { 1.3.6.1.5.5.7.48.1.5 }
//id-pkix-ocsp-archive-cutoff	OBJECT IDENTIFIER ::= { 1.3.6.1.5.5.7.48.1.6 }
//id-pkix-ocsp-service-locator	OBJECT IDENTIFIER ::= { 1.3.6.1.5.5.7.48.1.7 }
#endregion
	/// <summary>
	/// Represents an OCSP response received from OCSP responder against previously submitted OCSP Request.
	/// </summary>
	public class OCSPResponse {
		readonly WebClient wc;
		Asn1Reader asn1;
		List<X509Extension> listExtensions = new List<X509Extension>();

		internal OCSPResponse(Byte[] rawData, OCSPRequest req, WebClient web) {
			RawData = rawData;
			Request = req;
			wc = web;
			decoderesponse();
		}

		/// <summary>
		/// Gets OCSP response version. Currently only version 1 is defined.
		/// </summary>
		public int Version { get; private set; }
		/// <summary>
		/// Gets response type (for example, <strong>id_pkix_ocsp_basic</strong>, which means Basic OCSP Response type).
		/// </summary>
		public OCSPResponseType ResponseType { get; private set; }
		/// <summary>
		/// Gets response status. Response status indicates whether the OCSP responder was able to process the request
		/// and obtain information about requested certificate.
		/// </summary>
		/// <remarks><strong>Note:</strong> this property do not say anything about certificate status.</remarks>
		public OCSPResponseStatus ResponseStatus { get; private set; }
		/// <summary>
		/// Gets the the time at which the OCSP responder signed this response.
		/// </summary>
		public DateTime ProducedAt { get; private set; }
		/// <summary>
		/// Indicates whether the <strong>Nonce</strong> extension is included in the response.
		/// </summary>
		public bool NonceReceived { get; private set; }
		/// <summary>
		/// Gets Nonce extension value. This value (if extension is presented) MUST be exactly as specified in the request.
		/// </summary>
		public string NonceValue { get; private set; }
		/// <summary>
		/// Gets OCSP responder key ID (a hash calculated over responder's public key). If this property is empty,
		/// a <see cref="ResponderNameId"/> is used.
		/// </summary>
		public string ResponderKeyId { get; private set; }
		/// <summary>
		/// Gets OCSP responder name ID. If this property is empty, a <see cref="ResponderKeyId"/> is used.
		/// </summary>
		public X500DistinguishedName ResponderNameId { get; private set; }
		/// <summary>
		/// Gets original OCSP request object.
		/// </summary>
		public OCSPRequest Request { get; private set; }
		/// <summary>
		/// Gets OCSP Signing certificate that was used to sign the response.
		/// </summary>
		public X509Certificate2Collection SignerCertificates { get; private set; }
		/// <summary>
		/// Gets a collection of OCSPSingleResponse objects, which contains revocation status about each requested certificate.
		/// </summary>
		public OCSPSingleResponseCollection Responses { get; private set; }
		/// <summary>
		/// Gets optional OCSP response extensions. This may contain Nonce extension.
		/// </summary>
		public X509ExtensionCollection ResponseExtensions {
			get {
				if (listExtensions.Count == 0) { return null; }
				X509ExtensionCollection retValue = new X509ExtensionCollection();
				foreach (X509Extension item in listExtensions) { retValue.Add(item); }
				return retValue;
			}
		}
		/// <summary>
		/// Gets response HTTP headers.
		/// </summary>
		public WebHeaderCollection HttpHeaders {
			get { return wc.ResponseHeaders; }
		}
		/// <summary>
		/// Indicates whether the signig certificate is valid for requested usage.
		/// </summary>
		/// <remarks>This check returns <strong>True</strong> under the following circumstances:
		/// <list type="bullet">
		/// <item>Is issued by the trusted certification authority.</item>
		/// <item>If it is delegated signing certificate, the certificate MUST contains id-kp-OCSPSigning
		/// Enhanced Key Usage .</item>
		/// <item>If it is delegated signing certificate, the certificate MUST contains OCSP id-pkix-ocsp-nocheck
		/// extension.</item>
		/// </list>
		/// If any of this check fails, the property returns <strong>False</strong>.
		/// </remarks>
		public Boolean SignerCertificateIsValid { get; private set; }
		/// <summary>
		/// Indicates whether the signature is valid.
		/// </summary>
		public Boolean SignatureIsValid { get; private set; }
		/// <summary>
		/// Gets error information returned by the certificate chaining engine.
		/// </summary>
		public X509ChainStatus[] ChainErrorInformation { get; private set; }
		/// <summary>
		/// Gets error and warning information about received response conformance with
		/// <see href="http://tools.ietf.org/html/rfc2560.html">RFC2560</see>.
		/// </summary>
		/// <remarks>Not all entries should be treated as an error. For example, if original request contains Nonce extension,
		/// OCSP Responder may not return this extension in the response.</remarks>
		public OCSPResponseComplianceError ResponseErrorInformation { get; private set; }
		/// <summary>
		/// Gets the algorithm used to create the signature of a response.
		/// </summary>
		/// <remarks>The object identifier <see cref="Oid">(Oid)</see> identifies the type of signature
		/// algorithm used by the responder.</remarks>
		public Oid SignatureAlgorithm { get; private set; }
		/// <summary>
		/// Gets encoded response's raw data.
		/// </summary>
		public byte[] RawData { get; private set; }

		void decoderesponse() {
			asn1 = new Asn1Reader(RawData);
			if (asn1.Tag != 48) {
				throw new Exception("Response data is not valid ASN.1 encoded data.");
			}
			//response status
			asn1.MoveNext();
			if (asn1.Tag != 10) {
				throw new Exception("Unable to decode OCSP Reponse data. The data is invalid.");
			}
			ResponseStatus = (OCSPResponseStatus) asn1.GetPayload()[0];
			if (asn1.NextOffset == 0) { return; }
			//responseBytesCS
			asn1.MoveNext();
			if (asn1.Tag != 160) {
				throw new Exception("Unable to decode Response.");
			}
			asn1.MoveNext();
			asn1.MoveNext();
			if (asn1.Tag != 6) {
				throw new Exception("Response type is invalid.");
			}
			Byte[] oidbytes = Asn1Utils.Encode(asn1.GetPayload(), (Byte) Asn1Type.OBJECT_IDENTIFIER);
			decoderesponsetype(oidbytes);
			asn1.MoveNext();
			if (asn1.Tag != 4) {
				throw new Exception("Response is missing.");
			}
			//BasicOCSPResponse
			asn1.MoveNext();
			if (asn1.Tag != 48) {
				throw new Exception("tbsResponseData is missing.");
			}
			asn1.MoveNext();
			//tbsResponseData
			var a = asn1.GetPayload();
			Asn1Reader tbsResponseData = new Asn1Reader(asn1.GetTagRawData());
			//decodetbsResponse(tbsResponseData);
			//signatureAlgorithm
			asn1.MoveNextCurrentLevel();
			SignatureAlgorithm = (new AlgorithmIdentifier(Asn1Utils.Encode(asn1.GetPayload(), 48))).AlgorithmId;
			//signature
			asn1.MoveNextCurrentLevel();
			Byte[] signature = asn1.GetPayload().Skip(1).ToArray();
			// GenericArray.GetSubArray(asn1.Payload, 1, asn1.Payload.Length - 1);
			SignerCertificates = new X509Certificate2Collection();
			if (asn1.MoveNext()) {
				asn1.MoveNext();
				Asn1Reader cert = new Asn1Reader(asn1.GetPayload());
				do {
					SignerCertificates.Add(new X509Certificate2(Asn1Utils.Encode(cert.GetPayload(), 48)));
				} while (cert.MoveNextCurrentLevel());
				verifysigner(SignerCertificates[0], true);
			} // optional. Find cert in store.
			verifyall(tbsResponseData, signature, SignatureAlgorithm);
		}
		void decoderesponsetype(Byte[] raw) {
			Oid oid = Asn1Utils.DecodeObjectIdentifier(raw);
			switch (oid.Value) {
				case "1.3.6.1.5.5.7.48.1.1": ResponseType = OCSPResponseType.id_pkix_ocsp_basic; break;
				case "1.3.6.1.5.5.7.48.1.4": ResponseType = OCSPResponseType.id_pkix_ocsp_response; break;
			}
		}
		void decodetbsResponse(Asn1Reader tbsResponseData) {
			tbsResponseData.MoveNext();
			if (tbsResponseData.Tag == 160) {
				//Asn1Reader aversion = new Asn1Reader(tbsResponseData.RawData, tbsResponseData.PayloadStartOffset);
				Asn1Reader aversion = new Asn1Reader(tbsResponseData);
				aversion.MoveNext();
				Version = aversion.GetPayload()[0] + 1;
				tbsResponseData.MoveNextCurrentLevel();
			} else {
				Version = 1;
			}
			//responderID
			switch (tbsResponseData.Tag) {
				case 161:
					ResponderNameId = new X500DistinguishedName(tbsResponseData.GetPayload());
					tbsResponseData.MoveNextCurrentLevel();
					break;
				case 162:
					tbsResponseData.MoveNext();
					StringBuilder SB = new StringBuilder();
					foreach (Byte element in tbsResponseData.GetPayload()) { SB.Append(element.ToString("X2")); }
					ResponderKeyId = SB.ToString();
					tbsResponseData.MoveNext();
					break;
				default: 
					throw new Exception("Invalid tag at responderID. Expected 161 (byName) or 162 (byKey).");
			}
			//tbsResponseData.MoveNextCurrentLevel();
			ProducedAt = Asn1Utils.DecodeGeneralizedTime(tbsResponseData.GetTagRawData());
			if (DateTime.Now < ProducedAt.AddMinutes(-10)) {
				ResponseErrorInformation += (Int32)OCSPResponseComplianceError.ResponseNotTimeValid;
			}
			//responses
			tbsResponseData.MoveNext();
			//single response
			Asn1Reader responses = new Asn1Reader(tbsResponseData.GetTagRawData());
			responses.MoveNext();
			Int32 Offset;
			Responses = new OCSPSingleResponseCollection();
			do {
				Asn1Reader response = new Asn1Reader(responses);
				Offset = response.NextCurrentLevelOffset;
				Responses.Add(new OCSPSingleResponse(response));
				foreach (OCSPSingleResponse item in Responses) {
					Boolean certidmatch = false;
					foreach (OCSPSingleRequest reqitem in Request.RequestList.Cast<OCSPSingleRequest>().Where(reqitem => reqitem.CertId.Equals(item.CertId))) {
						certidmatch = true;
					}
					if (!certidmatch) {
						ResponseErrorInformation += (Int32)OCSPResponseComplianceError.CertIdMismatch;
					}
				}
			} while (Offset != 0);
			if (tbsResponseData.NextCurrentLevelOffset != 0) {
				tbsResponseData.MoveNextCurrentLevel();
				if (tbsResponseData.Tag == 161) {
					X509ExtensionCollection exts = Crypt32Managed.DecodeX509Extensions(tbsResponseData.GetPayload());
					foreach (X509Extension item in exts) {
						listExtensions.Add(CryptographyUtils.ConvertExtension(item));
						if (listExtensions[listExtensions.Count - 1].Oid.Value == "1.3.6.1.5.5.7.48.1.2") { 
							NonceReceived = true;
							NonceValue = listExtensions[listExtensions.Count - 1].Format(false);
						}
					}
				} else { throw new Exception("Unexpected tag at responseExtensions. Expected 161."); }
			}
		}
		void findcertinstore() {
			String[] storenames = { "Root", "CA" };
			foreach (X509Store store in storenames.Select(storename => new X509Store(storename, StoreLocation.CurrentUser))) {
				store.Open(OpenFlags.ReadOnly);
				X509Certificate2Collection findcerts = store.Certificates;
				X509Certificate2Collection findcert;
				if (ResponderNameId != null) {
					findcert = findcerts.Find(X509FindType.FindBySubjectDistinguishedName, ResponderNameId.Name, true);
					if (findcert.Count > 0) {
						SignerCertificates.Add(findcert[0]);
						verifysigner(findcert[0], false);
					}
				} else {
					findcert = findcerts.Find(X509FindType.FindBySubjectKeyIdentifier, ResponderKeyId, true);
					if (findcert.Count > 0) {
						SignerCertificates.Add(findcert[0]);
						verifysigner(findcert[0], false);
					}
				}
				store.Close();
			}
		}
		void verifyall(Asn1Reader tbsResponseData, Byte[] signature, Oid signatureAlgorithm) {
			verifyheaders();
			decodetbsResponse(tbsResponseData);
			if (NonceReceived) {
				if (Request.NonceValue != NonceValue) {
					ResponseErrorInformation += (Int32)OCSPResponseComplianceError.NonceMismatch;
				}
			}
			if (SignerCertificates.Count > 0) {
				SignatureIsValid = MessageSignature.VerifySignature(
					SignerCertificates[0],
                    tbsResponseData.RawData,
                    signature,
					signatureAlgorithm
				);
			} else {
				findcertinstore();
				if (SignerCertificates.Count > 0) {
					SignatureIsValid = MessageSignature.VerifySignature(
						SignerCertificates[0],
                        tbsResponseData.RawData,
                        signature,
						signatureAlgorithm
					);
				} else {
					ResponseErrorInformation += (Int32)OCSPResponseComplianceError.MissingCert;
				}
			}
			verifyresponses();
		}
		void verifyheaders() {
			if (wc.ResponseHeaders.Get("Content-type") != "application/ocsp-response") {
				ResponseErrorInformation += (Int32)OCSPResponseComplianceError.InvalidHTTPHeader;
			}
		}
		void verifyresponses() {
			if (Responses.Cast<OCSPSingleResponse>()
				.Any(item => item.ThisUpdate > DateTime.Now || (item.NextUpdate != null && item.NextUpdate < DateTime.Now))) {
				ResponseErrorInformation += (Int32)OCSPResponseComplianceError.UpdateNotTimeValid;
			}
		}
		void verifysigner(X509Certificate2 cert, Boolean excplicitcert) {
			SignerCertificateIsValid = true;
			X509Chain chain = new X509Chain {ChainPolicy = {RevocationMode = X509RevocationMode.NoCheck}};
			SignerCertificateIsValid = chain.Build(cert);
			if (!SignerCertificateIsValid) {
				ChainErrorInformation = chain.ChainStatus;
				SignerCertificateIsValid = false;
			}
			if (excplicitcert) {
				X509Extension ocspnocheck = cert.Extensions["1.3.6.1.5.5.7.48.1.5"];
				if (ocspnocheck == null) {
					ResponseErrorInformation += (Int32)OCSPResponseComplianceError.MissingOCSPRevNoCheck;
					SignerCertificateIsValid = false;
				}
				X509Extension eku = cert.Extensions["2.5.29.37"];
				if (eku == null) {
					ResponseErrorInformation += (Int32)OCSPResponseComplianceError.MissingOCSPSigningEKU;
					SignerCertificateIsValid = false;
				}
			}
		}

		/// <summary>
		/// Displays OCSP response signing certificates in a familiar UI. If multiple certificates are available,
		/// they are displayed as a certificate pick up list.
		/// </summary>
		public void DisplaySigningCertificateUI() {
			if (SignerCertificates.Count == 0) {
				throw new NullReferenceException("No signing certificates are available");
			}
			if (SignerCertificates.Count == 1) {
				X509Certificate2UI.DisplayCertificate(SignerCertificates[0]);
			} else if (SignerCertificates.Count > 1) {
				X509Certificate2UI.SelectFromCollection(SignerCertificates, "Response signing certificates", "", X509SelectionFlag.SingleSelection);
			}
		}
	}
}
