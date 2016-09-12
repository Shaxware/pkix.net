using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace PKI.Web {
	class WebSSL2 {
		static Int32 currentIndex, treshold;
		static readonly String _nl = Environment.NewLine;
		static Boolean redirected, globalErrors, globalWarnings;
		HttpWebRequest request;
		WebProxy proxy;
		X509Certificate2 clientCert;

		public WebSSL2(Uri url) {
			if (url == null) { throw new ArgumentNullException(nameof(url)); }
			RequestedUrl = url;
		}

		public Uri RequestedUrl { get; }
		public Uri ReturnedUrl { get; private set; }
		public Boolean StrictKeyUsageValidation { get; set; }
		public Boolean AllowUserStoreTrust { get; set; }
		public Boolean StrictUSageValidation { get; set; }
		public ICredentials Credentials { get; set; }
		public X509Certificate2 ClientCertificate {
			get { return clientCert; }
			set {
				if (value != null) {
					if (!value.HasPrivateKey) { return; }
				}
				clientCert = value;
			}
		}
		//public SslTransaction[] Transactions { get; private set; }


		//void m_initialize(HttpWebRequest request, Boolean allowUserTrust) {
		//	ServicePointManager.MaxServicePointIdleTime = 0;
		//	ServicePointManager.ServerCertificateValidationCallback =
		//		delegate(Object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors) {
		//			ServerCertificateValidationObject serverValidator = new ServerCertificateValidationObject {
		//				Certificate = new X509Certificate2(certificate),
		//				SslChain = chain,
		//				SslErrors = sslPolicyErrors
		//			};
		//			tempChain = new X509Chain(allowUserTrust);
		//			if (redirected) {
		//				serverValidator.Url = ((HttpWebRequest)sender).Address.AbsoluteUri;
		//				Debug.WriteLine("We are redirected. Entering the certificate validation callback function again.");
		//				Debug.WriteLine("Redirected URL: " + ((HttpWebRequest)sender).Address.AbsoluteUri);
		//				currentItem.ChainStatus = 0;
		//			} else {
		//				Debug.WriteLine("Server returned " + chain.ChainElements.Count + " certificates.");
		//			}
		//			if (chain.ChainElements.Count > 1) {
		//				currentItem.Log.Add("Dumping certificates:" + _nl);
		//				for (Int32 index = 0; index < chain.ChainElements.Count; index++) {
		//					Debug.WriteLine(
		//						"=============================== Certificate " + index + " ===============================" + _nl
		//					);
		//					Debug.WriteLine(chain.ChainElements[index].Certificate.ToString(true));
		//					currentItem.TempChain.ChainPolicy.ExtraStore.Add(chain.ChainElements[index].Certificate);
		//				}
		//			}
		//			if (((Int32)sslPolicyErrors & (Int32)SslPolicyErrors.RemoteCertificateNameMismatch) == 0) {
		//				currentItem.ChainStatus += (Int32)X509ChainStatus2.NameMismatch;
		//			}
		//			ExecuteChain(currentItem, chain);
		//			currentItem.TempChain.Reset();
		//			redirected = true;
		//			return true;
		//		};
		//	try {
		//		currentItem.TempResponse = (HttpWebResponse)currentItem.TempRequest.GetResponse();
		//	} catch (Exception e) {
		//		Debug.WriteLine("An exception occured while attempting to connect to server: ");
		//		Debug.WriteLine(e.Message + _nl);
		//		globalErrors = true;
		//		currentItem.ChainStatus += (Int32)X509ChainStatus2.CertificateNotFound;
		//	} finally {
		//		ServicePointManager.ServerCertificateValidationCallback = null;
		//	}
		//}
		void sendRequest() {
			request = (HttpWebRequest)WebRequest.Create(RequestedUrl);
			request.Credentials = Credentials;
			request.Proxy = proxy;
			if (clientCert != null) {
				X509Chain chain = new X509Chain {
					ChainPolicy = {
						RevocationMode = X509RevocationMode.NoCheck
					}
				};
				chain.Build(clientCert);
				request.ClientCertificates = new X509Certificate2Collection();
				foreach (X509ChainElement certElement in chain.ChainElements) {
					request.ClientCertificates.Add(certElement.Certificate);
				}
			}
			request.Timeout = 30000;
			request.AllowAutoRedirect = true;
		}
		
	}
}
