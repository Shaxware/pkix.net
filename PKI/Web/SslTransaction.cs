//using System;
//using System.Collections.Generic;
//using System.Diagnostics;
//using System.Linq;
//using System.Net;
//using System.Net.Security;
//using System.Security.Cryptography;
//using System.Security.Cryptography.X509Certificates;
//using System.Text;

//namespace PKI.Web {
//	class SslTransaction {
//		readonly X509Certificate2Collection
//			_sslChain = new X509Certificate2Collection(),
//			_pkcs7Chain = new X509Certificate2Collection();
//		readonly X509AlternativeNameCollection _san = new X509AlternativeNameCollection();
//		X509Chain tempChain;
//		Boolean redirected;
		

//		SslTransaction(ServerCertificateValidationObject obj) {
			
//		}
//		/// <summary>
//		/// Gets the URL associated with the current transaction.
//		/// </summary>
//		public Uri Url { get; private set; }
//		/// <summary>
//		/// Gets certificate subject name.
//		/// </summary>
//		public X500DistinguishedName Subject { get; private set; }
//		/// <summary>
//		/// Gets certificate issuer.
//		/// </summary>
//		public X500DistinguishedName Issuer { get; private set; }
//		/// <summary>
//		/// Gets an array of Subject Alternative Names (SAN) if they are configured.
//		/// </summary>
//		public String[] SubjectAlternativeNames {
//			get {
//				if (_san.Count == 0) { return null; }
//				String[] names = new String[_san.Count];
//				for (int index = 0; index < _san.Count; index++) {
//					names[index] = _san[index].Value;
//				}
//				return names;
//			}
//		}
//		/// <summary>
//		/// Gets the SSL certificate.
//		/// </summary>
//		public X509Certificate2 Certificate { get; private set; }
//		/// <summary>
//		/// Gets the status of the certificate. <strong>True</strong> if the certificate is valid, otherwise <strong>False</strong>.
//		/// </summary>
//		public Boolean CertificateIsValid { get; private set; }
//		/// <summary>
//		/// Gets certificate chain error information.
//		/// </summary>
//		public X509ChainStatus2 ErrorInformation { get; private set; }
//		public X509Certificate2Collection GetSslChain() {
//			return _sslChain;
//		}
//		public X509Certificate2Collection GetOfflineChain() {
//			return _pkcs7Chain;
//		}


//		void ExecuteChain(ServerCertificateValidationObject obj) {
//			Debug.WriteLine("Entering server certificate chain validation function...");
//			if (currentItem.TempRequest.ServicePoint.Certificate == null) {
//				currentItem.TempChain.Reset();
//				currentItem.ItemStatus = ServerStatusEnum.Failed;
//				currentItem.ChainStatus += (Int32)X509ChainStatus2.CertificateNotFound;
//				return;
//			}
//			X509Certificate2 cert = new X509Certificate2(currentItem.TempRequest.ServicePoint.Certificate);
//			Debug.WriteLine("Leaf certificate issued to: " + cert.Subject);
//			currentItem.Certificate = cert;
//			processSAN(currentItem);
//			// configure chaining engine
//			if (obj.StrictEKU) {
//				currentItem.TempChain.ChainPolicy.ApplicationPolicy.Add(new Oid("1.3.6.1.5.5.7.3.1"));
//			}
//			Boolean status = currentItem.TempChain.Build(cert);
//			if (status) {
//				Debug.WriteLine("Certificate chain successfully passed all checks.");
//			} else {
//				Debug.WriteLine("Certificate chaining engine reported some issues with the certificate.");
//				foreach (X509ChainStatus chainStatus in currentItem.TempChain.ChainStatus) {
//					Debug.WriteLine(chainStatus.Status + n);
//				}
//			}
//			GrabInternalChain(currentItem, chain);
//		}
//		void processSAN() {
//			foreach (X509Extension item in Certificate.Extensions.Cast<X509Extension>().Where(item => item.Oid.Value == "2.5.29.17")) {
//				Debug.WriteLine("Found Subject Alternative Names extension in the certificate.");
//				Debug.WriteLine("Fetching SAN values:");
//				Debug.WriteLine(item.Format(true));
//				_san.Decode(item.RawData);
//			}
//		}
//		static void GrabInternalChain(ServerObject currentItem, X509Chain chain) {
//			TreeNode<ChainElement> tree = currentItem.TempResponse == null
//				? new TreeNode<ChainElement>(new ChainElement { Name = currentItem.TempRequest.Address.AbsoluteUri, IsRoot = true })
//				: new TreeNode<ChainElement>(new ChainElement { Name = currentItem.TempResponse.ResponseUri.AbsoluteUri, IsRoot = true });
//			List<TreeNode<ChainElement>> tempList = new List<TreeNode<ChainElement>> { tree };
//			for (Int32 index = chain.ChainElements.Count - 1; index >= 0; index--) {
//				ChainElement temp = new ChainElement {
//					Certificate = currentItem.TempChain.ChainElements[index].Certificate,
//					Name = StripName(currentItem.TempChain.ChainElements[index].Certificate.Subject)
//				};
//				tree.AddChild(temp);
//				temp.PropagatedErrors = tree.Value.NativeErrors;
//				tree = tree.Children[0];
//				AddStatus(tree.Value, chain.ChainStatus);
//				AddStatus(tree.Value, currentItem.TempChain.ChainElements.Item(chain.ChainElements[index]).ChainElementStatus);
//				if ((chain.ChainElements[index].Certificate.NotAfter - DateTime.Now).Days <= treshold) {
//					AddStatus(tree.Value, new[] { new X509ChainStatus { Status = (X509ChainStatusFlags)X509ChainStatus2.AboutExpire } });
//				}
//				if (index == 0) {
//					if (!HasValidEKU(chain.ChainElements[index].Certificate)) {
//						if ((chain.ChainElements[index].Certificate.NotAfter - DateTime.Now).Days <= treshold) {
//							AddStatus(tree.Value, new[] { new X509ChainStatus { Status = (X509ChainStatusFlags)X509ChainStatus2.NotValidForUsage } });
//						}
//					}
//				}
//			}
//		}
//		static Boolean HasValidEKU(X509Certificate2 cert) {
//			return (from X509Extension extension in cert.Extensions where extension.Oid.Value == "2.5.29.37" select new AsnEncodedData(extension.RawData)).
//				Any(asn => (new X509EnhancedKeyUsageExtension(asn, false)).
//					EnhancedKeyUsages.Cast<Oid>().Any(oid => oid.Value == "1.3.6.1.5.5.7.3.1"));
//		}

//		static void AddStatus(ChainElement temp, IEnumerable<X509ChainStatus> status) {
//			if (status == null) { return; }
//			foreach (X509ChainStatus flag in status) {
//				if (flag.Status != X509ChainStatusFlags.NoError && flag.Status != (X509ChainStatusFlags)X509ChainStatus2.AboutExpire) {
//					temp.HasErrors = globalErrors = true;
//				}
//				if (flag.Status == (X509ChainStatusFlags)X509ChainStatus2.AboutExpire) {
//					temp.HasWarnings = globalWarnings = true;
//				}
//				if (!temp.PropagatedErrors.Contains((X509ChainStatus2)flag.Status)) {
//					temp.NativeErrors.Add((X509ChainStatus2)flag.Status);
//				}
//			}
//		}
//	}
//}
