using System.ServiceProcess;
using CERTADMINLib;
using PKI.Exceptions;
using System;
using System.ComponentModel;
using PKI.Utils;

namespace PKI.OCSP.Server {
	/// <summary>
	/// Represents a Online Responder server object.
	/// </summary>
	public class OnlineResponder : IDisposable {
		OcspAuditFilterEnum audit;
		Int32 numOfThreads, maxNumOfCacheEntries;
		OCSPAdmin OcspAdmin;

		/// <param name="computerName">Online Responder computer name to connect.</param>
		public OnlineResponder(String computerName) {
			if (String.IsNullOrEmpty(computerName)) { throw new ArgumentNullException("computerName"); }
			IsDisposed = false;
			m_initialize(computerName);
		}

		/// <summary>
		/// Gets Online Responder computer name.
		/// </summary>
		public String ComputerName { get; private set; }
		/// <summary>
		/// Gets Online Responder service (<strong>ocspsvc</strong>) status.
		/// </summary>
		public ServiceControllerStatus ServiceStatus { get; private set; }
		/// <summary>
		/// Gets the revocation configurations count.
		/// </summary>
		public Int32 ConfigurationCount {
			get { return OcspAdmin.OCSPCAConfigurationCollection.Count; }
		}
		/// <summary>
		/// Gets an array of revocation configurations.
		/// </summary>
		public OcspConfigurationCollection ActiveConfigurations { get; set; }
		/// <summary>
		/// Gets  the computer name of the OCSP server that acts as the array controller for an OCSP array configuration.
		/// </summary>
		public String ArrayController { get; private set; }
		/// <summary>
		/// Gets the computer names of the OCSP servers that are part of an OCSP array configuration.
		/// </summary>
		public String[] ArrayMembers { get; private set; }
		/// <summary>
		/// Gets service audit settings.
		/// </summary>
		public OcspAuditFilterEnum AuditFilter {
			get { return audit; }
			set {
				if (audit == value) { return; }
				IOCSPProperty property = (IOCSPProperty)OcspAdmin.OCSPServiceProperties.ItemByName["MaxNumOfCacheEntries"];
				property.Value = (Int32)value;
				setConfiguration();
				audit = value;
			}
		}
		/// <summary>
		/// Gets the maximum number of cached responses.
		/// </summary>
		public Int32 MaxNumOfCacheEntries {
			get { return maxNumOfCacheEntries; }
			set {
				if (maxNumOfCacheEntries == value) { return; }
				IOCSPProperty property = (IOCSPProperty)OcspAdmin.OCSPServiceProperties.ItemByName["MaxNumOfCacheEntries"];
				property.Value = value;
				setConfiguration();
				maxNumOfCacheEntries = value;
			}
		}
		/// <summary>
		/// 
		/// </summary>
		public Int32 NumOfThreads {
			get { return numOfThreads; }
			set {
				if (numOfThreads == value) { return; }
				if (OcspAdmin == null) { throw new InvalidOperationException(); }
				IOCSPProperty property = (IOCSPProperty)OcspAdmin.OCSPServiceProperties.ItemByName["NumOfThreads"];
				property.Value = value;
				setConfiguration();
				numOfThreads = value;
			}
		}
		/// <summary>
		/// Indicates whether the object is disposed.
		/// </summary>
		public Boolean IsDisposed { get; private set; }

		void m_initialize(String computerName) {
			OcspAdmin = new OCSPAdmin();
			try {
				OcspAdmin.Ping(computerName);
			} catch (Exception e) {
				throw Error.ComExceptionHandler(e);
			}
			OcspAdmin.GetConfiguration(computerName, true);
			ComputerName = computerName;
			Object[,] obj = (Object[,])OcspAdmin.OCSPServiceProperties.GetAllProperties();
			for (Int32 index = 0; index < OcspAdmin.OCSPServiceProperties.Count; index++) {
				switch ((String)obj[index,0]) {
					case "ArrayController": ArrayController = (String)obj[index, 1]; break;
					case "ArrayMembers":
						Int32 length = ((Object[])obj[index, 1]).Length;
						ArrayMembers = new String[length];
						Array.Copy((Object[])obj[index, 1], ArrayMembers, length);
						break;
					case "AuditFilter": audit = (OcspAuditFilterEnum)obj[index, 1]; break;
					case "MaxNumOfCacheEntries": maxNumOfCacheEntries = (Int32)obj[index, 1]; break;
					case "NumOfThreads": numOfThreads = (Int32)obj[index, 1]; break;
				}
			}
			get_configurations(OcspAdmin);
		}
		void get_configurations(IOCSPAdmin ocspadmin) {
			OcspConfigurationCollection configs = new OcspConfigurationCollection();
			foreach (IOCSPCAConfiguration item in ocspadmin.OCSPCAConfigurationCollection) {
				configs.Add(new OcspConfiguration(item, this, OcspAdmin));
			}
			ActiveConfigurations = configs;
		}
		void setConfiguration() {
			if (!IsDisposed) {
				OcspAdmin.SetConfiguration(ComputerName, true);
			}
		}

		/// <summary>
		/// Returns all roles granted on the Online Responder to the caller.
		/// </summary>
		/// <exception cref="UninitializedObjectException"></exception>
		/// <returns>Granted roles.</returns>
		public OcspRolesEnum GetMyRoles() {
			if (IsDisposed) { throw new UninitializedObjectException(); }
			return (OcspRolesEnum)OcspAdmin.GetMyRoles(ComputerName);
		}
		/// <summary>
		/// Attempts to check Online Responder's management interfaces availability.
		/// </summary>
		/// <returns><strong>True</strong> if management interfaces are available and accessible, otherwise <strong>False</strong>.</returns>
		public Boolean Ping() {
			if (IsDisposed) { throw new UninitializedObjectException(); }
			try {
				OcspAdmin.Ping(ComputerName);
				return true;
			} catch {
				return false;
			}
		}
		/// <summary>
		/// Not implemented.
		/// </summary>
		public void AddConfiguration() {
			throw new NotImplementedException();
		}
		/// <summary>
		/// Removes specified revocation configuration and all related data.
		/// </summary>
		/// <param name="name">A string that contains the configuration name.</param>
		public void RemoveConfiguration(String name) {
			if (IsDisposed) { throw new UninitializedObjectException(); }
			if (!GetMyRoles().HasFlag(OcspRolesEnum.Administrator)) { throw new Win32Exception(5); }
			OcspAdmin.OCSPCAConfigurationCollection.DeleteCAConfiguration(name);
			OcspAdmin.SetConfiguration(ComputerName, true);
		}
		/// <summary>
		/// Releases unmanaged resources held by the object.
		/// </summary>
		public void Dispose() {
			ComputerName = null;
			ServiceStatus = ServiceControllerStatus.Stopped;
			//ProvConfig = null;
			ActiveConfigurations = null;
			ArrayController = null;
			ArrayMembers = null;
			maxNumOfCacheEntries = numOfThreads = 0;
			AuditFilter = 0;
			if (OcspAdmin != null) {
				CryptographyUtils.ReleaseCom(OcspAdmin);
				OcspAdmin = null;
				IsDisposed = true;
			}
		}

		/// <summary>
		/// Attempts to check Online Responder's management interfaces availability.
		/// </summary>
		/// <param name="computerName"></param>
		/// <returns>
		/// <strong>True</strong> if management interfaces are available and accessible, otherwise <strong>False</strong>.
		/// </returns>
		/// <exception cref="ArgumentNullException"><strong>computerName</strong> parameter is null or empty string.</exception>
		public static Boolean Ping(String computerName) {
			if (String.IsNullOrEmpty(computerName)) { throw new ArgumentNullException("computerName"); }
			OCSPAdmin ocspAdmin = null;
			try {
				ocspAdmin = new OCSPAdmin();
				ocspAdmin.Ping(computerName);
				return true;
			} catch {
				return false;
			} finally {
				if (ocspAdmin != null) {
					CryptographyUtils.ReleaseCom(ocspAdmin);
				}
			}
		}
	}
}
