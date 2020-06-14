using System;
using PKI.Utils;
using SysadminsLV.PKI.Dcom;
using SysadminsLV.PKI.Dcom.Implementations;

namespace SysadminsLV.PKI.Management.CertificateServices {
    /// <summary>
    /// 
    /// </summary>
    public class CertSrvConfigUtil {
        // add .NET native Remote Registry and ICertAdmin DCOM implementations of ICertRegManagerD
        readonly ICertRegManagerD _certRegD, _certRegNative;

        /// <summary>
        /// Initializes a new instance of <strong>CertSrvConfigUtil</strong> class from Certification Authority server host name.
        /// </summary>
        /// <param name="computerName">Server's NetBIOS or FQDN name. If this parameter is null, current computer name is used.</param>
        public CertSrvConfigUtil(String computerName) {
            ComputerName = computerName ?? Environment.MachineName;
            _certRegD = new CertRegManagerD(ComputerName);
            _certRegNative = new RemoteRegManager(ComputerName);
        }

        /// <summary>
        /// Gets Certification Authority host name.
        /// </summary>
        public String ComputerName { get; }
        /// <summary>
        /// Indicates whether Certification Authority server configuration is accessible via .NET remote registry.
        /// </summary>
        public Boolean RegistryOnline => _certRegNative.IsAccessible;
        /// <summary>
        /// Indicates whether Certification Authority server configuration is accessible via unmanaged RPC/DCOM.
        /// </summary>
        public Boolean DcomOnline => _certRegD.IsAccessible;

        T getConfigEntry<T>(String entryName, String node) {
            try {
                if (_certRegNative.IsAccessible) {
                    return _certRegNative.GetConfigEntry<T>(entryName, node);
                } else if (_certRegD.IsAccessible) {
                    return _certRegD.GetConfigEntry<T>(entryName, node);
                }
            } catch {
                return default;
            }
            return default;
        }

        public String GetStringEntry(String entryName, String node = null) {
            return getConfigEntry<String>(entryName, node);
        }
        public String[] GetMultiStringEntry(String entryName, String node = null) {
            return getConfigEntry<String[]>(entryName, node);
        }
        public Int32 GetNumericEntry(String entryName, String node = null) {
            return getConfigEntry<Int32>(entryName, node);
        }
        public Boolean GetBooleanEntry(String entryName, String node = null) {
            return getConfigEntry<Boolean>(entryName, node);
        }
        public Byte[] GetBinaryEntry(String entryName, String node = null) {
            return getConfigEntry<Byte[]>(entryName, node);
        }

        public void SetRootNode(Boolean forceActiveNode) {
            _certRegNative.SetRootNode(forceActiveNode);
            _certRegD.SetRootNode(forceActiveNode);
        }
    }
}