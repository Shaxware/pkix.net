using System;
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
            _certRegD = new CertSrvRegManagerD(ComputerName);
            _certRegNative = new CertSrvRegManager(ComputerName);
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
                }

                if (_certRegD.IsAccessible) {
                    return _certRegD.GetConfigEntry<T>(entryName, node);
                }
            } catch {
                return default;
            }
            return default;
        }

        /// <summary>
        /// Requests a named configuration entry value of type of string.
        /// </summary>
        /// <param name="entryName">Configuration entry name.</param>
        /// <param name="node">Optional node path under Certification Authority active node.</param>
        /// <returns>Configuration entry value.</returns>
        /// <remarks>Active node is located at: System\CurrentControlSet\Services\CertSvc\Configuration\&lt;CA_Name&gt;</remarks>
        public String GetStringEntry(String entryName, String node = null) {
            return getConfigEntry<String>(entryName, node);
        }
        /// <summary>
        /// Requests a named configuration entry value of type of string array.
        /// </summary>
        /// <param name="entryName">Configuration entry name.</param>
        /// <param name="node">Optional node path under Certification Authority active node.</param>
        /// <returns>Configuration entry value.</returns>
        /// <remarks>Active node is located at: System\CurrentControlSet\Services\CertSvc\Configuration\&lt;CA_Name&gt;</remarks>
        public String[] GetMultiStringEntry(String entryName, String node = null) {
            return getConfigEntry<String[]>(entryName, node);
        }
        /// <summary>
        /// Requests a named configuration entry value of type of numeric (integral) value.
        /// </summary>
        /// <param name="entryName">Configuration entry name.</param>
        /// <param name="node">Optional node path under Certification Authority active node.</param>
        /// <returns>Configuration entry value.</returns>
        /// <remarks>Active node is located at: System\CurrentControlSet\Services\CertSvc\Configuration\&lt;CA_Name&gt;</remarks>
        public Int32 GetNumericEntry(String entryName, String node = null) {
            return getConfigEntry<Int32>(entryName, node);
        }
        /// <summary>
        /// Requests a named configuration entry value of type of boolean.
        /// </summary>
        /// <param name="entryName">Configuration entry name.</param>
        /// <param name="node">Optional node path under Certification Authority active node.</param>
        /// <returns>Configuration entry value.</returns>
        /// <remarks>Active node is located at: System\CurrentControlSet\Services\CertSvc\Configuration\&lt;CA_Name&gt;</remarks>
        public Boolean GetBooleanEntry(String entryName, String node = null) {
            return getConfigEntry<Boolean>(entryName, node);
        }
        /// <summary>
        /// Requests a named configuration entry value of type of byte array.
        /// </summary>
        /// <param name="entryName">Configuration entry name.</param>
        /// <param name="node">Optional node path under Certification Authority active node.</param>
        /// <returns>Configuration entry value.</returns>
        /// <remarks>Active node is located at: System\CurrentControlSet\Services\CertSvc\Configuration\&lt;CA_Name&gt;</remarks>
        public Byte[] GetBinaryEntry(String entryName, String node = null) {
            return getConfigEntry<Byte[]>(entryName, node);
        }

        /// <summary>
        /// Sets the root configuration node context.
        /// </summary>
        /// <param name="forceActiveNode">Indicates whether active context must be used.</param>
        /// <remarks>
        /// When <strong>forceActiveNode</strong> is set to True, root node context is set to
        /// 'System\CurrentControlSet\Services\CertSvc\Configuration\&lt;CA_Name&gt;'. Otherwise, root node context is set to
        /// 'System\CurrentControlSet\Services\CertSvc\Configuration'.
        /// </remarks>
        public void SetRootNode(Boolean forceActiveNode) {
            _certRegNative.SetRootNode(forceActiveNode);
            _certRegD.SetRootNode(forceActiveNode);
        }
    }
}