using System;
using System.Collections.Generic;
using System.ComponentModel;
using CERTADMINLib;
using Microsoft.Win32;
using PKI.CertificateServices;
using SysadminsLV.PKI.Management.CertificateServices.Configuration;

namespace PKI.Utils {
    class CryptoRegistry {
        readonly String _computer, _configString, _node;
        readonly Dictionary<Type, RegistryValueKind> _switch = new Dictionary<Type, RegistryValueKind> {
            { typeof(Int16), RegistryValueKind.DWord },
            { typeof(UInt16), RegistryValueKind.DWord },
            { typeof(Int32), RegistryValueKind.DWord },
            { typeof(UInt32), RegistryValueKind.DWord },
            { typeof(Int64), RegistryValueKind.QWord },
            { typeof(UInt64), RegistryValueKind.QWord },
            { typeof(String), RegistryValueKind.String },
            { typeof(String[]), RegistryValueKind.MultiString },
            { typeof(Byte[]), RegistryValueKind.Binary }
        };


        public CryptoRegistry(String computerName, String caSanitizedName) {
            _computer = computerName;
            _configString = $@"{_computer}\{caSanitizedName}";
            _node = $@"System\CurrentControlSet\Services\CertSvc\Configuration\{_configString}\";
        }
        public Boolean PingRemoteRegistry() {
            try {
                RegistryKey key = RegistryKey.OpenRemoteBaseKey(RegistryHive.LocalMachine, _computer);
                key.Close();
            } catch { return false; }
            return true;
        }
        public Boolean PingRpcDcom() {
            return CertificateAuthority.Ping(_computer);
        }

        public Object GetRemoteRegistryValue(String node, String entryName) {
            node = _node + node;
            RegistryKey key = RegistryKey.OpenRemoteBaseKey(RegistryHive.LocalMachine, _computer);
            key = key.OpenSubKey(node, false);
            if (key != null) {
                Object retn = key.GetValue(entryName, "false");
                if (retn.ToString() == "false") {
                    key.Close();
                    throw new Win32Exception(2);
                }
                key.Close();
                return retn;
            }
            throw new Win32Exception(2);
        }
        public Object GetRpcDcomValue(String node, String entryName) {
            CCertAdmin CertAdmin = new CCertAdmin();
            try {
                Object retn = CertAdmin.GetConfigEntry(_configString, node, entryName);
                CryptographyUtils.ReleaseCom(CertAdmin);
                return retn;
            } catch (Exception e) {
                throw Error.ComExceptionHandler(e);
            } finally {
                CryptographyUtils.ReleaseCom(CertAdmin);
            }
        }
        public void SetRemoteRegistryValue(AdcsInternalConfigPath entry) {
            var node = _node + entry.NodePath;
            if (!_switch.ContainsKey(entry.Value.GetType())) {
                throw new ArgumentException();
            }
            RegistryValueKind regType = _switch[entry.Value.GetType()];
            RegistryKey key = RegistryKey.OpenRemoteBaseKey(RegistryHive.LocalMachine, _computer);
            key = key.OpenSubKey(node, true);
            try {
                key?.SetValue(entry.ValueName, entry.Value, regType);
            } finally {
                key?.Close();
            }
        }
        public void SetRpcDcomValue(AdcsInternalConfigPath entry) {
            CCertAdmin CertAdmin = new CCertAdmin();
            try {
                CertAdmin.SetConfigEntry(_configString, entry.NodePath, entry.ValueName, entry.Value);
            } catch (Exception e) {
                throw Error.ComExceptionHandler(e);
            } finally {
                CryptographyUtils.ReleaseCom(CertAdmin);
            }
        }

        // everything balow should be removed.

        #region Local registry
        const String ContextAutoEnrollment = @"SOFTWARE\Policies\Microsoft\Cryptography";
        public static Object GetLKey(String context, Boolean userContext) {
            RegistryKey key;
            switch (context) {
                case "Autoenrollment":
                    key = userContext
                        ? Registry.CurrentUser.OpenSubKey($@"{ContextAutoEnrollment}\AutoEnrollment")
                        : Registry.LocalMachine.OpenSubKey($@"{ContextAutoEnrollment}\AutoEnrollment");
                    if (key == null) { return null; }
                    Int32 result = (Int32)key.GetValue("AEPolicy");
                    key.Close();
                    return result;
                default:
                    return null;
            }
        }
        #endregion

        #region Native remote registry methods
        /// <summary>
        /// Attempts to open remote registry on a specified computer.
        /// </summary>
        /// <param name="computerName">Computer name to check for accessibility via remote registry.</param>
        /// <returns></returns>
        public static Boolean Ping(String computerName) {
            try {
                RegistryKey key = RegistryKey.OpenRemoteBaseKey(RegistryHive.LocalMachine, computerName);
                key.Close();
            } catch { return false; }
            return true;
        }
        public static Object GetRReg(
            String entry,
            String caName,
            String computerName,
            String node = @"System\CurrentControlSet\Services\CertSvc\Configuration\"
        ) {
            RegistryKey key = RegistryKey.OpenRemoteBaseKey(RegistryHive.LocalMachine, computerName);
            key = caName == String.Empty
                ? key.OpenSubKey(node, false)
                : key.OpenSubKey(node + caName, false);
            if (key != null) {
                Object retn = key.GetValue(entry, "false");
                if (retn.ToString() != "false") {
                    key.Close();
                    return retn;
                }
                key.Close();
                throw new Win32Exception(2);
            }
            throw new Win32Exception(2);
        }
        public static void SetRReg(
            Object value,
            String entry,
            RegistryValueKind type,
            String caName,
            String computerName,
            String node = @"System\CurrentControlSet\Services\CertSvc\Configuration\"
        ) {
            RegistryKey key = RegistryKey.OpenRemoteBaseKey(RegistryHive.LocalMachine, computerName);
            key = caName == String.Empty
                ? key.OpenSubKey(node, true)
                : key.OpenSubKey(node + caName, true);
            try {
                key?.SetValue(entry, value, type);
            } finally {
                key?.Close();
            }
        }
        public static void SetRReg(
            List<String> value,
            String entry,
            String caName,
            String computerName,
            String node = @"System\CurrentControlSet\Services\CertSvc\Configuration\"
        ) {
            RegistryKey key = RegistryKey.OpenRemoteBaseKey(RegistryHive.LocalMachine, computerName);
            key = caName == String.Empty
                ? key.OpenSubKey(node, true)
                : key.OpenSubKey(node + caName, true);
            try {
                key?.SetValue(entry, value.ToArray(), RegistryValueKind.MultiString);
            } finally {
                key?.Close();
            }
        }
        public static void SetRReg(
            Byte[] value,
            String entry,
            String caName,
            String computerName,
            String node = @"System\CurrentControlSet\Services\CertSvc\Configuration\"
        ) {
            RegistryKey key = RegistryKey.OpenRemoteBaseKey(RegistryHive.LocalMachine, computerName);
            key = caName == String.Empty
                ? key.OpenSubKey(node, true)
                : key.OpenSubKey(node + caName, true);
            try {
                key?.SetValue(entry, value, RegistryValueKind.Binary);
            } finally {
                key?.Close();
            }
        }
        #endregion

        #region ICertAdmin registry methods
        public static Object GetRegFallback(
            String configString,
            String node,
            String entry
        ) {
            CCertAdmin CertAdmin = new CCertAdmin();
            try {
                Object retn = CertAdmin.GetConfigEntry(configString, node, entry);
                CryptographyUtils.ReleaseCom(CertAdmin);
                return retn;
            } catch (Exception e) {
                throw Error.ComExceptionHandler(e);
            } finally {
                CryptographyUtils.ReleaseCom(CertAdmin);
            }
        }
        public static void SetRegFallback(
            String configString,
            String node,
            String entry,
            Object value
        ) {
            CCertAdmin CertAdmin = new CCertAdmin();
            try {
                CertAdmin.SetConfigEntry(configString, node, entry, value);
            } catch (Exception e) {
                throw Error.ComExceptionHandler(e);
            } finally {
                CryptographyUtils.ReleaseCom(CertAdmin);
            }
        }
        public static void SetRegFallback(
            String configString,
            String node,
            String entry,
            List<String> value
        ) {
            CCertAdmin CertAdmin = new CCertAdmin();
            try {
                CertAdmin.SetConfigEntry(configString, node, entry, value);
            } catch (Exception e) {
                throw Error.ComExceptionHandler(e);
            } finally {
                CryptographyUtils.ReleaseCom(CertAdmin);
            }
        }
        #endregion
    }
}
