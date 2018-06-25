using System;
using System.Collections.Generic;
using PKI.CertificateServices;
using PKI.Exceptions;
using PKI.Utils;

namespace SysadminsLV.PKI.Management.CertificateServices.Configuration {
    /// <summary>
    /// Represents a Certification Authority configuration composite setting. Some settings can be logically
    /// grouped from a set of single 
    /// </summary>
    abstract class AdcsConfigurationEntry {
        readonly String _configString;
        readonly String _name;

        protected AdcsConfigurationEntry(CertificateAuthority certificateAuthority) {
            _configString = certificateAuthority.ConfigString;
            _name = certificateAuthority.Name;
            DisplayName = certificateAuthority.DisplayName;
            ComputerName = certificateAuthority.ComputerName;
        }
        /// <summary>
        /// Gets the display name of the Certification Authority (sanitized characters are decoded to textual characters).
        /// </summary>
        public String DisplayName { get; }
        /// <summary>
        /// Gets the host fully qualified domain name (FQDN) of the server where Certification Authority is installed.
        /// </summary>
        public String ComputerName { get; }
        /// <summary>
        /// Indiciates whether the object was modified after it was instantiated. Implementers are responsible
        /// to set this value to <strong>True</strong> if configuration changes. If configuration is changed and
        /// this member is set to <string>False</string>, changes are not commited.
        /// </summary>
        public Boolean IsModified { get; protected set; }

        void readRemoteRegistry(AdcsInternalConfigPath entry) {
            String node = getRawNode(entry.NodePath);
            entry.Value = CryptoRegistry.GetRReg(entry.ValueName, _name, ComputerName, node);
        }
        void readRpcDcom(AdcsInternalConfigPath entry) {
            entry.Value = CryptoRegistry.GetRegFallback(_configString, entry.NodePath, entry.ValueName);
        }
        void writeRemoteRegistry(AdcsInternalConfigPath entry) {

        }
        void writeRpcDcom(AdcsInternalConfigPath entry) {

        }
        void deleteRemoteRegistry(AdcsInternalConfigPath entry) {

        }
        void deleteRpcDcom(AdcsInternalConfigPath entry) {

        }
        static String getRawNode(String relativeNode) {
            return @"System\CurrentControlSet\Services\CertSvc\Configuration\" + relativeNode;
        }

        /// <summary>
        /// Gets a list of registry settings associated with a current composite configuration entry.
        /// Inheritors are responsible for list maintenance.
        /// </summary>
        protected ISet<AdcsInternalConfigPath> RegEntries { get; } = new HashSet<AdcsInternalConfigPath>();

        /// <summary>
        /// Reads config from CA registry based on requested registry entries in <see cref="RegEntries"/> collection.
        /// After completion, a <see cref="AdcsInternalConfigPath.Value"/> member is populated with a value;
        /// </summary>
        /// <exception cref="ServerUnavailableException">
        /// CA server is inaccessible via any suitable registry reading means.
        /// </exception>
        /// <remarks>
        /// This method attempts to read registry by using remote registry. If remote registry fails, ADCS DCOM
        /// registry access is attempted. If both methods fails, a <see cref="ServerUnavailableException"/> will
        /// be thrown.
        /// </remarks>
        public virtual void ReadConfig() {
            if (CryptoRegistry.Ping(ComputerName)) {

            } else if (CertificateAuthority.Ping(ComputerName)) {

            } else {
                throw new ServerUnavailableException(DisplayName);
            }
            
        }
        /// <summary>
        /// Saves current configuration back to 
        /// </summary>
        /// <param name="restartRequired">
        /// Indiciates whether Certification Authority service restart is required when at least one property is
        /// successfully commited to CA registry.
        /// </param>
        /// <returns>
        /// <strong>True</strong> if configuration was changed. If an object was not modified since it was
        /// instantiated, configuration is not updated and the method returns <strong>False</strong>.
        /// </returns>
        /// <remarks>
        /// This method attempts to write registry by using remote registry. If remote registry fails, ADCS DCOM
        /// registry access is attempted. If both methods fails, a <see cref="ServerUnavailableException"/> will
        /// be thrown.
        /// </remarks>
        public virtual Boolean SaveChanges(Boolean restartRequired) {
            if (CryptoRegistry.Ping(ComputerName)) {

            } else if (CertificateAuthority.Ping(ComputerName)) {

            } else {
                throw new ServerUnavailableException(DisplayName);
            }
            return false;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="restartRequired">
        /// Indiciates whether Certification Authority service restart is required when at least one property is
        /// successfully commited to CA registry.
        /// </param>
        /// <remarks>
        /// This method attempts to write registry by using remote registry. If remote registry fails, ADCS DCOM
        /// registry access is attempted. If both methods fails, a <see cref="ServerUnavailableException"/> will
        /// be thrown.
        /// </remarks>
        public virtual void DeleteConfig(Boolean restartRequired) {
            if (CryptoRegistry.Ping(ComputerName)) {

            } else if (CertificateAuthority.Ping(ComputerName)) {

            } else {
                throw new ServerUnavailableException(DisplayName);
            }
        }
    }
}
