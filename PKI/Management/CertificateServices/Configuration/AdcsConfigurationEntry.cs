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
    public abstract class AdcsConfigurationEntry {
        readonly String _computer;
        readonly CryptoRegistry _configProvider;
        /// <summary>
        /// Initializes a new instance of <strong>AdcsConfigurationEntry</strong> from Certification Authority object.
        /// </summary>
        /// <param name="certificateAuthority">
        /// Certificate Authority object associated with configuration object.
        /// </param>
        /// <exception cref="ArgumentNullException">
        /// <strong>certificateAuthority</strong> parameter is null.
        /// </exception>
        protected AdcsConfigurationEntry(CertificateAuthority certificateAuthority) {
            if (certificateAuthority == null) {
                throw new ArgumentNullException(nameof(certificateAuthority));
            }
            _computer = certificateAuthority.ComputerName;
            String name = certificateAuthority.Name;
            _configProvider = new CryptoRegistry(certificateAuthority.ComputerName, name);
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
            entry.Value = _configProvider.GetRemoteRegistryValue(entry.NodePath, entry.ValueName);
        }
        void readRpcDcom(AdcsInternalConfigPath entry) {
            entry.Value = _configProvider.GetRpcDcomValue(entry.NodePath, entry.ValueName);
        }
        void writeRemoteRegistry(AdcsInternalConfigPath entry) {
            _configProvider.SetRemoteRegistryValue(entry);
        }
        void writeRpcDcom(AdcsInternalConfigPath entry) {
            _configProvider.SetRpcDcomValue(entry);
        }
        void deleteRemoteRegistry(AdcsInternalConfigPath entry) {

        }
        void deleteRpcDcom(AdcsInternalConfigPath entry) {

        }

        /// <summary>
        /// Gets a list of registry settings associated with a current composite configuration entry.
        /// Inheritors are responsible for list maintenance.
        /// </summary>
        protected IList<AdcsInternalConfigPath> RegEntries { get; } = new List<AdcsInternalConfigPath>();

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
        protected virtual void ReadConfig() {
            if (_configProvider.PingRemoteRegistry()) {
                foreach (AdcsInternalConfigPath entry in RegEntries) {
                    readRemoteRegistry(entry);
                }
            } else if (_configProvider.PingRpcDcom()) {
                foreach (AdcsInternalConfigPath entry in RegEntries) {
                    readRpcDcom(entry);
                }
            } else {
                var e = new ServerUnavailableException(DisplayName);
                e.Data.Add(nameof(e.Source), OfflineSource.DCOM | OfflineSource.Registry);
                throw e;
            }
        }
        /// <summary>
        /// Saves current configuration back to CA configuration. This method is based on registry configuration.
        /// For custom configurations implementers must override this method.
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
            if (!IsModified) { return false; }
            if (_configProvider.PingRemoteRegistry()) {
                foreach (AdcsInternalConfigPath entry in RegEntries) {
                    writeRemoteRegistry(entry);
                }
            } else if (_configProvider.PingRpcDcom()) {
                foreach (AdcsInternalConfigPath entry in RegEntries) {
                    writeRpcDcom(entry);
                }
            } else {
                var e = new ServerUnavailableException(DisplayName);
                e.Data.Add(nameof(e.Source), OfflineSource.DCOM | OfflineSource.Registry);
                throw e;
            }

            IsModified = false;
            if (restartRequired) {
                CertificateAuthority.Restart(_computer);
            }
            return true;
        }

        /// <summary>
        /// Deletes specified configuration entry from CA server. This method is not implemented and reserved for
        /// future use.
        /// </summary>
        /// <param name="restartRequired">
        /// Indiciates whether Certification Authority service restart is required when at least one property is
        /// successfully commited to CA registry.
        /// </param>
        /// <exception cref="NotImplementedException">The method is not implemented.</exception>
        /// <remarks>
        /// This method attempts to write registry by using remote registry. If remote registry fails, ADCS DCOM
        /// registry access is attempted. If both methods fails, a <see cref="ServerUnavailableException"/> will
        /// be thrown.
        /// </remarks>
        public virtual void DeleteConfig(Boolean restartRequired) {
            if (CryptoRegistry.Ping(ComputerName)) {
                throw new NotImplementedException();
            } else if (CertificateAuthority.Ping(ComputerName)) {
                throw new NotImplementedException();
            } else {
                var e = new ServerUnavailableException(DisplayName);
                e.Data.Add(nameof(e.Source), OfflineSource.DCOM | OfflineSource.Registry);
                throw e;
            }
        }
    }
}
