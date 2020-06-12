using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using CERTADMINLib;
using PKI.Utils;

namespace SysadminsLV.PKI.Dcom.Implementations {
    /// <summary>
    /// Represents a managed implementation of <see cref="ICertRegManagerD"/> interface and used to manage ADCS Certification Authority configuration.
    /// </summary>
    public class CertRegManagerD : ICertRegManagerD {
        readonly String _configString;

        /// <summary>
        /// Initializes a new instance of <strong>CertRegManagerD</strong> class from a Certification Authority configuration string.
        /// </summary>
        /// <param name="configString"></param>
        /// <exception cref="ArgumentNullException">
        /// <strong>configString</strong> parameter is null.
        /// </exception>
        public CertRegManagerD(String configString) {
            _configString = configString ?? throw new ArgumentNullException(nameof(configString));
        }

        /// <inheritdoc />
        public Object GetConfigEntry(String entryName, String node = "") {
            ICertAdmin2 certAdmin = new CCertAdminClass();
            try {
                return certAdmin.GetConfigEntry(_configString, node ?? String.Empty, entryName ?? String.Empty);
            } catch (Exception ex) {
                if (ex is FileNotFoundException) {
                    return null;
                }
                throw;
            } finally {
                CryptographyUtils.ReleaseCom(certAdmin);
            }
        }
        /// <inheritdoc />
        public T GetConfigEntry<T>(String entryName, String node = "") {
            ICertAdmin2 certAdmin = new CCertAdminClass();
            try {
                return (T)certAdmin.GetConfigEntry(_configString, node ?? String.Empty, entryName ?? String.Empty);
            } finally {
                CryptographyUtils.ReleaseCom(certAdmin);
            }
        }
        /// <inheritdoc />
        public String GetStringConfigEntry(String entryName, String node = "") {
            return GetConfigEntry<String>(entryName, node);
        }
        /// <inheritdoc />
        public String[] GetMultiStringConfigEntry(String entryName, String node = "") {
            return GetConfigEntry<String[]>(entryName, node);
        }
        /// <inheritdoc />
        public Int32 GetNumericConfigEntry(String entryName, String node = "") {
            return GetConfigEntry<Int32>(entryName, node);
        }
        /// <inheritdoc />
        public Boolean GetBooleanConfigEntry(String entryName, String node = "") {
            return GetConfigEntry<Int32>(entryName, node) != 0;
        }
        /// <inheritdoc />
        public Byte[] GetBinaryConfigEntry(String entryName, String node = "") {
            return GetConfigEntry<Byte[]>(entryName, node);
        }
        /// <inheritdoc />
        public void SetConfigEntry(Object data, String entryName, String node = "") {
            if (data == null) {
                throw new ArgumentNullException(nameof(data));
            }

            ICertAdmin2 certAdmin = new CCertAdminClass();

            try {
                switch (data) {
                    case String _:
                    case Int32 _:
                        certAdmin.SetConfigEntry(_configString, node, entryName, data);
                        break;
                    case Boolean b:
                        certAdmin.SetConfigEntry(_configString, node, entryName, b ? 1 : 0);
                        break;
                    case IEnumerable<String> array:
                        certAdmin.SetConfigEntry(_configString, node, entryName, array.ToArray());
                        break;
                    case IEnumerable<Byte> array:
                        certAdmin.SetConfigEntry(_configString, node, entryName, array.ToArray());
                        break;
                    default:
                        throw new ArgumentException();

                }
            } finally {
                CryptographyUtils.ReleaseCom(certAdmin);
            }
        }
        /// <inheritdoc />
        public void DeleteConfigEntry(String entryName, String node = "") {
            ICertAdmin2 certAdmin = new CCertAdminClass();
            try {
                certAdmin.SetConfigEntry(_configString, node ?? String.Empty, entryName ?? String.Empty, null);
            } catch (Exception ex) {
                if (!(ex is FileNotFoundException)) {
                    throw;
                }
            } finally {
                CryptographyUtils.ReleaseCom(certAdmin);
            }
        }
    }
}