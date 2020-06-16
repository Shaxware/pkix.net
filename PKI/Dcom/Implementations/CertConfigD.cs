using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using CERTCLILib;

namespace SysadminsLV.PKI.Dcom.Implementations {
    /// <summary>
    /// Represents Windows implementation for <see cref="ICertConfigD"/> interface.
    /// </summary>
    public class CertConfigD : ICertConfigD {

        String getConfig(CertConfigOption option) {
            var certConfig = new CCertConfigClass();
            try {
                return certConfig.GetConfig((Int32)option);
            } catch {
                return null;
            } finally {
                Marshal.FinalReleaseComObject(certConfig);
            }
        }

        /// <inheritdoc />
        public String GetDefaultConfig() {
            return getConfig(CertConfigOption.DefaultConfig);
        }
        /// <inheritdoc />
        public String GetFirstConfig() {
            return getConfig(CertConfigOption.FirstConfig);
        }
        /// <inheritdoc />
        public String GetLocalConfig() {
            return getConfig(CertConfigOption.LocalConfig);
        }
        /// <inheritdoc />
        public String GetLocalActiveConfig() {
            return getConfig(CertConfigOption.LocalActiveConfig);
        }
        /// <inheritdoc />
        public String GetUIConfig() {
            return getConfig(CertConfigOption.UIPickConfig);
        }
        /// <inheritdoc />
        public String GetUISkipLocalConfig() {
            return getConfig(CertConfigOption.UIPickConfigSkipLocalCA);
        }
        /// <inheritdoc />
        public ICertConfigEntryD[] EnumConfigEntries() {
            var list = new List<ICertConfigEntryD>();
            var certConfig = new CCertConfigClass();
            while (certConfig.Next() >= 0) {
                list.Add(new CertConfigEntryD(certConfig));
            }
            Marshal.FinalReleaseComObject(certConfig);
            return list.ToArray();
        }
        /// <inheritdoc />
        public ICertConfigEntryD FindConfigEntryByName(String caName) {
            var certConfig = new CCertConfigClass();

            while (certConfig.Next() >= 0) {
                try {
                    if (certConfig.GetField("CommonName").Equals(caName, StringComparison.CurrentCultureIgnoreCase)) {
                        var entry = new CertConfigEntryD(certConfig);
                        Marshal.FinalReleaseComObject(certConfig);
                        return entry;
                    }
                } catch { }
            }
            return null;
        }
        /// <inheritdoc />
        public ICertConfigEntryD FindConfigEntryByServerName(String computerName) {
            var certConfig = new CCertConfigClass();

            while (certConfig.Next() >= 0) {
                try {
                    if (certConfig.GetField("Server").Equals(computerName, StringComparison.OrdinalIgnoreCase)) {
                        var entry = new CertConfigEntryD(certConfig);
                        Marshal.FinalReleaseComObject(certConfig);
                        return entry;
                    }
                } catch { }
            }
            return null;
        }
    }
}