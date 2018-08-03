using System;
using System.Collections.Specialized;
using System.ComponentModel;
using System.Linq;

namespace SysadminsLV.PKI.Management.CertificateServices.Configuration {
    public sealed class AdcsAiaExtensionConfig : AdcsCAConfigurationEntry {
        public AdcsAiaExtensionConfig(AdcsCertificateAuthority certificateAuthority) : base(certificateAuthority) {
            URLs.PropertyChanged += OnItemsPropertyChanged;
            RegEntries.Add(new AdcsInternalConfigPath { ValueName = "CACertPublicationURLs" });
            ReadConfig();
            m_initialize();
            URLs.CollectionChanged += OnItemsCollectionChanged;
        }

        public AiaUriCollection URLs { get; } = new AiaUriCollection(true);

        void m_initialize() {
            foreach (String entry in (String[])RegEntries[0].Value) {
                URLs.Add(new AiaConfigUri(entry));
            }
        }
        void OnItemsCollectionChanged(Object Sender, NotifyCollectionChangedEventArgs NotifyCollectionChangedEventArgs) {
            updateData();
            IsModified = true;
        }
        void OnItemsPropertyChanged(Object s, PropertyChangedEventArgs e) {
            if (e.PropertyName == "child") {
                updateData();
                IsModified = true;
            }
        }
        void updateData() {
            RegEntries[0].Value = URLs.Select(x => x.GetConfigUri()).ToArray();
        }
    }
}
