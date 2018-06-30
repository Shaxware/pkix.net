using System;
using System.Collections.Generic;
using System.Linq;
using SysadminsLV.PKI.Management.ActiveDirectory;

namespace PKI.Management.ActiveDirectory {
    public class DsAiaContainer : DsPkiContainer {
        IList<DsAiaEntry> _list = new List<DsAiaEntry>();

        public DsAiaContainer() {
            ContainerType = DsContainerType.NTAuth;
            BaseEntryPath = "CN=AIA";
        }

        public DsAiaEntry AddChild(String name) {
            var childDsEntry = BaseEntry.Children.Add(name, "certificationAuthority");
            BaseEntry.CommitChanges();
            var entry = new DsAiaEntry(childDsEntry.Name, this);
            _list.Add(entry);
            return entry;
        }
        public DsAiaEntry RemoveChild(String name) {
            DsAiaEntry entry = _list.FirstOrDefault(x => x.DsPath.Equals($"CN={name},{BaseEntryPath}", StringComparison.OrdinalIgnoreCase));
            if (_list.Remove(entry)) {
                throw new ArgumentException("Specified object was not found");
            }

            return entry;
        }

        /// <inheritdoc />
        public override void SaveChanges(Boolean forceDelete) {
            throw new NotImplementedException();
        }
    }
}
