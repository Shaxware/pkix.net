using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.Security.Cryptography.X509Certificates;
using PKI.Exceptions;
using PKI.Utils;

namespace SysadminsLV.PKI.Management.ActiveDirectory {
    /// <summary>
    /// Represents a base class for PKI-related objects in Active Directory.
    /// </summary>
    public abstract class DsPkiContainer : IDisposable {
        String baseDsEntryPath;
        readonly String _pkiConfigContext;

        /// <summary>
        /// Initializes a new instance of <strong>DsPkiContainer</strong> class.
        /// </summary>
        /// <exception cref="PlatformNotSupportedException">
        /// The calling client is not a member of Active Directory domain or no domain controller can be contacted.
        /// </exception>
        protected DsPkiContainer() {
            if (!DsUtils.Ping()) {
                throw new PlatformNotSupportedException();
            }
            _pkiConfigContext = $",CN=Public Key Services,CN=Services,{DsUtils.ConfigContext}";
        }
        /// <summary>
        /// Gets an X.500 path to an Active Directory container.
        /// </summary>
        public String DsPath => $"{BaseEntryPath}{_pkiConfigContext}";
        /// <summary>
        /// Gets or sets container type in Active Directory.
        /// </summary>
        public DsContainerType ContainerType { get; protected set; }
        /// <summary>
        /// Indicates whether the container contents was changed.
        /// </summary>
        public Boolean IsModified { get; protected set; }
        /// <summary>
        /// Gets or sets a base path to this object in Active Directory.
        /// </summary>
        protected String BaseEntryPath {
            get => baseDsEntryPath;
            set {
                baseDsEntryPath = value;
                // do not throw exception if such object doesn't exist in Active Directory. It should be
                // created during SaveChanges method call.
                try {
                    BaseEntry = new DirectoryEntry($"LDAP://{BaseEntryPath}{_pkiConfigContext}");
                } catch { }

            }
        }
        /// <summary>
        /// Gets an instance of <see cref="DirectoryEntry"/> object associated with a current PKI container.
        /// </summary>
        protected DirectoryEntry BaseEntry { get; set; }

        /// <summary>
        /// Gets a property from an Active Directory object.
        /// </summary>
        /// <typeparam name="T">Specifies the expected output type.</typeparam>
        /// <param name="entry">
        /// A directory entry object. If this parameter is null, a <see cref="BaseEntry"/> object is used.
        /// </param>
        /// <param name="prop">Specifies the property name to query.</param>
        /// <returns>
        /// A collection of values of type speficies in the type parameter.
        /// </returns>
        /// <remarks>
        /// If actual property value doesn't match requested type (specified in the type parameter), the
        /// value is ignored and empty array is returned.
        /// </remarks>
        protected T[] GetEntryProperty<T>(DirectoryEntry entry, String prop) where T : class {
            DirectoryEntry localEntry = entry ?? BaseEntry;
            var list = new List<T>();
            if (localEntry.Properties.Contains(prop)) {
                foreach (Object propValue in localEntry.Properties[prop]) {
                    if (!(propValue is T)) {
                        continue;
                    }
                    list.Add(propValue as T);
                }
            }
            return list.ToArray();
        }
        /// <summary>
        /// Safely adds certificate to a collection. If certificate already exist in the collection, it is not added.
        /// </summary>
        /// <param name="certs">A collection to add the certificate to.</param>
        /// <param name="cert">A certificate object to add to collection.</param>
        /// <exception cref="ArgumentNullException">
        /// <strong>certs</strong> or <strong>cert</strong> parameter is null.
        /// </exception>
        /// <exception cref="UninitializedObjectException">
        /// Certificate object in <strong>cert</strong> parameter is not properly initialized.
        /// </exception>
        /// <returns>
        /// <strong>True</strong> if certificate was added, otherwise <strong>False</strong>. If certificate in
        /// <strong>cert</strong> parameter is already presented in NTAuth store, it is not added again and
        /// the method returns <strong>False</strong>.
        /// </returns>
        /// <remarks>
        /// After required object manipulations, it is necessary to call <see cref="SaveChanges"/> method to
        /// commit changes back to Active Directory.
        /// </remarks>
        protected Boolean SafeAddCertToCollection(IList<X509Certificate2> certs, X509Certificate2 cert) {
            if (cert == null) {
                throw new ArgumentNullException(nameof(cert));
            }
            if (certs == null) {
                throw new ArgumentNullException(nameof(certs));
            }
            if (cert.RawData == null) {
                throw new UninitializedObjectException();
            }
            if (certs.Contains(cert)) {
                return false;
            }
            certs.Add(cert);
            return true;
        }
        /// <summary>
        /// Removes certificate from a specified collection.
        /// </summary>
        /// <param name="certs">A collection to remove the certificate from.</param>
        /// <param name="cert">Certificate to remove.</param>
        /// <exception cref="ArgumentNullException">
        /// <strong>certs</strong> or <strong>cert</strong> parameter is null.
        /// </exception>
        /// <exception cref="UninitializedObjectException">
        /// Certificate object in <strong>cert</strong> parameter is not properly initialized.
        /// </exception> 
        /// <returns>
        /// <strong>True</strong> if certificate was found and deleted, otherwise <strong>False</strong>.
        /// </returns>
        /// <remarks>
        /// After required object manipulations, it is necessary to call <see cref="SaveChanges"/> method to
        /// commit changes back to Active Directory.
        /// </remarks>
        protected static Boolean SafeRemoveCertFromCollection(IList<X509Certificate2> certs, X509Certificate2 cert) {
            if (cert == null) {
                throw new ArgumentNullException(nameof(cert));
            }
            if (cert.RawData == null) {
                throw new UninitializedObjectException();
            }
            if (!certs.Contains(cert)) {
                return false;
            }
            certs.Remove(cert);
            return true;
        }
        protected DirectoryEntry AddSubContainer(String parentPath, String name, String schemaClassName) {
            var entry = new DirectoryEntry(parentPath);
            return entry.Children.Add(name, schemaClassName);
        }

        /// <summary>
        /// Saves changes back to Active Directory.
        /// </summary>
        /// <param name="forceDelete">
        /// Forces object deletion if there are no more elements (certificates, CRLs, etc.).
        /// </param>
        /// <remarks>
        /// Typically, only members of Domain Admins group in forest root domain and members of Enterprise Admins
        /// group have permissions to write to Active Directory configuration naming context. Other members should
        /// be granted delegated permissions to write to configuration naming context.
        /// </remarks>
        public abstract void SaveChanges(Boolean forceDelete);


        #region IDisposable
        protected virtual void Dispose(Boolean disposing) {
            if (disposing) {
                BaseEntry?.Dispose();
            }
        }
        /// <inheritdoc />
        public void Dispose() {
            Dispose(true);
            GC.SuppressFinalize(this);
        }
        #endregion
    }
}
