using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Win32.SafeHandles;
using PKI.Exceptions;
using PKI.Structs;
using PKI.Utils;
using SysadminsLV.PKI.Win32;

namespace SysadminsLV.PKI.Utils.CLRExtensions {
    /// <summary>
    /// Contains extension methods for <see cref="X509Certificate2"/> class.
    /// </summary>
    public static class X509Certificate2Extensions {
        /// <summary>
        /// Converts generic X.509 extension objects to specialized certificate extension objects
        /// inherited from <see cref="X509Extension"/> class that provide extension-specific information.
        /// </summary>
        /// <param name="cert">Certificate.</param>
        /// <exception cref="ArgumentNullException">
        /// <strong>cert</strong> parameter is null reference.
        /// </exception>
        /// <returns>A collection of certificate extensions</returns>
        /// <remarks>
        /// This method can transform the following X.509 certificate extensions:
        /// <list type="bullet">
        /// <item><description><see cref="X509CertificateTemplateExtension"/></description></item>
        /// <item><description><see cref="X509ApplicationPoliciesExtension"/></description></item>
        /// <item><description><see cref="X509ApplicationPolicyMappingsExtension"/></description></item>
        /// <item><description><see cref="X509ApplicationPolicyConstraintsExtension"/></description></item>
        /// <item><description><see cref="X509AuthorityInformationAccessExtension"/></description></item>
        /// <item><description><see cref="X509NonceExtension"/></description></item>
        /// <item><description><see cref="X509CRLReferenceExtension"/></description></item>
        /// <item><description><see cref="X509ArchiveCutoffExtension"/></description></item>
        /// <item><description><see cref="X509ServiceLocatorExtension"/></description></item>
        /// <item><description><see cref="X509SubjectKeyIdentifierExtension"/></description></item>
        /// <item><description><see cref="X509KeyUsageExtension"/></description></item>
        /// <item><description><see cref="X509SubjectAlternativeNamesExtension"/></description></item>
        /// <item><description><see cref="X509IssuerAlternativeNamesExtension"/></description></item>
        /// <item><description><see cref="X509BasicConstraintsExtension"/></description></item>
        /// <item><description><see cref="X509CRLNumberExtension"/></description></item>
        /// <item><description><see cref="X509NameConstraintsExtension"/></description></item>
        /// <item><description><see cref="X509CRLDistributionPointsExtension"/></description></item>
        /// <item><description><see cref="X509CertificatePoliciesExtension"/></description></item>
        /// <item><description><see cref="X509CertificatePolicyMappingsExtension"/></description></item>
        /// <item><description><see cref="X509AuthorityKeyIdentifierExtension"/></description></item>
        /// <item><description><see cref="X509CertificatePolicyConstraintsExtension"/></description></item>
        /// <item><description><see cref="X509EnhancedKeyUsageExtension"/></description></item>
        /// <item><description><see cref="X509FreshestCRLExtension"/></description></item>
        /// </list>
        /// Non-supported extensions will be returned as an <see cref="X509Extension"/> object.
        /// </remarks>
        public static X509ExtensionCollection ResolveExtensions (this X509Certificate2 cert) {
            if (cert == null) { throw new ArgumentNullException(nameof(cert)); }
            if (cert.Extensions.Count == 0) { return cert.Extensions; }
            X509ExtensionCollection extensions = new X509ExtensionCollection();
            foreach (var ext in cert.Extensions) {
                extensions.Add(CryptographyUtils.ConvertExtension(ext));
            }
            return extensions;
        }

        /// <summary>
        /// Gets the list of certificate properties associated with the current certificate object.
        /// </summary>
        /// <param name="cert">Certificate.</param>
        /// <exception cref="ArgumentNullException">
        /// <strong>cert</strong> parameter is null reference.
        /// </exception>
        /// <exception cref="UninitializedObjectException">
        /// Certificate object is not initialized and is empty.
        /// </exception>
        /// <returns>An array of certificate context property types associated with the current certificate.</returns>
        public static X509CertificatePropertyType[] GetCertificateContextPropertyList(this X509Certificate2 cert) {
            if (cert == null) { throw new ArgumentNullException(nameof(cert)); }
            if (IntPtr.Zero.Equals(cert.Handle)) { throw new UninitializedObjectException(); }
            List<X509CertificatePropertyType> props = new List<X509CertificatePropertyType>();
            UInt32 propID = 0;
            while ((propID = Crypt32.CertEnumCertificateContextProperties(cert.Handle, propID)) > 0) {
                props.Add((X509CertificatePropertyType)propID);
            }
            return props.ToArray();
        }
        /// <summary>
        /// Gets a specified certificate context property.
        /// </summary>
        /// <param name="cert">Certificate.</param>
        /// <param name="propID">Property ID to retrieve.</param>
        /// <exception cref="ArgumentNullException">
        /// <strong>cert</strong> parameter is null reference.
        /// </exception>
        /// <exception cref="UninitializedObjectException">
        /// Certificate object is not initialized and is empty.
        /// </exception>
        /// <exception cref="Exception">
        /// Requested context property is not found for the current certificate object.
        /// </exception>
        /// <returns>Specified certificate context property.</returns>
        public static X509CertificateContextProperty GetCertificateContextProperty(this X509Certificate2 cert, X509CertificatePropertyType propID) {
            if (cert == null) { throw new ArgumentNullException(nameof(cert)); }
            if (IntPtr.Zero.Equals(cert.Handle)) { throw new UninitializedObjectException(); }
            UInt32 pcbData = 0;
            switch (propID) {
                case X509CertificatePropertyType.Handle:
                case X509CertificatePropertyType.KeyContext:
                case X509CertificatePropertyType.ProviderInfo:
                    if (!Crypt32.CertGetCertificateContextProperty(cert.Handle, (UInt32)propID, IntPtr.Zero, ref pcbData)) {
                        throw new Exception("No such property.");
                    }
                    IntPtr ptr = Marshal.AllocHGlobal((Int32)pcbData);
                    Crypt32.CertGetCertificateContextProperty(cert.Handle, (UInt32)propID, ptr, ref pcbData);
                    try {
                        return new X509CertificateContextProperty(cert, propID, ptr);
                    } finally {
                        Marshal.FreeHGlobal(ptr);
                    }
                // byte[]
                default:
                    if (!Crypt32.CertGetCertificateContextProperty(cert.Handle, (UInt32)propID, null, ref pcbData)) {
                        throw new Exception("No such property.");
                    }
                    Byte[] bytes = new byte[pcbData];
                    Crypt32.CertGetCertificateContextProperty(cert.Handle, (UInt32)propID, bytes, ref pcbData);
                    return new X509CertificateContextProperty(cert, propID, bytes);
            }
        }
        /// <summary>
        /// Gets a collection of certificate context properties associated with the current certificate. If no
        /// property is associated, an empty collection will be returned.
        /// </summary>
        /// <param name="cert">Certificate.</param>
        /// <exception cref="ArgumentNullException">
        /// <strong>cert</strong> parameter is null reference.
        /// </exception>
        /// <exception cref="UninitializedObjectException">
        /// Certificate object is not initialized and is empty.
        /// </exception>
        /// <returns>A collection of certificate context properties.</returns>
        public static X509CertificateContextPropertyCollection GetCertificateContextProperties(this X509Certificate2 cert) {
            if (cert == null) { throw new ArgumentNullException(nameof(cert)); }
            if (IntPtr.Zero.Equals(cert.Handle)) { throw new UninitializedObjectException(); }
            X509CertificatePropertyType[] props = GetCertificateContextPropertyList(cert);
            X509CertificateContextPropertyCollection properties = new X509CertificateContextPropertyCollection();
            foreach (X509CertificatePropertyType propID in props) {
                properties.Add(GetCertificateContextProperty(cert, propID));
            }
            properties.Close();
            return properties;
        }
        /// <summary>
        /// Deletes private key material associated with a X.509 certificate from file system or hardware storage.
        /// </summary>
        /// <param name="cert">An instance of X.509 certificate.</param>
        /// <returns>
        /// <strong>True</strong> if associated private key was found and successully deleted, otherwise <strong>False</strong>.
        /// </returns>
        public static Boolean DeletePrivateKey(this X509Certificate2 cert) {
            if (!Crypt32.CryptAcquireCertificatePrivateKey(
                cert.Handle,
                Wincrypt.CRYPT_ACQUIRE_ALLOW_NCRYPT_KEY_FLAG,
                IntPtr.Zero,
                out SafeNCryptKeyHandle phCryptProvOrNCryptKey,
                out UInt32 pdwKeySpec,
                out Boolean _)) { return false; }
            return pdwKeySpec == UInt32.MaxValue
                ? deleteCngKey(phCryptProvOrNCryptKey)
                : deleteLegacyKey(cert.PrivateKey);
        }
        static Boolean deleteLegacyKey(AsymmetricAlgorithm privateKey) {
            if (privateKey == null) { return false; }
            String keyContainer;
            String provName;
            UInt32 provType;
            switch (privateKey) {
                case RSACryptoServiceProvider _:
                    keyContainer = ((RSACryptoServiceProvider) privateKey).CspKeyContainerInfo.KeyContainerName;
                    provName = ((RSACryptoServiceProvider)privateKey).CspKeyContainerInfo.ProviderName;
                    provType = (UInt32) ((RSACryptoServiceProvider)privateKey).CspKeyContainerInfo.ProviderType;
                    break;
                case DSACryptoServiceProvider _:
                    keyContainer = ((DSACryptoServiceProvider)privateKey).CspKeyContainerInfo.KeyContainerName;
                    provName = ((DSACryptoServiceProvider)privateKey).CspKeyContainerInfo.ProviderName;
                    provType = (UInt32) ((DSACryptoServiceProvider)privateKey).CspKeyContainerInfo.ProviderType;
                    break;
                default:
                    privateKey.Dispose();
                    return false;
            }
            IntPtr phProv = IntPtr.Zero;
            var status = AdvAPI.CryptAcquireContext(
                ref phProv,
                keyContainer,
                provName,
                provType,
                Wincrypt.CRYPT_DELETEKEYSET);
            privateKey.Dispose();
            return status;
        }
        static Boolean deleteCngKey(SafeNCryptKeyHandle phKey) {
            var hresult = NCrypt.NCryptDeleteKey(phKey, 0);
            phKey.Dispose();
            return hresult == 0;
        }
    }
}
