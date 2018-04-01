using System;
using System.Collections;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using CERTENROLLLib;
using Microsoft.Win32.SafeHandles;
using PKI.Structs;
using PKI.Utils;

namespace PKI.ServiceProviders {
    /// <summary>
    /// This class is used to obtain installed about Cryptographic Service Providers, Key Storage Providers and their parameters.
    /// </summary>
    [Obsolete]
    public static class Csp {

        /// <summary>
        /// Retrives Cryptographic Service Providers (CSPs).
        /// </summary>
        /// <returns>List of installed CSPs and their parameters.</returns>
        /// <remarks>This method is deprecated.</remarks>
        [Obsolete("Use 'CspProviderInfoCollection.GetProviderInfo' class.")]
        public static CspCollection EnumLegacyProviders() {
            return m_enumprovs();
        }
        ///  <summary>
        ///  Retrieves Key Storage Providers (also known as CNG providers).
        ///  </summary>
        /// <exception cref="PlatformNotSupportedException">
        ///		The exception is thrown if the method is executed on <strong>Windows XP</strong> or
        /// 		<strong>Windows Server 2003</strong> operating system.
        /// </exception>
        /// <returns>List of installed Key Storage Providers and their parameters</returns>
        /// <remarks>This method is deprecated.</remarks>
        [Obsolete("Use 'CspProviderInfoCollection.GetProviderInfo' class.")]
        public static CspCNGCollection EnumCNGProviders() {
            if (!CryptographyUtils.TestCNGCompat()) { throw new PlatformNotSupportedException(); }
            return m_enumcngprovs();
        }
        /// <summary>
        /// Retrives Cryptographic Service Providers (CSPs). This method returns both, legacy and CNG providers.
        /// </summary>
        /// <exception cref="PlatformNotSupportedException">
        ///		The exception is thrown if the method is executed on <strong>Windows XP</strong> or
        ///		<strong>Windows Server 2003</strong> operating system.
        /// </exception>
        /// <returns>An array of registered cryptographic service providers.</returns>
        [Obsolete("Use 'CspProviderInfoCollection.GetProviderInfo' class.")]
        public static CspObject[] EnumProviders() {
            if (!CryptographyUtils.TestCNGCompat()) { throw new PlatformNotSupportedException(); }
            var csps = new CCspInformations();
            csps.AddAvailableCsps();

            return (from ICspInformation csp in csps select new CspObject(csp)).ToArray();
        }

        static CspCollection m_enumprovs() {
            Hashtable ProvTypes = get_provtypes();
            StringBuilder pszProvName = new StringBuilder();
            CspCollection csps = new CspCollection();

            uint dwIndex = 0;
            uint pdwProvType = 0;
            uint pcbProvName = 0;
            while (AdvAPI.CryptEnumProviders(dwIndex, 0, 0, ref pdwProvType, null, ref pcbProvName)) {
                pszProvName.Length = (Int32)pcbProvName;
                // retrieve CSP
                if (!AdvAPI.CryptEnumProviders(dwIndex++, 0, 0, ref pdwProvType, pszProvName, ref pcbProvName)) {
                    throw new Win32Exception(Error.InvalidDataException);
                }
                String name = pszProvName.ToString();
                String pType = (String)ProvTypes[pdwProvType];
                IntPtr phProv = IntPtr.Zero;
                // retrieve CSP context
                if (!AdvAPI.CryptAcquireContext(ref phProv, null, name, pdwProvType, Wincrypt.CRYPT_VERIFYCONTEXT)) {
                    throw new Win32Exception(Error.InavlidHandleException);
                }
                Int32 pdwDataLen = 0;
                ALG_IDCollection algs = new ALG_IDCollection();
                if (AdvAPI.CryptGetProvParam(phProv, 0x16, null, ref pdwDataLen, Wincrypt.CRYPT_FIRST)) {
                    Byte[] pbData = new Byte[Marshal.SizeOf(typeof(Wincrypt.PROV_ENUMALGS_EX))];
                    while (AdvAPI.CryptGetProvParam(phProv, 0x16, pbData, ref pdwDataLen, Wincrypt.CRYPT_NEXT)) {
                        IntPtr ptr = Marshal.AllocHGlobal(pbData.Length);
                        Marshal.Copy(pbData, 0, ptr, pbData.Length);
                        Wincrypt.PROV_ENUMALGS_EX AlgStructure =
                            (Wincrypt.PROV_ENUMALGS_EX)Marshal.PtrToStructure(ptr, typeof(Wincrypt.PROV_ENUMALGS_EX));
                        Marshal.FreeHGlobal(ptr);
                        ALG_ID alg = get_algparams(AlgStructure);
                        algs.Add(alg);
                    }
                    csps.Add(new CspLegacy(name, pType, algs));
                } else {
                    csps.Add(new CspLegacy(name, pType, algs));
                }
                AdvAPI.CryptReleaseContext(phProv, 0);
            }
            return csps;
        }
        static CspCNGCollection m_enumcngprovs() {
            UInt32 pImplCount = 0;
            IntPtr ppImplList = IntPtr.Zero;
            StringBuilder SB = new StringBuilder();
            Hashtable interfaces = get_interfaces();
            CspCNGCollection csps = new CspCNGCollection();

            Int32 retn = nCrypt.NCryptEnumStorageProviders(ref pImplCount, ref ppImplList, 0);
            if (retn != 0) {
                throw new Win32Exception(unchecked((Int32)retn));
            }
            IntPtr pvInput = ppImplList;
            for (Int32 index = 0; index < pImplCount; index++) {
                nCrypt2.NCryptProviderName Name =
                    (nCrypt2.NCryptProviderName)Marshal.PtrToStructure(ppImplList, typeof(nCrypt2.NCryptProviderName));
                ppImplList = (IntPtr)((UInt64)ppImplList + (UInt32)Marshal.SizeOf(typeof(nCrypt2.NCryptProviderName)));
                SB.Append(Name.pszName + ",");
            }
            String[] names = SB.ToString().Split(",".ToCharArray(), StringSplitOptions.RemoveEmptyEntries);
            nCrypt.NCryptFreeBuffer(pvInput);
            foreach (String pszProviderName in names) {
                ALG_ID_CNGCollection algs = new ALG_ID_CNGCollection();
                retn = nCrypt.NCryptOpenStorageProvider(out SafeNCryptProviderHandle phProvider, pszProviderName, 0);
                if (retn == 0) {
                    Int32 pdwAlgCount = 0;
                    IntPtr ppAlgList = IntPtr.Zero;
                    retn = nCrypt.NCryptEnumAlgorithms(phProvider, 0, ref pdwAlgCount, ref ppAlgList, 0);
                    if (retn != 0) {
                        throw new Win32Exception(unchecked((Int32)retn));
                    }
                    pvInput = ppAlgList;
                    for (Int32 index = 0; index < pdwAlgCount; index++) {
                        nCrypt2.NCryptAlgorithmName AlgId =
                            (nCrypt2.NCryptAlgorithmName)Marshal.PtrToStructure(ppAlgList, typeof(nCrypt2.NCryptAlgorithmName));
                        algs.Add(get_cngalgparams(AlgId, interfaces));
                        ppAlgList = (IntPtr)((UInt64)ppAlgList + (UInt32)Marshal.SizeOf(typeof(nCrypt2.NCryptAlgorithmName)));
                    }
                    nCrypt.NCryptFreeBuffer(pvInput);
                }
                csps.Add(new CspCNG(pszProviderName, String.Empty, algs));
            }
            return csps;
        }
        static Hashtable get_provtypes() {
            UInt32 dwIndex = 0;
            UInt32 pdwProvType = 0;
            UInt32 pcbTypeName = 0;
            StringBuilder pszTypeName = new StringBuilder();
            Hashtable ProvTypes = new Hashtable();

            while (AdvAPI.CryptEnumProviderTypes(dwIndex, 0, 0, ref pdwProvType, null, ref pcbTypeName)) {
                pszTypeName.Length = (Int32)pcbTypeName;
                if (AdvAPI.CryptEnumProviderTypes(dwIndex++, 0, 0, ref pdwProvType, pszTypeName, ref pcbTypeName)) {
                    String pType = pszTypeName.ToString();
                    ProvTypes.Add(pdwProvType, pType);
                }
            }
            return ProvTypes;
        }
        static Hashtable get_interfaces() {
            Hashtable interfaces = new Hashtable {
                {3, "Asymmetric encryption"},
                {4, "Secret agreement"},
                {5, "Signature interface"},
                {0x00010001, "Key storage interface"},
                {0x00010002, "SChannel interface"},
                {0x00010003, "SChannel signature interface"}
            };
            return interfaces;
        }
        static ALG_ID get_algparams(Wincrypt.PROV_ENUMALGS_EX algStructure) {
            Int16[] options = new Int16[] { 1, 2, 4, 8, 16, 32 };
            List<String> szProtocols = new List<string>();

            List<Int16> validoptions = options.Where(dwData => (algStructure.dwProtocols & dwData) != 0).ToList();
            foreach (Int16 opt in validoptions) {
                switch (opt) {
                    case 1:
                        szProtocols.Add("Private communications transport (PCT) version 1 protocol");
                        break;
                    case 2:
                        szProtocols.Add("Secure sockets layer (SSL) version 2 protocol");
                        break;
                    case 4:
                        szProtocols.Add("SSL version 3 protocol");
                        break;
                    case 8:
                        szProtocols.Add("Transport layer security (TLS) version 1 protocol");
                        break;
                    case 16:
                        szProtocols.Add("Internet protocol security (IPsec) protocol");
                        break;
                    case 32:
                        szProtocols.Add("Signing protocol");
                        break;
                }
            }
            return new ALG_ID(
                algStructure.szName,
                algStructure.szLongName,
                szProtocols.ToArray(),
                algStructure.dwDefaultLen,
                algStructure.dwMinLen,
                algStructure.dwMaxLen,
                algStructure.aiAlgid
            );
        }
        static ALG_ID_CNG get_cngalgparams(nCrypt2.NCryptAlgorithmName algId, IDictionary interfaces) {
            Int32[] options = { 4, 8, 16 };
            Int32[] validoptions = new Int32[0];
            String[] operations = new String[0];
            Int32 index = 0;

            foreach (int dwAlgOperations in options.Where(dwAlgOperations => (algId.dwAlgOperations & dwAlgOperations) != 0)) {
                Array.Resize(ref validoptions, index + 1);
                validoptions.SetValue(dwAlgOperations, index);
                index++;
            }
            index = 0;
            foreach (Int32 opt in validoptions) {
                switch (opt) {
                    case 4:
                        Array.Resize(ref operations, index + 1);
                        operations.SetValue("Asymmetric encryption", index);
                        break;
                    case 8:
                        Array.Resize(ref operations, index + 1);
                        operations.SetValue("Secret agreement", index);
                        break;
                    case 16:
                        Array.Resize(ref operations, index + 1);
                        operations.SetValue("Signature", index);
                        break;
                }
            }
            return new ALG_ID_CNG(algId.pszName, (String)interfaces[algId.dwClass], operations);
        }
    }
}
