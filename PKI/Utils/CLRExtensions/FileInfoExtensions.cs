using System;
using System.IO;
using System.Runtime.InteropServices;
using PKI.Structs;
using SysadminsLV.PKI.Cryptography.Pkcs;
using SysadminsLV.PKI.Win32;

namespace SysadminsLV.Utils.CLRExtensions {
    public static class FileInfoExtensions {
        public static DefaultSignedPkcs7 GetSignatureObject(this FileInfo fileInfo) {
            if (!fileInfo.Exists) {
                return null;
            }

            if (!Crypt32.CryptQueryObject(
                Wincrypt.CERT_QUERY_OBJECT_FILE,
                fileInfo.FullName,
                Wincrypt.CERT_QUERY_CONTENT_FLAG_ALL,
                Wincrypt.CERT_QUERY_FORMAT_FLAG_ALL,
                0,
                out Int32 _,
                out Int32 pdwContentType,
                out Int32 _,
                out IntPtr phCertStore,
                out IntPtr phMsg,
                out IntPtr ppvContext
            )) { return null; }

            Byte[] pvData = null;

            if (!IntPtr.Zero.Equals(phCertStore)) {
                Crypt32.CertCloseStore(phCertStore, 0);
            }

            switch (pdwContentType) {
                case Wincrypt.CERT_QUERY_CONTENT_PKCS7_SIGNED:
                case Wincrypt.CERT_QUERY_CONTENT_PKCS7_SIGNED_EMBED:
                case Wincrypt.CERT_QUERY_CONTENT_PKCS7_UNSIGNED:
                    pvData = getMsgBytes(phMsg);
                    break;
                case Wincrypt.CERT_QUERY_CONTENT_CTL:
                case Wincrypt.CERT_QUERY_CONTENT_SERIALIZED_CTL:
                    pvData = getCtlBytes(ppvContext);
                    break;
                case Wincrypt.CERT_QUERY_CONTENT_CERT:
                case Wincrypt.CERT_QUERY_CONTENT_SERIALIZED_CERT:
                    Crypt32.CertFreeCertificateContext(ppvContext);
                    return null;
                case Wincrypt.CERT_QUERY_CONTENT_CRL:
                case Wincrypt.CERT_QUERY_CONTENT_SERIALIZED_CRL:
                    Crypt32.CertFreeCRLContext(ppvContext);
                    return null;
            }

            return pvData == null
                ? null
                : new DefaultSignedPkcs7(pvData);
        }

        static Byte[] getMsgBytes(IntPtr phMsg) {
            try {
                if (!Crypt32.CryptMsgGetParam(phMsg, 29, 0, null, out Int32 pcbData)) {
                    return null;
                }
                Byte[] pvData = new Byte[pcbData];
                Crypt32.CryptMsgGetParam(phMsg, 29, 0, pvData, out _);
                return pvData;
            } finally {
                Crypt32.CryptMsgClose(phMsg);
            }
        }
        static Byte[] getCtlBytes(IntPtr ctlContext) {
            try {
                var ctl = (Wincrypt.CTL_CONTEXT)Marshal.PtrToStructure(ctlContext, typeof(Wincrypt.CTL_CONTEXT));
                var ctlBytes = new Byte[ctl.cbCtlEncoded];
                Marshal.Copy(ctl.pbCtlEncoded, ctlBytes, 0, ctlBytes.Length);
                return ctlBytes;
            }
            finally {
                Crypt32.CertFreeCTLContext(ctlContext);
            }
        }
    }
}
