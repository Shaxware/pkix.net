using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using PKI.Structs;
using SysadminsLV.PKI.Win32;

namespace SysadminsLV.PKI.Cryptography.Pkcs {
    /// <summary>
    /// The <strong>ContentInfo2</strong> class represents the CMS/PKCS #7 ContentInfo data structure as defined in
    /// the CMS/PKCS #7 standards document. This data structure is the basis for all CMS/PKCS #7 messages.
    /// </summary>
    /// <remarks>
    /// This class is a replacement of original <see cref="ContentInfo"/> class. Replacement was made because original
    /// class does not provide expected behavior.
    /// </remarks>
    [Obsolete]
    public sealed class ContentInfo2 {
        /// <summary>
        /// Creates an instance of the <strong>ContentInfo2</strong> class by using an array of byte values as the data.
        /// </summary>
        /// <param name="content">
        /// An array of byte values that represents the data from which to create the <strong>ContentInfo2</strong> object.
        /// </param>
        /// <exception cref="ArgumentNullException"><strong>content</strong> parameter is null or empty array.</exception>
        public ContentInfo2(Byte[] content) {
            if (content == null) { throw new ArgumentNullException(nameof(content)); }
            m_initialize(content);
        }
        internal ContentInfo2(Wincrypt.CRYPTOAPI_BLOB blob) {
            m_initialize2(blob);
        }

        /// <summary>
        /// Gets the type of the inner content of the CMS/PKCS #7 message.
        /// </summary>
        public Oid ContentType { get; private set; }
        /// <summary>
        /// Gets the inner content value (without an envelope).
        /// </summary>
        public Byte[] RawData { get; private set; }

        void m_initialize(Byte[] content) {
            UInt32 pcbStructInfo = 0;
            if (!Crypt32.CryptDecodeObject(1, Wincrypt.PKCS_CONTENT_INFO, content, (UInt32)content.Length, 0, IntPtr.Zero, ref pcbStructInfo)) {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            IntPtr pvStructInfo = Marshal.AllocHGlobal((Int32)pcbStructInfo);
            if (!Crypt32.CryptDecodeObject(1, Wincrypt.PKCS_CONTENT_INFO, content, (UInt32)content.Length, 0, pvStructInfo, ref pcbStructInfo)) {
                Marshal.FreeHGlobal(pvStructInfo);
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            Wincrypt.CRYPT_CONTENT_INFO contentInfo = (Wincrypt.CRYPT_CONTENT_INFO) Marshal.PtrToStructure(pvStructInfo, typeof(Wincrypt.CRYPT_CONTENT_INFO));
            ContentType = new Oid(contentInfo.pszObjId);
            RawData = new Byte[contentInfo.cbData];
            Marshal.Copy(contentInfo.pbData, RawData, 0, (Int32)contentInfo.cbData);
            Marshal.FreeHGlobal(pvStructInfo);
        }
        void m_initialize2(Wincrypt.CRYPTOAPI_BLOB blob) {
            UInt32 pcbStructInfo = 0;
            if (!Crypt32.CryptDecodeObject(1, Wincrypt.PKCS_CONTENT_INFO, blob.pbData, blob.cbData, 0, IntPtr.Zero, ref pcbStructInfo)) {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            IntPtr pvStructInfo = Marshal.AllocHGlobal((Int32)pcbStructInfo);
            if (!Crypt32.CryptDecodeObject(1, Wincrypt.PKCS_CONTENT_INFO, blob.pbData, blob.cbData, 0, pvStructInfo, ref pcbStructInfo)) {
                Marshal.FreeHGlobal(pvStructInfo);
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            Wincrypt.CRYPT_CONTENT_INFO contentInfo = (Wincrypt.CRYPT_CONTENT_INFO)Marshal.PtrToStructure(pvStructInfo, typeof(Wincrypt.CRYPT_CONTENT_INFO));
            ContentType = new Oid(contentInfo.pszObjId);
            RawData = new Byte[contentInfo.cbData];
            Marshal.Copy(contentInfo.pbData, RawData, 0, (Int32)contentInfo.cbData);
            Marshal.FreeHGlobal(pvStructInfo);
        }

        /// <summary>
        /// Gets textual representation of the object.
        /// </summary>
        /// <returns>String that indicates the underlying type stored in the <see cref="RawData"/> member.</returns>
        public override String ToString() {
            return String.IsNullOrEmpty(ContentType.FriendlyName)
                ? ContentType.Value
                : ContentType.FriendlyName + " (" + ContentType.Value + ")";
        }
    }
}
