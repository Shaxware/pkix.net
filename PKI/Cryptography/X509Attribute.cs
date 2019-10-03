﻿using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using PKI.Enrollment;
using SysadminsLV.Asn1Parser;

namespace System.Security.Cryptography {
    /// <summary>
    /// Represents a cryptographic attribute.
    /// </summary>
    public class X509Attribute : AsnEncodedData {
        /// <summary>
        /// Initializes a new instance of the <strong>X509Attribute</strong> class using an Oid object and a byte array
        /// </summary>
        /// <param name="oid">An Oid object that identifies attribute.</param>
        /// <param name="rawData">A byte array that contains Abstract Syntax Notation One (ASN.1)-encoded data.</param>
        public X509Attribute(Oid oid, Byte[] rawData) : base(oid, rawData) { }
        /// <summary>
        ///		Initializes a new instance of the <strong>X509Attribute</strong> class using an Oid object, an integer that
        ///		identifies the tagged attribute and a byte array. This constructor is used only for tagged attributes.
        /// </summary>
        /// <param name="oid">An Oid object that identifies attribute.</param>
        /// <param name="partId">An integer that identifies attribute.</param>
        /// <param name="rawData">A byte array that contains Abstract Syntax Notation One (ASN.1)-encoded data.</param>
        public X509Attribute(Oid oid, Int32 partId, Byte[] rawData) : base(oid, rawData) {
            BodyPartId = partId;
        }

        /// <summary>
        /// Gets the value that identifies the tagged attribute.
        /// </summary>
        /// <remarks>This property is used only for tagged attributes.</remarks>
        public Int32 BodyPartId { get; private set; }

        /// <summary>
        /// Encodes current object to ASN.1-encoded byte array.
        /// </summary>
        /// <returns>ASN.1-encoded byte array.</returns>
        public Byte[] Encode() {
            List<Byte> list = new List<Byte>(Asn1Utils.Encode(RawData, 49));
            list.InsertRange(0, Asn1Utils.EncodeObjectIdentifier(Oid));
            return Asn1Utils.Encode(list.ToArray(), 48);
        }
        /// <summary>
        /// Decodes ASN.1-encoded attribute (with envelope) to an instance of <strong>X509Attribute</strong> class.
        /// </summary>
        /// <param name="rawData">ASN.1-encoded attribute full data.</param>
        /// <exception cref="ArgumentNullException"><strong>rawData</strong> parameter is null.</exception>
        /// <exception cref="Asn1InvalidTagException">Invalid tag identifier occured.</exception>
        /// <returns>Instance of <strong>X509Attribute</strong> class</returns>
        public static X509Attribute Decode(Byte[] rawData) {
            if (rawData == null) { throw new ArgumentNullException(nameof(rawData)); }
            Asn1Reader asn = new Asn1Reader(rawData);
            if (asn.Tag != 48) { throw new Asn1InvalidTagException(asn.Offset); }
            asn.MoveNext();
            Oid oid = Asn1Utils.DecodeObjectIdentifier(asn.GetTagRawData());
            asn.MoveNextAndExpectTags(0x31);
            return new X509Attribute(oid, asn.GetPayload());
        }
        /// <summary>
        /// Returns a formatted version of the Abstract Syntax Notation One (ASN.1)-encoded data as a string.
        /// </summary>
        /// <param name="multiLine">
        /// <strong>True</strong> if the return string should contain carriage returns; otherwise, <strong>False</strong>
        /// </param>
        /// <returns>
        /// A formatted string that represents the Abstract Syntax Notation One (ASN.1)-encoded data
        /// </returns>
        /// <remarks>Use this method if you need to print Abstract Syntax Notation One (ASN.1)-encoded data or output the
        /// information to a text box. Use the <strong>multiLine</strong> parameter to control the layout of the output.</remarks>
        public override String Format(Boolean multiLine) {
            if (RawData != null && RawData.Length != 0) {
                StringBuilder SB = new StringBuilder();
                Asn1Reader asn = new Asn1Reader(RawData);
                switch (Oid.Value) {
                    // Content Type
                    case "1.2.840.113549.1.9.3":
                        Oid value = Asn1Utils.DecodeObjectIdentifier(asn.RawData);
                        SB.Append("Content type (OID=1.2.840.113549.1.9.3): ");
                        if (multiLine) {
                            SB.Append(Environment.NewLine + "    " + value.Value);
                        } else {
                            SB.Append(value.Value);
                        }
                        if (!String.IsNullOrEmpty(value.FriendlyName)) {
                            SB.Append("(" + value.FriendlyName + ")");
                        }
                        break;
                    // Message Digest
                    case "1.2.840.113549.1.9.4":
                        SB.Append("Message Digest (OID=1.2.840.113549.1.9.4): ");
                        if (multiLine) {
                            SB.Append(Environment.NewLine + Asn1Utils.DecodeOctetString(asn.RawData));
                        } else {
                            SB.Append(Asn1Utils.DecodeOctetString(asn.RawData));
                        }
                        break;
                    // Renewal certificate
                    case "1.3.6.1.4.1.311.13.1":
                        X509Certificate2 cert = new X509Certificate2(asn.RawData);
                        SB.Append("Renewal Certificate (OID=1.3.6.1.4.1.311.13.1): ");
                        if (multiLine) {
                            SB.Append(Environment.NewLine + "    " + cert.ToString().Replace("\r\n", "\r\n    "));
                        } else {
                            SB.Append(cert.ToString().Replace("\r\n", " ").Replace("   ", " ").Replace("  ", ", "));
                        }
                        break;
                    //  Enrollment Name Value Pair
                    case "1.3.6.1.4.1.311.13.2.1":
                        asn.MoveNext();
                        SB.Append("Enrollment Name Value Pair (OID=1.3.6.1.4.1.311.13.2.1): ");
                        if (multiLine) {
                            SB.Append(Environment.NewLine + "    ");
                        }
                        SB.Append(Encoding.BigEndianUnicode.GetString(asn.GetPayload()) + "=");
                        asn.MoveNext();
                        SB.Append(Encoding.BigEndianUnicode.GetString(asn.GetPayload()));
                        if (multiLine) { SB.Append(Environment.NewLine); }
                        break;
                    // CSP Info
                    case "1.3.6.1.4.1.311.13.2.2":
                        asn.MoveNext();
                        SB.Append("CSP Info (OID=1.3.6.1.4.1.311.13.2.2): ");
                        if (multiLine) { SB.Append(Environment.NewLine + "    "); }
                        if (asn.Tag == (Int32)Asn1Type.INTEGER) {
                            SB.Append("KeySpec: " + asn.GetPayload()[0]);
                            asn.MoveNext();
                        }
                        if (multiLine) { SB.Append(Environment.NewLine + "    "); } else { SB.Append(", "); }
                        if (asn.Tag == (Int32)Asn1Type.BMPString) {
                            SB.Append("Provider: " + Encoding.BigEndianUnicode.GetString(asn.GetPayload()));
                            asn.MoveNext();
                        }
                        if (multiLine) { SB.Append(Environment.NewLine + "    "); } else { SB.Append(", "); }
                        if (asn.Tag == (Int32)Asn1Type.BIT_STRING) {
                            SB.Append("Signature unused bits: " + asn.GetPayload()[0]);
                        }
                        if (multiLine) { SB.Append(Environment.NewLine); }
                        break;
                    //OS version
                    case "1.3.6.1.4.1.311.13.2.3":
                        SB.Append("OS Version (OID=1.3.6.1.4.1.311.13.2.3): " + Asn1Utils.DecodeIA5String(asn.GetTagRawData()));
                        if (multiLine) { SB.Append(Environment.NewLine); }
                        break;
                    // client info
                    case "1.3.6.1.4.1.311.21.20":
                        asn.MoveNext();
                        SB.Append("Client Info (OID=1.3.6.1.4.1.311.21.20): ");
                        if (multiLine) { SB.Append(Environment.NewLine + "    "); }
                        if (asn.Tag == (Int32)Asn1Type.INTEGER) {
                            Int64 id = Asn1Utils.DecodeInteger(asn.GetTagRawData());
                            SB.Append("Client ID: " + (ClientIdEnum)id + " (" + id + ")");
                            asn.MoveNext();
                        }
                        if (multiLine) { SB.Append(Environment.NewLine + "    "); } else { SB.Append(", "); }
                        if (asn.Tag == (Int32)Asn1Type.UTF8String) {
                            SB.Append("Computer name: " + Asn1Utils.DecodeUTF8String(asn.GetTagRawData()));
                            if (multiLine) { SB.Append(Environment.NewLine + "    "); } else { SB.Append(", "); }
                            asn.MoveNext();
                            SB.Append("User name: " + Asn1Utils.DecodeUTF8String(asn.GetTagRawData()));
                            if (multiLine) { SB.Append(Environment.NewLine + "    "); } else { SB.Append(", "); }
                            asn.MoveNext();
                            SB.Append("Process name: " + Asn1Utils.DecodeUTF8String(asn.GetTagRawData()));
                            if (multiLine) { SB.Append(Environment.NewLine); }
                        }
                        break;
                    // szOID_NT_PRINCIPAL_NAME
                    case "1.3.6.1.4.1.311.20.2.3":
                        if (asn.Tag == (Byte)Asn1Type.UTF8String) {
                            SB.Append("User Principal Name (OID=1.3.6.1.4.1.311.20.2.3): " + Asn1Utils.DecodeUTF8String(asn.GetTagRawData()));
                            if (multiLine) { SB.Append(Environment.NewLine); }
                        }
                        break;
                    // szOID_NTDS_REPLICATION
                    case "1.3.6.1.4.1.311.25.1":
                        if (asn.Tag == (Byte)Asn1Type.OCTET_STRING) {
                            SB.Append("NTDS Replication GUID (OID=1.3.6.1.4.1.311.25.1): " + new Guid(asn.GetPayload()));
                            if (multiLine) { SB.Append(Environment.NewLine); }
                        }
                        break;
                    #region PropIDs
                    // CERT_SHA1_HASH_PROP_ID
                    case "1.3.6.1.4.1.311.10.11.3":
                        if (asn.Tag == (Byte)Asn1Type.OCTET_STRING) {
                            SB.Append("SHA1 hash (OID=1.3.6.1.4.1.311.10.11.3): " + Asn1Utils.DecodeOctetString(asn.GetTagRawData()));
                            if (multiLine) { SB.Append(Environment.NewLine); }
                        }
                        break;
                    // CERT_MD5_HASH_PROP_ID
                    case "1.3.6.1.4.1.311.10.11.4":
                        if (asn.Tag == (Byte)Asn1Type.OCTET_STRING) {
                            SB.Append("SHA1 hash (OID=1.3.6.1.4.1.311.10.11.4): " + Asn1Utils.DecodeOctetString(asn.GetTagRawData()));
                            if (multiLine) { SB.Append(Environment.NewLine); }
                        }
                        break;
                    // CERT_ENHKEY_USAGE_PROP_ID
                    case "1.3.6.1.4.1.311.10.11.9":
                        if (asn.Tag == (Byte)Asn1Type.OCTET_STRING) {
                            asn.MoveNext();
                            asn.MoveNext();
                            SB.Append("Enhanced Key Usages (OID=1.3.6.1.4.1.311.10.11.9): ");
                            if (multiLine) { SB.Append(Environment.NewLine + "    "); }
                            do {
                                if (Asn1Utils.DecodeObjectIdentifier(asn.GetTagRawData()).FriendlyName != null) {
                                    SB.Append(Asn1Utils.DecodeObjectIdentifier(asn.GetTagRawData()).Value + " (" + Asn1Utils.DecodeObjectIdentifier(asn.GetTagRawData()).FriendlyName + ") ");
                                } else {
                                    SB.Append(Asn1Utils.DecodeObjectIdentifier(asn.GetTagRawData()).Value);
                                }
                                if (multiLine) { SB.Append(Environment.NewLine + "    "); } else { SB.Append(", "); }
                            } while (asn.MoveNext());
                        }
                        break;
                    // CERT_FRIENDLY_NAME_PROP_ID
                    case "1.3.6.1.4.1.311.10.11.11":
                        if (asn.Tag == (Byte)Asn1Type.OCTET_STRING) {
                            SB.Append("Friendly name (OID=1.3.6.1.4.1.311.10.11.11): " + Encoding.Unicode.GetString(asn.GetPayload()));
                            if (multiLine) { SB.Append(Environment.NewLine); }
                        }
                        break;
                    // CERT_KEY_IDENTIFIER_PROP_ID
                    case "1.3.6.1.4.1.311.10.11.20":
                        if (asn.Tag == (Byte)Asn1Type.OCTET_STRING) {
                            SB.Append("Subject Key Identifier (OID=1.3.6.1.4.1.311.10.11.20): " + Asn1Utils.DecodeOctetString(asn.GetTagRawData()));
                            if (multiLine) { SB.Append(Environment.NewLine); }
                        }
                        break;
                    // CERT_SUBJECT_NAME_MD5_HASH_PROP_ID
                    case "1.3.6.1.4.1.311.10.11.29":
                        if (asn.Tag == (Byte)Asn1Type.OCTET_STRING) {
                            SB.Append("Subject name MD5 hash (OID=1.3.6.1.4.1.311.10.11.29): " + Asn1Utils.DecodeOctetString(asn.GetTagRawData()));
                            if (multiLine) { SB.Append(Environment.NewLine); }
                        }
                        break;
                    #endregion
                    default:
                        SB.Append("Unknown attribute (OID=" + Oid.Value);
                        if (!String.IsNullOrEmpty(Oid.FriendlyName)) {
                            SB.Append(" (" + Oid.FriendlyName + ")");
                        }
                        SB.Append("): ");
                        if (multiLine) {
                            String tempString = AsnFormatter.BinaryToString(RawData, EncodingType.HexAsciiAddress);
                            SB.Append(tempString.Replace("\r\n", "\r\n    ") + Environment.NewLine);
                            SB.Append(Environment.NewLine);
                        } else {
                            SB.Append(AsnFormatter.BinaryToString(RawData) + Environment.NewLine);
                        }
                        break;
                }
                return SB.ToString();
            }
            return base.Format(multiLine);
        }
    }
}
