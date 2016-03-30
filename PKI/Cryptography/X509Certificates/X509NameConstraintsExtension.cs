using SysadminsLV.Asn1Parser;
using System.Collections.Generic;
using System.Linq;

namespace System.Security.Cryptography.X509Certificates {
    /// <summary>
    /// The name constraints extension, which MUST be used only in a CA certificate, indicates a name space
    /// within which all subject names in subsequent certificates in a certification path MUST be located.
    /// Restrictions apply to the subject distinguished name and apply to subject alternative names.
    /// Restrictions apply only when the specified name form is present. If no name of the type is in the
    /// certificate, the certificate is acceptable.
    /// </summary>
    public sealed class X509NameConstraintsExtension : X509Extension {
        readonly Oid _oid = new Oid("2.5.29.30");

        public X509NameConstraintsExtension(AsnEncodedData nameConstraints)
            : base(new Oid("2.5.29.30"), nameConstraints.RawData, true) {
            if (nameConstraints == null) { throw new ArgumentNullException("nameConstraints"); }
            m_decode(nameConstraints.RawData);
        }
        public X509NameConstraintsExtension(X509AlternativeNameCollection permittedSubtree, X509AlternativeNameCollection excludedSubtree) {
            if (permittedSubtree == null && excludedSubtree == null) {
                throw new ArgumentException("Both, 'permittedSubtree' and 'excludedSubtree' cannot be null.");
            }
            m_initialize(permittedSubtree, excludedSubtree);
        }

        public X509AlternativeNameCollection PermittedSubtree { get; private set; }
        public X509AlternativeNameCollection ExcludedSubtree { get; set; }

        void m_initialize(X509AlternativeNameCollection permittedSubtree, X509AlternativeNameCollection excludedSubtree) {
            Oid = _oid;
            Critical = true;

            List<Byte> rawData = new List<Byte>();
            if (permittedSubtree != null) {
                PermittedSubtree = encodeAltNames(permittedSubtree, rawData, 0xa0);
            }
            if (excludedSubtree != null) {
                ExcludedSubtree = encodeAltNames(excludedSubtree, rawData, 0xa1);
            }
            RawData = Asn1Utils.Encode(rawData.ToArray(), 48);
        }
        void m_decode(Byte[] rawData) {
            Asn1Reader asn = new Asn1Reader(rawData);
            asn.MoveNext();
            do {
                switch (asn.Tag) {
                    case 0xa0: PermittedSubtree = decodeNamesFromAsn(asn.GetTagRawData()); break;
                    case 0xa1: ExcludedSubtree = decodeNamesFromAsn(asn.GetTagRawData()); break;
                }
            } while (asn.MoveNextCurrentLevel());
        }

        static X509AlternativeNameCollection encodeAltNames(X509AlternativeNameCollection permittedSubtree, List<Byte> rawData, Byte tag) {
            X509AlternativeNameCollection altNames = new X509AlternativeNameCollection();
            List<Byte> tempRawData = new List<Byte>();
            foreach (X509AlternativeName name in permittedSubtree
                .Where(x => x.Type != X509AlternativeNamesEnum.RegisteredId)) {
                altNames.Add(name);
                tempRawData.AddRange(Asn1Utils.Encode(name.RawData, 48));
            }
            rawData.AddRange(Asn1Utils.Encode(tempRawData.ToArray(), tag));
            altNames.Close();
            return altNames;
        }
        static X509AlternativeNameCollection decodeNamesFromAsn(Byte[] rawData) {
            X509AlternativeNameCollection altNames = new X509AlternativeNameCollection();
            Asn1Reader asn = new Asn1Reader(rawData);
            asn.MoveNext();
            do {
                altNames.Add(new X509AlternativeName(asn.GetPayload()));
            } while (asn.MoveNextCurrentLevel());
            altNames.Close();
            return altNames;
        }
    }
}
