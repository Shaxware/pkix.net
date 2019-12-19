using System;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using SysadminsLV.Asn1Parser;
using SysadminsLV.PKI.Cryptography.Pkcs;

namespace SysadminsLV.PKI.Cryptography {
    public class TspAuthenticodeRequest : TspRequest {
        const String SPC_TIME_STAMP_REQUEST_OBJID = "1.3.6.1.4.1.311.3.2.1";
        const String PKCS_7_DATA = "1.2.840.113549.1.7.1";
        readonly Byte[] _data;

        public TspAuthenticodeRequest(PkcsSignerInfo signerInfo) : base(new Oid(SPC_TIME_STAMP_REQUEST_OBJID)) {
            if (signerInfo == null) {
                throw new ArgumentNullException(nameof(signerInfo));
            }
            _data = signerInfo.EncryptedHash;
        }

        public Byte[] Data => _data.ToArray();

        public TspAuthenticodeRequest(Byte[] rawData) : base(new Oid(SPC_TIME_STAMP_REQUEST_OBJID)) {

        }

        public override Byte[] Encode() {
            var builder = new Asn1Builder()
                .AddObjectIdentifier(new Oid(SPC_TIME_STAMP_REQUEST_OBJID))
                .AddSequence(x => {
                    return x.AddObjectIdentifier(new Oid(PKCS_7_DATA))
                        .AddExplicit(0, y => y.AddOctetString(_data));
                });
            return builder.GetEncoded();
        }
        public override TspResponse SendRequest() {
            using (var wc = new WebClient { Proxy = Proxy, Credentials = Credentials }) {
                PrepareWebClient(wc);
                String base64String = Encoding.ASCII.GetString(wc.UploadData(TsaUrl, "POST", Encode()));
                return new TspResponse(Convert.FromBase64String(base64String));
            }
        }
    }
}
