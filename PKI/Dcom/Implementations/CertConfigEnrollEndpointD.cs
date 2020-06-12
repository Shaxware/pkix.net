using System;

namespace SysadminsLV.PKI.Dcom.Implementations {
    class CertConfigEnrollEndpointD : ICertConfigEnrollEndpointD {

        internal CertConfigEnrollEndpointD(String dsUriString) {
            String[] tokens = dsUriString.Split(new[] { '\n' }, StringSplitOptions.RemoveEmptyEntries);
            if (tokens.Length < 3) {
                return;
            }
            Priority = Convert.ToInt32(tokens[0]);
            Authentication = (AdcsEnrollAuthenticationType)Convert.ToInt32(tokens[1]);
            RenewalOnly = Convert.ToBoolean(Byte.Parse(tokens[2]));
            Uri = tokens[3].TrimEnd();
        }

        public String Uri { get; }
        public AdcsEnrollAuthenticationType Authentication { get; }
        public Int32 Priority { get; }
        public Boolean RenewalOnly { get; }
        public String DsEncode() {
            return $"{Priority}\n{Authentication}\n{Convert.ToInt32(RenewalOnly)}\n{Uri}";
        }
    }
}