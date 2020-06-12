using System;
using SysadminsLV.PKI.Dcom;

namespace SysadminsLV.PKI.Management.CertificateServices {
    /// <summary>
    /// Represents Certificate Enrollment Web Services (CES) URL object.
    /// </summary>
    public class PolicyEnrollEndpointUri {
        public PolicyEnrollEndpointUri(String uri, PolicyEnrollAuthenticationType authentication, Int32 priority, Boolean renewalOnly) {
            if (String.IsNullOrEmpty(uri)) { throw new ArgumentNullException(nameof(uri)); }
            Uri = new Uri(uri);
            Authentication = authentication;
            Priority = priority;
            RenewalOnly = renewalOnly;
        }
        internal PolicyEnrollEndpointUri(ICertConfigEnrollEndpointD dcomUri) {
            Uri = new Uri(dcomUri.Uri);
            Authentication = (PolicyEnrollAuthenticationType)dcomUri.Authentication;
            Priority = dcomUri.Priority;
            RenewalOnly = dcomUri.RenewalOnly;
        }

        /// <summary>
        /// Gets enrollment web services endpoint URL.
        /// </summary>
        public Uri Uri { get; }
        /// <summary>
        /// Gets the authentication type.
        /// </summary>
        public PolicyEnrollAuthenticationType Authentication { get; }
        /// <summary>
        /// Gets the priority of this endpoint.
        /// </summary>
        public Int32 Priority { get; }
        /// <summary>
        /// Indicates whether the endpoint is for renewal requests only (<strong>True</strong>), or accepts initial requests (<strong>False</strong>).
        /// </summary>
        public Boolean RenewalOnly { get; }

        public String Encode() {
            return $"{Priority}\n{Authentication}\n{Convert.ToInt32(RenewalOnly)}\n{Uri.AbsoluteUri}";

        }

        /// <inheritdoc />
        public override String ToString() {
            return Uri.AbsoluteUri;
        }
    }
}