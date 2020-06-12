using System;
using SysadminsLV.PKI.Dcom;

namespace SysadminsLV.PKI.Management.CertificateServices {
    public class PolicyEnrollEndpointUri {
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
    }
}