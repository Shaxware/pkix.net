using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Numerics;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SysadminsLV.Asn1Parser;
using SysadminsLV.Asn1Parser.Universal;
using SysadminsLV.PKI.Utils.CLRExtensions;

namespace SysadminsLV.PKI.Cryptography {
    public class TspRequest {
        readonly IList<X509Extension> _extensions = new List<X509Extension>();
        ICredentials creds;
        Byte[] nonce;

        /// <summary>
        ///     Initializes a new instance of <strong>TspRequest</strong> from hash algorithm and data to hash.
        /// </summary>
        /// <param name="hashAlgorithm">
        ///     A hash algorithm to hash the data.
        /// </param>
        /// <param name="data">
        ///     Data to hash.
        /// </param>
        /// <exception cref="ArgumentNullException">
        ///     <strong>hashAlgorithm</strong> or <strong>data</strong> is null.
        /// </exception>
        /// <exception cref="CryptographicException">
        ///     <strong>hashAlgorithm</strong> is invalid hashing algorithm.
        /// </exception>
        public TspRequest(Oid hashAlgorithm, Byte[] data) {
            if (hashAlgorithm == null) {
                throw new ArgumentNullException(nameof(hashAlgorithm));
            }
            if (data == null) {
                throw new ArgumentNullException(nameof(data));
            }
            initialize(hashAlgorithm, data);
        }

        /// <summary>
        ///     Initializes a new instance of <strong>TspRequest</strong> from ASN.1-encoded byte array.
        /// </summary>
        /// <param name="rawData">
        ///     ASN.1-encoded byte array that represents TSP request.
        /// </param>
        /// <exception cref="ArgumentNullException">
        ///     <strong>rawData</strong> is null.
        /// </exception>
        public TspRequest(Byte[] rawData) {
            if (rawData == null) {
                throw new ArgumentNullException(nameof(rawData));
            }
            decode(new Asn1Reader(rawData));
        }

        /// <summary>
        /// Gets the version of TSP request. Currently, Version 1 is used.
        /// </summary>
        public Int32 Version { get; private set; } = 1;
        /// <summary>
        /// Gets the message to timestamp.
        /// </summary>
        public TspMessageImprint RequestMessage { get; private set; }
        /// <summary>
        /// Gets or sets the policy ID.
        /// </summary>
        public Oid PolicyID { get; set; }
        /// <summary>
        /// Gets or sets the nonce value supplied along with request.
        /// </summary>
        /// <remarks>
        /// Nonce is used by clients to verify the timeliness of the response when no local clock is available.
        /// <para>When presented, same nonce value must be returned by TSA server.</para>
        /// </remarks>
        public Boolean UseNonce { get; set; }
        public Boolean RequestCertificates { get; set; }
        /// <summary>
        /// Gets a collection of optional extensions associated with the current TSP request.
        /// </summary>
        public X509ExtensionCollection Extensions {
            get {
                var retValue = new X509ExtensionCollection();
                foreach (X509Extension extension in _extensions) {
                    retValue.Add(extension);
                }
                return retValue;
            }
        }
        /// <summary>
        /// Gets or sets web proxy information that will be used to connect to TSA server.
        /// </summary>
        public WebProxy Proxy { get; set; }


        void initialize(Oid hashAlgorithm, Byte[] data) {
            RequestMessage = new TspMessageImprint(hashAlgorithm, data);
        }
        void decode(Asn1Reader asn) {
            asn.MoveNextAndExpectTags((Byte)Asn1Type.INTEGER);
            Version = (Int32)new Asn1Integer(asn).Value;
            asn.MoveNextAndExpectTags(48);
            RequestMessage = new TspMessageImprint(asn.GetTagRawData());
            while (asn.MoveNextCurrentLevel()) {
                switch (asn.Tag) {
                    case (Byte)Asn1Type.OBJECT_IDENTIFIER:
                        PolicyID = new Asn1ObjectIdentifier(asn).Value;
                        break;
                    case (Byte)Asn1Type.INTEGER:
                        UseNonce = true;
                        nonce = new Asn1Integer(asn).Value.ToByteArray();
                        break;
                    case (Byte)Asn1Type.BOOLEAN:
                        RequestCertificates = new Asn1Boolean(asn).Value;
                        break;
                    case 0xa0:
                        var extList = new X509ExtensionCollection();
                        extList.Decode(asn.GetTagRawData());
                        foreach (X509Extension extension in extList) {
                            _extensions.Add(extension);
                        }
                        break;
                }
            }
        }
        static void prepareWebClient(WebClient wc) {
            Version ver = Assembly.GetExecutingAssembly().GetName().Version;
            wc.Headers.Add("Content-Type", "application/timestamp-query");
            wc.Headers.Add("Accept", "application/timestamp-reply");
            wc.Headers.Add("User-Agent", $"PKIX.NET/{ver}");
            wc.Headers.Add("Cache-Control", "no-cache");
            wc.Headers.Add("Pragma", "no-cache");
        }

        /// <summary>
        ///     Adds an optional extension to TSP request.
        /// </summary>
        /// <param name="extension">
        ///     Extension to add.
        /// </param>
        /// <returns>
        ///     <strong>True</strong> if extension was added to request, otherwise <strong>False</strong>.
        /// </returns>
        /// <remarks>
        ///     This method returns <strong>False</strong> when same extension is already added to the list.
        /// </remarks>
        public Boolean AddExtension(X509Extension extension) {
            if (extension == null) {
                throw new ArgumentNullException(nameof(extension));
            }
            if (_extensions.Any(x => x.Oid.Value == extension.Oid.Value)) {
                return false;
            }
            _extensions.Add(extension);
            return true;
        }
        /// <summary>
        /// Gets or sets the network credentials that are sent to a TSA server and used to authenticate the request.
        /// </summary>
        /// <param name="credentials">Credentials to use.</param>
        /// <remarks>
        ///		TSA servers should not use authentication for incoming requests.
        /// </remarks>
        public void SetCredential(ICredentials credentials) {
            creds = credentials;
        }
        /// <summary>
        /// Gets the byte array associated with the nonce value. If nonce is not present, an empty array is returned.
        /// </summary>
        /// <returns>
        /// A 16-byte long random byte array if nonce is present or 0-byte long array if nonce is not present.
        /// </returns>
        /// <remarks>In the current implementation, random byte array is generated from random GUID instance.</remarks>
        public Byte[] GetNonceBytes() {
            return nonce == default
                ? new Byte[0]
                : nonce.ToArray();
        }
        /// <summary>
        /// Encodes current request state to a ASN.1-encoded byte array.
        /// </summary>
        /// <returns>ASN.1-encoded byte array.</returns>
        public Byte[] Encode() {
            var rawData = new List<Byte>(new Asn1Integer(Version).RawData);
            rawData.AddRange(RequestMessage.Encode());
            if (PolicyID != null) {
                rawData.AddRange(new Asn1ObjectIdentifier(PolicyID).RawData);
            }
            if (UseNonce) {
                nonce = Guid.NewGuid().ToByteArray();
                rawData.AddRange(new Asn1Integer(new BigInteger(nonce)).RawData);
            } else {
                nonce = default;
            }
            if (RequestCertificates) {
                rawData.AddRange(new Asn1Boolean(RequestCertificates).RawData);
            }
            if (_extensions.Any()) {
                rawData.AddRange(Extensions.Encode(0xa0));
            }

            return Asn1Utils.Encode(rawData.ToArray(), 48);
        }
        /// <summary>
        /// Sends request to specified TSA server and returns response.
        /// </summary>
        /// <param name="tsaServerUri">TSA server URI.</param>
        /// <returns>
        /// Time-Stamp Response.
        /// </returns>
        public TspResponse SendRequest(Uri tsaServerUri) {
            using (var wc = new WebClient { Proxy = Proxy, Credentials = creds }) {
                prepareWebClient(wc);
                return new TspResponse(wc.UploadData(tsaServerUri, "POST", Encode()));
            }
        }
    }
}
