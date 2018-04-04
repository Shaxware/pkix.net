using System;
using SysadminsLV.Asn1Parser;
using SysadminsLV.PKI.Cryptography.Pkcs;

namespace SysadminsLV.PKI.Cryptography.X509CertificateRequests {
    /// <summary>
    /// Represents a CMC (Certificate Management Message over CMS) object that contains PKCS #10 certificate
    /// request and associated CMC data.
    /// </summary>
    /// <remarks>Currently, this class do not support extra attributes.</remarks>
    public sealed class X509CertificateRequestCmc : SignedPkcs7<X509CertificateRequestPkcs10> {
        /*
        CmcData ::= SEQUENCE 
        {
           controlSequence         ControlSequence,
           reqSequence             ReqSequence,
           cmsSequence             CmsSequence,
           otherMsgSequence        OtherMsgSequence
        }


        ControlSequence  ::=    SEQUENCE OF TaggedAttribute
        ReqSequence      ::=    SEQUENCE OF TaggedRequest
        CmsSequence      ::=    SEQUENCE OF TaggedContentInfo
        OtherMsgSequence ::=    SEQUENCE OF TaggedOtherMsg

        TaggedAttribute ::= SEQUENCE 
        {
           bodyPartID              BodyPartID,
           type                    EncodedObjectID,
           values                  AttributeSetValue
        }

        TaggedRequest ::= CHOICE 
        {
           tcr                     [0] IMPLICIT TaggedCertificationRequest
        }

        TaggedContentInfo ::= SEQUENCE 
        {
           bodyPartID              BodyPartID,
           contentInfo             ANY
        }

        BodyPartID ::= INTEGER (0..4294967295)
        EncodedObjectID ::= OBJECT IDENTIFIER
        AttributeSetValue ::= SET OF ANY
         */

        public X509CertificateRequestCmc(Byte[] rawData) : base(rawData) { }

        protected override void DecodeContent(Byte[] rawData) {
            var asn = new Asn1Reader(rawData);
            asn.MoveNext();             // ControlSequence  ::=    SEQUENCE OF TaggedAttribute
            asn.MoveNextCurrentLevel(); // ReqSequence      ::=    SEQUENCE OF TaggedRequest
            asn.MoveNext();
            // theoretically, it is a sequence, but we pick only first request. Never seen an array of requests
            Content = new X509CertificateRequestPkcs10(asn.GetTagRawData());
        }
    }
}