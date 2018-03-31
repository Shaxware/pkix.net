using System;

namespace PKI.Structs {
    static class AlgorithmOids {
        // public key group
        public const String RSA             = "1.2.840.113549.1.1.1";
        public const String DSA             = "1.2.840.10040.4.1";
        public const String ECC             = "1.2.840.10045.2.1";
        // md5 group
        public const String MD5             = "1.2.840.113549.2.5";
        public const String MD5_RSA         = "1.2.840.113549.1.1.4";
        // sha1 group
        public const String SHA1            = "1.3.14.3.2.26";
        public const String SHA1_RSA        = "1.2.840.113549.1.1.5";
        public const String SHA1_DSA        = "1.2.840.10040.4.3";
        public const String SHA1_ECDSA      = "1.2.840.10045.4.1";
        // sha256 group
        public const String SHA256          = "2.16.840.1.101.3.4.2.1";
        public const String SHA256_RSA      = "1.2.840.113549.1.1.11";
        public const String SHA256_ECDSA    = "1.2.840.10045.4.3.2";
        // sha384 group
        public const String SHA384          = "2.16.840.1.101.3.4.2.2";
        public const String SHA384_RSA      = "1.2.840.113549.1.1.12";
        public const String SHA384_ECDSA    = "1.2.840.10045.4.3.3";
        // sha 512 group
        public const String SHA512          = "2.16.840.1.101.3.4.2.3";
        public const String SHA512_RSA      = "1.2.840.113549.1.1.13";
        public const String SHA512_ECDSA    = "1.2.840.10045.4.3.4";
        // specified group
        public const String RSA_PSS         = "1.2.840.113549.1.1.10";
        public const String ECDSA_SPECIFIED = "1.2.840.10045.4.3";
    }
}
