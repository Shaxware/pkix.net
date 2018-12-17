namespace SysadminsLV.PKI.Cryptography {
    public sealed class DsaPrivateKey {
    }
}
/*
PrivateKeyInfo ::= SEQUENCE {
  version Version,
  algorithm AlgorithmIdentifier,
  PrivateKey OCTETSTRING
}

AlgorithmIdentifier ::= SEQUENCE {
  algorithm ALGORITHM.id,
  parameters Dss-Parms
}

Dss-Parms ::= SEQUENCE {
  p INTEGER,
  q INTEGER,
  g INTEGER
}

DSAPrivateKey ::= OCTETSTRING {
  privateExponent INTEGER
}
 */
