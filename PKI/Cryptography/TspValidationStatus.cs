using System;

namespace SysadminsLV.PKI.Cryptography {
    [Flags]
    public enum TspValidationErrorStatus {
        None = 0,
        NoResponse = 1,
        SignatureMismatch = 2,
        SignerNotValidForUsage,
        MissingNonce,
        NonceMismatch,
        MessageImprintMismatch,
    }
}
