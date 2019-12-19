using System;

namespace SysadminsLV.PKI.Cryptography {
    /// <summary>
    /// Represents a combination of possible Time-Stamp Response validation failures.
    /// </summary>
    [Flags]
    public enum TspValidationErrorStatus {
        None                      = 0x0,
        NoResponse                = 0x1,
        MissingSigningCertificate = 0x2,
        MissingNonce              = 0x4,
        NonceMismatch             = 0x8,
        SignatureMismatch         = 0x10,
        SignerNotValidForUsage    = 0x20,
        MessageImprintMismatch    = 0x40
    }
}
