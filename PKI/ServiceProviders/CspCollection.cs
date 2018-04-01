using System;
using PKI.Base;

namespace PKI.ServiceProviders {
    /// <summary>
    /// Represents a collection of <see cref="CspLegacy"/> objects.
    /// </summary>
    [Obsolete("Use 'CspProviderInfoCollection' class instead.")]
    public class CspCollection : BasicCollection<CspLegacy> {

    }
}