using System;
using PKI.Base;

namespace PKI.ServiceProviders {
    /// <summary>
    /// Represents a collection of <see cref="CspCNG"/> objects.
    /// </summary>
    [Obsolete("Use 'CspProviderInfoCollection' class instead.")]
    public class CspCNGCollection : BasicCollection<CspCNG> {

    }
}