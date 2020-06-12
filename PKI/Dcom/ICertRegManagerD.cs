using System;
using System.IO;

namespace SysadminsLV.PKI.Dcom {
    /// <summary>
    /// Represents a wrapper interface for Microsoft
    /// <see href="https://docs.microsoft.com/en-us/windows/win32/api/certadm/nn-certadm-icertadmin2">ICertAdmin2</see> COM interface.
    /// </summary>
    public interface ICertRegManagerD {
        /// <summary>
        /// Gets the Certification Authority configuration registry entry value.
        /// </summary>
        /// <param name="entryName">Configuration value name to retrieve.</param>
        /// <param name="node">Configuration node path under Configuration node. Optional.</param>
        /// <returns>Requested entry value. If configuration entry does not exist, the method returns null.</returns>
        Object GetConfigEntry(String entryName, String node);
        /// <summary>
        /// Gets the Certification Authority configuration registry entry value.
        /// </summary>
        /// <typeparam name="T">Expected registry value type. Can be String, String[], Int32 or Byte[].</typeparam>
        /// <param name="entryName">Configuration value name to retrieve.</param>
        /// <param name="node">Configuration node path under Configuration node. Optional.</param>
        /// <exception cref="FileNotFoundException">Requested entry name not found.</exception>
        /// <returns></returns>
        T GetConfigEntry<T>(String entryName, String node);
        /// <summary>
        /// Gets the Certification Authority configuration registry entry string value.
        /// </summary>
        /// <param name="entryName">Configuration value name to retrieve.</param>
        /// <param name="node">Configuration node path under Configuration node. Optional.</param>
        /// <exception cref="FileNotFoundException">Requested entry name not found.</exception>
        /// <returns>Requested entry value. If configuration entry does not exist, the method returns null.</returns>
        String GetStringConfigEntry(String entryName, String node);
        /// <summary>
        /// Gets the Certification Authority configuration registry entry multi-string value.
        /// </summary>
        /// <param name="entryName">Configuration value name to retrieve.</param>
        /// <param name="node">Configuration node path under Configuration node. Optional.</param>
        /// <exception cref="FileNotFoundException">Requested entry name not found.</exception>
        /// <returns>Requested entry value. If configuration entry does not exist, the method returns null.</returns>
        String[] GetMultiStringConfigEntry(String entryName, String node);
        /// <summary>
        /// Gets the Certification Authority configuration registry entry numerical (integer) value.
        /// </summary>
        /// <param name="entryName">Configuration value name to retrieve.</param>
        /// <param name="node">Configuration node path under Configuration node. Optional.</param>
        /// <exception cref="FileNotFoundException">Requested entry name not found.</exception>
        /// <returns>Requested entry value. If configuration entry does not exist, the method returns null.</returns>
        Int32 GetNumericConfigEntry(String entryName, String node);
        /// <summary>
        /// Gets the Certification Authority configuration registry entry boolean value.
        /// </summary>
        /// <param name="entryName">Configuration value name to retrieve.</param>
        /// <param name="node">Configuration node path under Configuration node. Optional.</param>
        /// <exception cref="FileNotFoundException">Requested entry name not found.</exception>
        /// <returns>Requested entry value. If configuration entry does not exist, the method returns null.</returns>
        Boolean GetBooleanConfigEntry(String entryName, String node);
        /// <summary>
        /// Gets the Certification Authority configuration registry entry binary value.
        /// </summary>
        /// <param name="entryName">Configuration value name to retrieve.</param>
        /// <param name="node">Configuration node path under Configuration node. Optional.</param>
        /// <exception cref="FileNotFoundException">Requested entry name not found.</exception>
        /// <returns>Requested entry value. If configuration entry does not exist, the method returns null.</returns>
        Byte[] GetBinaryConfigEntry(String entryName, String node);
        /// <summary>
        /// Writes value to Certification Authority configuration. If value does not exist it will be created. Created registry value type
        /// is inferred from <strong>data</strong> parameter.
        /// </summary>
        /// <param name="data">Configuration value name to write.</param>
        /// <param name="entryName">Configuration value name to write to.</param>
        /// <param name="node">Configuration node path under Configuration node. Optional.</param>
        /// <exception cref="ArgumentNullException">
        ///     <strong>data</strong> parameter is null.
        /// </exception>
        /// <exception cref="ArgumentException">
        ///     Data type for <strong>data</strong> parameter is not accepted. See remarks section for valid types.
        /// </exception>
        /// <remarks>
        /// Valid types for <strong>data</strong> parameter are:
        /// <list type="bullet">
        ///     <item>String</item>
        ///     <item>String[]</item>
        ///     <item>Int32</item>
        ///     <item>Boolean</item>
        ///     <item>Byte[]</item>
        /// </list>
        /// </remarks>
        void SetConfigEntry(Object data, String entryName, String node);
        /// <summary>
        /// Deletes Certification Authority configuration entry.
        /// </summary>
        /// <param name="entryName">Configuration value name to delete.</param>
        /// <param name="node">Configuration node path under Configuration node. Optional.</param>
        void DeleteConfigEntry(String entryName, String node);
    }
}