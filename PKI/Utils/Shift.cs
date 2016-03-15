using System;
namespace PKI.Utils {
	/// <summary>
	/// This class is developed as a Windows PowerShell helper class to provide an ability to perform Shift operations as
	/// identified in <see href="http://msdn.microsoft.com/en-us/library/aa691377(VS.71).aspx">Shift Operators</see>.
	/// </summary>
	[Obsolete("Obsolete", true)]
	public static class Shift {
		// author: Joel Bennett
		/// <summary>
		/// Implements a .NET '>>' operator for Int32.
		/// </summary>
		/// <param name="x">A value to shift.</param>
		/// <param name="count">A number that represents additive-expression.</param>
		/// <returns>The result of Shift operation.</returns>
		public static Int32 Right(Int32 x, Int32 count) { return x >> count; }
		/// <summary>
		/// Implements a .NET '>>' operator for UInt32.
		/// </summary>
		/// <param name="x">A value to shift.</param>
		/// <param name="count">A number that represents additive-expression.</param>
		/// <returns>The result of Shift operation.</returns>
		public static UInt32 Right(UInt32 x, Int32 count) { return x >> count; }
		/// <summary>
		/// Implements a .NET '>>' operator for Int64.
		/// </summary>
		/// <param name="x">A value to shift.</param>
		/// <param name="count">A number that represents additive-expression.</param>
		/// <returns>The result of Shift operation.</returns>
		public static Int64 Right(Int64 x, Int32 count) { return x >> count; }
		/// <summary>
		/// Implements a .NET '>>' operator for UInt64.
		/// </summary>
		/// <param name="x">A value to shift.</param>
		/// <param name="count">A number that represents additive-expression.</param>
		/// <returns>The result of Shift operation.</returns>
		public static UInt64 Right(UInt64 x, Int32 count) { return x >> count; }
		/// <summary>
		/// Implements a .NET '&lt;&lt;' operator for Int32.
		/// </summary>
		/// <param name="x">A value to shift.</param>
		/// <param name="count">A number that represents additive-expression.</param>
		/// <returns>The result of Shift operation.</returns>
		public static Int32 Left(Int32 x, Int32 count) { return x << count; }
		/// <summary>
		/// Implements a .NET '&lt;&lt;' operator for UInt32.
		/// </summary>
		/// <param name="x">A value to shift.</param>
		/// <param name="count">A number that represents additive-expression.</param>
		/// <returns>The result of Shift operation.</returns>
		public static UInt32 Left(UInt32 x, Int32 count) { return x << count; }
		/// <summary>
		/// Implements a .NET '&lt;&lt;' operator for Int64.
		/// </summary>
		/// <param name="x">A value to shift.</param>
		/// <param name="count">A number that represents additive-expression.</param>
		/// <returns>The result of Shift operation.</returns>
		public static Int64 Left(Int64 x, Int32 count) { return x << count; }
		/// <summary>
		/// Implements a .NET '&lt;&lt;' operator for UInt64.
		/// </summary>
		/// <param name="x">A value to shift.</param>
		/// <param name="count">A number that represents additive-expression.</param>
		/// <returns>The result of Shift operation.</returns>
		public static UInt64 Left(UInt64 x, Int32 count) { return x << count; }
	}
}
