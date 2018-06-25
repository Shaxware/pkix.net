using System;
using System.Collections.Generic;
using System.Linq;
using CERTADMINLib;
using PKI.CertificateServices;
using PKI.Structs;
using PKI.Utils;

namespace SysadminsLV.PKI.Management.CertificateServices.Database {
    class AdcsDbReader : IDisposable {
        #region predefined columns per view table
        readonly String[] _revokedColumns   = {
                                                  "RequestID",
                                                  "Request.RevokedWhen",
                                                  "Request.RevokedReason",
                                                  "CommonName",
                                                  "SerialNumber",
                                                  "CertificateTemplate"
                                              };
        readonly String[] _issuedColumns    = {
                                                  "RequestID",
                                                  "Request.RequesterName",
                                                  "CommonName",
                                                  "NotBefore",
                                                  "NotAfter",
                                                  "SerialNumber",
                                                  "CertificateTemplate"
                                              };
        readonly String[] _pendingColumns   = {
                                                  "RequestID",
                                                  "Request.RequesterName",
                                                  "Request.SubmittedWhen",
                                                  "Request.CommonName",
                                                  "CertificateTemplate"
                                              };
        readonly String[] _failedColumns    = {
                                                  "RequestID",
                                                  "Request.StatusCode",
                                                  "Request.DispositionMessage",
                                                  "Request.SubmittedWhen",
                                                  "Request.CommonName",
                                                  "CertificateTemplate"
                                              };
        readonly String[] _requestColumns   = {
                                                  "RequestID",
                                                  "Request.StatusCode",
                                                  "Request.DispositionMessage",
                                                  "Request.RequesterName",
                                                  "Request.SubmittedWhen",
                                                  "Request.CommonName",
                                                  "CertificateTemplate"
                                              };
        readonly String[] _extensionColumns = {
                                                  "ExtensionRequestId",
                                                  "ExtensionName",
                                                  "ExtensionFlags",
                                                  "ExtensionRawValue"
                                              };
        readonly String[] _attributeColumns = {
                                                  "AttributeRequestId",
                                                  "AttributeName",
                                                  "AttributeValue"
                                              };
        readonly String[] _crlColumns       = {
                                                  "CRLRowId",
                                                  "CRLNumber",
                                                  "CRLThisUpdate",
                                                  "CRLNextUpdate",
                                                  "CRLPublishStatusCode",
                                                  "CRLPublishError"
                                              };
        #endregion
        readonly ICertView2 CaView = new CCertViewClass();
        readonly IList<Int32> _columnIDs = new List<Int32>();
        readonly IList<String> _columns = new List<String>();
        readonly ISet<AdcsDbQueryFilterEntry> _filters = new HashSet<AdcsDbQueryFilterEntry>();
        AdcsDbTableName table;
        Boolean isOpenView, outAllColumns;

        /// <summary>
        /// 
        /// </summary>
        /// <param name="certificateAuthority"></param>
        public AdcsDbReader(CertificateAuthority certificateAuthority)
            : this(certificateAuthority, AdcsDbViewTableName.Issued) { }
        /// <summary>
        /// 
        /// </summary>
        /// <param name="certificateAuthority"></param>
        /// <param name="viewTable"></param>
        public AdcsDbReader(CertificateAuthority certificateAuthority, AdcsDbViewTableName viewTable) {
            if (certificateAuthority == null) { throw new ArgumentNullException(nameof(certificateAuthority)); }

            ConfigString = certificateAuthority.ConfigString;
            CaView.OpenConnection(ConfigString);
            ViewTable = viewTable;
            mapTables();
        }

        /// <summary>
        /// Gets the CA's config string associated with the current database reader instance.
        /// </summary>
        public String ConfigString { get; }
        /// <summary>
        /// Gets an array of database columns added to include in the view.
        /// </summary>
        public String[] Columns => _columns.ToArray();
        /// <summary>
        /// Gets an array of currently applied query filters.
        /// </summary>
        public AdcsDbQueryFilterEntry[] QueryFilters => _filters.ToArray();
        /// <summary>
        /// Gets the view table to query. Default is '<strong>Request</strong>' view table.
        /// </summary>
        /// <remarks>
        /// Depending on view table, predefined column list is added to a result view.
        /// <list type="table">
        ///     <listheader>
        ///         <term>View Table</term>
        ///         <description>Default columns</description>
        ///     </listheader>
        ///     <item>
        ///          <term>Revoked</term>
        ///          <description>
        ///             <list type="bullet">
        ///                 <item>RequestID</item>
        ///                 <item>Request.RevokedWhen</item>
        ///                 <item>Request.RevokedReason</item>
        ///                 <item>CommonName</item>
        ///                 <item>SerialNumber</item>
        ///                 <item>CertificateTemplater</item>
        ///             </list>
        ///         </description>
        ///     </item>
        ///     <item>
        ///          <term>Issued</term>
        ///          <description>
        ///             <list type="bullet">
        ///                 <item>RequestID</item>
        ///                 <item>Request.RequesterName</item>
        ///                 <item>CommonName</item>
        ///                 <item>NotBefore</item>
        ///                 <item>NotAfter</item>
        ///                 <item>SerialNumber</item>
        ///                 <item>CertificateTemplate</item>
        ///             </list>
        ///         </description>
        ///     </item>
        ///     <item>
        ///          <term>Pending</term>
        ///          <description>
        ///             <list type="bullet">
        ///                 <item>RequestID</item>
        ///                 <item>Request.RequesterName</item>
        ///                 <item>Request.SubmittedWhen</item>
        ///                 <item>CommonName</item>
        ///                 <item>CertificateTemplate</item>
        ///             </list>
        ///         </description>
        ///     </item>
        ///     <item>
        ///          <term>Failed</term>
        ///          <description>
        ///             <list type="bullet">
        ///                 <item>RequestID</item>
        ///                 <item>Request.StatusCode</item>
        ///                 <item>Request.DispositionMessage</item>
        ///                 <item>Request.SubmittedWhen</item>
        ///                 <item>Request.CommonName</item>
        ///                 <item>CertificateTemplate</item>
        ///             </list>
        ///         </description>
        ///     </item>
        ///     <item>
        ///          <term>Request</term>
        ///          <description>
        ///             <list type="bullet">
        ///                 <item>RequestID</item>
        ///                 <item>Request.StatusCode</item>
        ///                 <item>Request.DispositionMessage</item>
        ///                 <item>Request.RequesterName</item>
        ///                 <item>Request.SubmittedWhen</item>
        ///                 <item>Request.CommonName</item>
        ///                 <item>CertificateTemplate</item>
        ///             </list>
        ///         </description>
        ///     </item>
        ///     <item>
        ///          <term>Extension</term>
        ///          <description>
        ///             <list type="bullet">
        ///                 <item>ExtensionRequestId</item>
        ///                 <item>ExtensionName</item>
        ///                 <item>ExtensionFlags</item>
        ///                 <item>ExtensionRawValue</item>
        ///             </list>
        ///         </description>
        ///     </item>
        ///     <item>
        ///          <term>Attribute</term>
        ///          <description>
        ///             <list type="bullet">
        ///                 <item>AttributeRequestId</item>
        ///                 <item>AttributeName</item>
        ///                 <item>AttributeValue</item>
        ///             </list>
        ///         </description>
        ///     </item>
        ///     <item>
        ///          <term>CRL</term>
        ///          <description>
        ///             <list type="bullet">
        ///                 <item>CRLRowId</item>
        ///                 <item>CRLNumber</item>
        ///                 <item>CRLThisUpdate</item>
        ///                 <item>CRLNextUpdate</item>
        ///                 <item>CRLPublishStatusCode</item>
        ///                 <item>CRLPublishError</item>
        ///             </list>
        ///         </description>
        ///     </item>
        /// </list>
        /// </remarks>
        public AdcsDbViewTableName ViewTable { get; }

        void mapTables() {
            var RColumn = CaView.GetColumnIndex(0, "Disposition");
            // map view table to DB table
            String[] columns;
            switch (ViewTable) {
                case AdcsDbViewTableName.Revoked:
                    columns = _revokedColumns;
                    table = AdcsDbTableName.Request;
                    CaView.SetRestriction(RColumn, 1, 0, 21);
                    break;
                case AdcsDbViewTableName.Issued:
                    columns = _issuedColumns;
                    table = AdcsDbTableName.Request;
                    CaView.SetRestriction(RColumn, 1, 0, 20);
                    break;
                case AdcsDbViewTableName.Pending:
                    columns = _pendingColumns;
                    table = AdcsDbTableName.Request;
                    CaView.SetRestriction(RColumn, 1, 0, 9);
                    break;
                case AdcsDbViewTableName.Failed:
                    columns = _failedColumns;
                    table = AdcsDbTableName.Request;
                    CaView.SetRestriction(-3, 0, 0, 0);
                    break;
                case AdcsDbViewTableName.Request:
                    columns = _requestColumns;
                    table = AdcsDbTableName.Request;
                    CaView.SetTable((Int32)AdcsDbTableName.Request);
                    break;
                case AdcsDbViewTableName.Extension:
                    columns = _extensionColumns;
                    table = AdcsDbTableName.Extension;
                    CaView.SetTable((Int32)AdcsDbTableName.Extension);
                    break;
                case AdcsDbViewTableName.Attribute:
                    columns = _attributeColumns;
                    table = AdcsDbTableName.Attribute;
                    CaView.SetTable((Int32)AdcsDbTableName.Attribute);
                    break;
                case AdcsDbViewTableName.CRL:
                    columns = _crlColumns;
                    table = AdcsDbTableName.CRL;
                    CaView.SetTable((Int32)AdcsDbTableName.CRL);
                    break;
                default:
                    throw new ArgumentOutOfRangeException();
            }
            // set columns for preconfigured view tables
            foreach (String column in columns) {
                AddColumnToView(column);
            }
        }
        void setResultColumns() {
            Int32 columnCount;
            if (outAllColumns) {
                columnCount = CaView.GetColumnCount(CertAdmConstants.CVRC_COLUMN_SCHEMA);
                CaView.SetResultColumnCount(columnCount);
                _columns.Clear();
                _columns.Add("*");
                foreach (var columnIndex in Enumerable.Range(0, columnCount)) {
                    CaView.SetResultColumn(columnIndex);
                }
            } else {
                columnCount = _columnIDs.Count;
                CaView.SetResultColumnCount(columnCount);
                foreach (var columnID in _columnIDs) {
                    CaView.SetResultColumn(columnID);
                }
            }
        }
        void setFilters() {
            foreach (AdcsDbQueryFilterEntry filter in _filters) {
                CaView.SetRestriction(
                    filter.ColumnID,
                    (Int32)filter.LogicalOperator,
                    CertAdmConstants.CVR_SORT_NONE,
                    filter.QualifierValue);
            }
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="columnName"></param>
        /// <returns></returns>
        public Boolean AddColumnToView(String columnName) {
            if (isOpenView) {
                throw new AccessViolationException();
            }

            // if '*' is specified then all columns are added implicitly, so return false.
            if (outAllColumns) { return false; }
            if (columnName == "*") {
                outAllColumns = true;
                return true;
            }
            Int32 index = CaView.GetColumnIndex(0, columnName);
            if (_columnIDs.Contains(index)) { return false; }
            _columnIDs.Add(index);
            _columns.Add(columnName);
            return true;
        }
        /// <summary>
        /// Adds filter to requested view.
        /// </summary>
        /// <param name="filter">Filter entry to add.</param>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="AccessViolationException"></exception>
        /// <returns>
        /// <strong>True</strong> if 
        /// </returns>
        public Boolean AddQueryFilter(AdcsDbQueryFilterEntry filter) {
            if (filter == null) { throw new ArgumentNullException(nameof(filter)); }
            if (isOpenView) {
                throw new AccessViolationException();
            }
            if (_filters.Contains(filter)) { return false; }

            Int32 index = CaView.GetColumnIndex(0, filter.ColumnName);
            filter.ColumnID = index;
            return _filters.Add(filter);
        }
        public IEnumerable<AdcsDbRow> GetView(Int32 skipRows, Int32 takeRows) {
            isOpenView = true;
            setResultColumns();
            setFilters();
            using (var reader = new AdcsDbInternalEnumerator(CaView.OpenView(), ConfigString, table)) {
                foreach (AdcsDbRow row in reader.EnumRows(skipRows, takeRows)) {
                    yield return row;
                }
            }
        }

        #region IDisposable
        void ReleaseUnmanagedResources() {
            CryptographyUtils.ReleaseCom(CaView);
        }
        /// <inheritdoc />
        public void Dispose() {
            ReleaseUnmanagedResources();
            GC.SuppressFinalize(this);
        }
        /// <inheritdoc />
        ~AdcsDbReader() {
            ReleaseUnmanagedResources();
        }
        #endregion
    }
}
