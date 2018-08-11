using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using CERTADMINLib;
using PKI.Structs;
using PKI.Utils;

namespace SysadminsLV.PKI.Management.CertificateServices.Database {
    class AdcsDbInternalEnumerator : IDisposable {
        readonly String _configString;
        readonly AdcsDbTableName _table;
        readonly IEnumCERTVIEWROW _dbRow;

        public AdcsDbInternalEnumerator(IEnumCERTVIEWROW dbRow, String configString, AdcsDbTableName table) {
            _configString = configString;
            _table = table;
            _dbRow = dbRow;
        }

        public String ConfigString { get; set; }
        public AdcsDbViewTableName Table { get; set; }


        static void enumColumnView(IEnumCERTVIEWROW dbRow, AdcsDbRow row) {
            var dbColumn = dbRow.EnumCertViewColumn();
            while (dbColumn.Next() != -1) {
                String colName = dbColumn.GetName();
                Object colVal = dbColumn.GetValue(CertAdmConstants.CV_OUT_BASE64);
                switch (colName) {
                    case "RequestID":
                    case "ExtensionRequestId":
                    case "AttributeRequestId":
                    case "CRLRowId":
                        row.RowId = (Int32)colVal;
                        break;
                }
                row.Properties.Add(colName, colVal);
            }
            CryptographyUtils.ReleaseCom(dbColumn);
        }
        static void postProcessRow(AdcsDbRow row) {
            if (row.Properties.ContainsKey("CertificateTemplate")) {
                row.Properties.Add("CertificateTemplateOid", new Oid((String)row.Properties["CertificateTemplate"]));
            }
            if (row.Properties.ContainsKey("ExtensionName")) {
                row.Properties.Add("ExtensionNameOid", new Oid((String)row.Properties["ExtensionName"]));
            }
        }

        public IEnumerable<AdcsDbRow> EnumRows(Int32 skipRows, Int32 takeRows) {
            Int32 rowsTaken = 0;
            _dbRow.Skip(skipRows);
            while (_dbRow.Next() != -1 && rowsTaken < takeRows) {
                rowsTaken++;
                var row = new AdcsDbRow {
                    ConfigString = _configString,
                    Table = _table
                };
                enumColumnView(_dbRow, row);
                postProcessRow(row);
                yield return row;
            }
        }

        #region IDisposable
        void releaseUnmanagedResources() {
            CryptographyUtils.ReleaseCom(_dbRow);
        }
        /// <inheritdoc />
        public void Dispose() {
            releaseUnmanagedResources();
            GC.SuppressFinalize(this);
        }
        /// <inheritdoc />
        ~AdcsDbInternalEnumerator() {
            releaseUnmanagedResources();
        }
        #endregion
    }
}