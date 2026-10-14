using System.Data.Common;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata;

namespace ServerCloak.Core;

/// <summary>
/// Creates the database and adds tables, columns and indexes that newer versions introduce, so existing data is kept
/// without EF migrations. Only additive changes are supported.
/// </summary>
public static class SchemaUpgrade
{
    public static void Apply(DbContext db)
    {
        db.Database.EnsureCreated();
        db.Database.OpenConnection();
        try
        {
            var conn = db.Database.GetDbConnection();
            Exec(conn, "PRAGMA journal_mode=WAL;");

            var tables = Query(conn, "SELECT name FROM sqlite_master WHERE type='table'").ToHashSet(StringComparer.OrdinalIgnoreCase);
            var indexes = Query(conn, "SELECT name FROM sqlite_master WHERE type='index'").ToHashSet(StringComparer.OrdinalIgnoreCase);
            var script = db.Database.GenerateCreateScript()
                .Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .Where(x => x.Length > 0)
                .ToList();

            foreach (var entity in db.Model.GetEntityTypes())
            {
                var table = entity.GetTableName();
                if (table == null)
                    continue;

                if (!tables.Contains(table))
                {
                    foreach (var sql in script.Where(x => x.StartsWith($"CREATE TABLE \"{table}\"", StringComparison.Ordinal)))
                        Exec(conn, sql);
                    continue;
                }

                var columns = Query(conn, $"SELECT name FROM pragma_table_info('{table}')").ToHashSet(StringComparer.OrdinalIgnoreCase);
                var store = StoreObjectIdentifier.Table(table);
                foreach (var p in entity.GetProperties())
                {
                    var column = p.GetColumnName(store);
                    if (column == null || columns.Contains(column))
                        continue;
                    var type = p.GetColumnType();
                    var sql = $"ALTER TABLE \"{table}\" ADD COLUMN \"{column}\" {type}";
                    if (!p.IsColumnNullable(store))
                        sql += " NOT NULL DEFAULT " + (type.Contains("TEXT", StringComparison.OrdinalIgnoreCase) ? "''" :
                                                       type.Contains("BLOB", StringComparison.OrdinalIgnoreCase) ? "X''" : "0");
                    Exec(conn, sql);
                }
            }

            foreach (var sql in script.Where(x => x.StartsWith("CREATE ", StringComparison.Ordinal) && x.Contains(" INDEX ", StringComparison.Ordinal)))
            {
                var name = sql.Split('"')[1];
                if (!indexes.Contains(name))
                    Exec(conn, sql);
            }
        }
        finally
        {
            db.Database.CloseConnection();
        }
    }

    private static void Exec(DbConnection conn, string sql)
    {
        using var cmd = conn.CreateCommand();
        cmd.CommandText = sql;
        cmd.ExecuteNonQuery();
    }

    private static List<string> Query(DbConnection conn, string sql)
    {
        using var cmd = conn.CreateCommand();
        cmd.CommandText = sql;
        using var r = cmd.ExecuteReader();
        var list = new List<string>();
        while (r.Read())
            list.Add(r.GetString(0));
        return list;
    }
}
