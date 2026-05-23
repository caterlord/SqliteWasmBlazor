// SqliteWasmBlazor - Minimal EF Core compatible provider
// MIT License

using SqliteWasmBlazor.Hosting;

namespace SqliteWasmBlazor;

/// <summary>
/// Configuration for SqliteWasmBlazor worker and asset resolution.
/// Registered via <see cref="SqliteWasmServiceCollectionExtensions.AddSqliteWasm(Microsoft.Extensions.DependencyInjection.IServiceCollection, System.Action{SqliteWasmOptions}?)"/>.
/// </summary>
public sealed class SqliteWasmOptions : SqliteWasmAssetOptions
{
    public SqliteWasmOptions()
    {
        AssetRoot = "_content/SqliteWasmBlazor/";
    }

    /// <summary>
    /// Enables SQL command text and parameter logging to the browser console.
    /// Defaults to <c>false</c> because SQL text can expose application schema
    /// and parameter values can contain sensitive data.
    /// </summary>
    public bool EnableCommandSqlLogging { get; set; }
}
