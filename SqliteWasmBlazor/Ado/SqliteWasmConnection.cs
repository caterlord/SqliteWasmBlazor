// SqliteWasmBlazor - Minimal EF Core compatible provider
// MIT License

using System.Data;
using System.Data.Common;
using System.Diagnostics.CodeAnalysis;
using Microsoft.Extensions.Logging;

namespace SqliteWasmBlazor;

/// <summary>
/// Minimal SQLite connection for EF Core using sqlite-wasm + OPFS.
/// </summary>
public sealed class SqliteWasmConnection : DbConnection
{
    private string _connectionString = string.Empty;
    private ConnectionState _state = ConnectionState.Closed;
    private readonly SqliteWasmWorkerBridge _bridge;
    private SqliteWasmTransaction? _currentTransaction;
    private ReadOnlyMemory<byte>? _encryptionKey;

    private ReadOnlyMemory<byte>? _encryptionPassword;

    public SqliteWasmConnection()
    {
        _bridge = SqliteWasmWorkerBridge.Instance;
    }

    /// <summary>
    /// Optional user password for at-rest encryption. When set (and
    /// <see cref="EncryptionKey"/> is null), the connection opens via the
    /// password path: the worker reads-or-creates a per-DB salt block and
    /// derives the 32-byte VFS key via Argon2id. Mutually exclusive with
    /// <see cref="EncryptionKey"/>; if both are set, the explicit key wins.
    /// </summary>
    public ReadOnlyMemory<byte>? EncryptionPassword
    {
        get => _encryptionPassword;
        set
        {
            if (value is { } v && v.Length == 0)
            {
                throw new ArgumentException(
                    "EncryptionPassword must be non-empty",
                    nameof(value));
            }
            _encryptionPassword = value;
        }
    }

    /// <summary>
    /// Optional 32-byte ChaCha20-Poly1305 key for at-rest encryption. Must be
    /// set BEFORE <see cref="Open"/> / <see cref="OpenAsync(CancellationToken)"/>
    /// is called; has no effect if the worker-side DB handle is already open.
    ///
    /// When set, the DB opens through the PRF-keyed VFS path (reserved_bytes=28,
    /// journal_mode=MEMORY, AEAD per page). When null, the DB opens as plain
    /// SAHPool, identical to base-library behavior.
    ///
    /// CryptoSync derives this via HKDF from the device's PRF seed and stamps
    /// it here before each connection open. Non-CryptoSync consumers leave it
    /// null.
    /// </summary>
    public ReadOnlyMemory<byte>? EncryptionKey
    {
        get => _encryptionKey;
        set
        {
            if (value is { } v && v.Length != 32)
            {
                throw new ArgumentException(
                    $"EncryptionKey must be exactly 32 bytes, got {v.Length}",
                    nameof(value));
            }
            _encryptionKey = value;
        }
    }

    public SqliteWasmConnection(string connectionString) : this()
    {
        _connectionString = connectionString;
    }

    public SqliteWasmConnection(string connectionString, LogLevel logLevel = LogLevel.Warning) : this(connectionString)
    {
        // Set log level before any worker operations
        if (OperatingSystem.IsBrowser())
        {
            SqliteWasmLogger.SetLogLevel(logLevel);
        }
    }

    [AllowNull]
    public override string ConnectionString
    {
        get => _connectionString;
        set => _connectionString = value ?? string.Empty;
    }

    public override string Database => GetDatabaseName();

    public override string DataSource => GetDatabaseName();

    public override string ServerVersion => "3.47.0"; // sqlite-wasm version

    public override ConnectionState State =>
        _state == ConnectionState.Open && !_bridge.IsDatabaseOpen(Database)
            ? ConnectionState.Closed
            : _state;

    private string GetDatabaseName()
    {
        // Parse "Data Source=mydb.db" from connection string
        if (string.IsNullOrEmpty(_connectionString))
        {
            return ":memory:";
        }

        var parts = _connectionString.Split(';');
        foreach (var part in parts)
        {
            var kv = part.Split('=', 2);
            if (kv.Length == 2 &&
                kv[0].Trim().Equals("Data Source", StringComparison.OrdinalIgnoreCase))
            {
                return kv[1].Trim();
            }
        }

        return ":memory:";
    }

    public override void Open()
    {
        // EF Core's EnsureCreatedAsync may call synchronous Open() in some paths
        // We can't await in WebAssembly, but we can fire-and-forget the async operation
        if (_state == ConnectionState.Open && _bridge.IsDatabaseOpen(Database))
        {
            return;
        }

        _state = ConnectionState.Open;

        // Fire and forget - reuse OpenAsync logic
        _ = OpenAsync(CancellationToken.None);
    }

    public override async Task OpenAsync(CancellationToken cancellationToken)
    {
        // Check both C# state AND worker state to detect stale connections
        // after import/export/close/delete/rename operations
        if (_state == ConnectionState.Open && _bridge.IsDatabaseOpen(Database))
        {
            return;
        }

        _state = ConnectionState.Connecting;

        try
        {
            if (EncryptionKey is not null)
            {
                // Explicit 32-byte key takes precedence when both are set.
                await _bridge.OpenDatabaseAsync(Database, EncryptionKey, cancellationToken);
            }
            else if (EncryptionPassword is { } password)
            {
                await _bridge.OpenDatabaseWithPasswordAsync(Database, password, cancellationToken);
            }
            else
            {
                await _bridge.OpenDatabaseAsync(Database, encryptionKey: null, cancellationToken);
            }

            // PRAGMAs are set by the worker on first database open
            // This ensures they apply to the actual worker-side connection and persist
            // for the lifetime of the cached database instance

            _state = ConnectionState.Open;
        }
        catch
        {
            _state = ConnectionState.Broken;
            throw;
        }
    }

    public override void Close()
    {
        // IMPORTANT: Do NOT close the worker-side database connection here!
        //
        // The worker maintains a persistent connection pool. Opening/closing
        // the database for every DbContext operation is extremely inefficient:
        // - Each open: create SAH, set PRAGMAs, register functions
        // - Each close: flush WAL, release SAH
        //
        // Instead, we only update the C# connection state. The worker keeps
        // the database open and reuses it for subsequent operations.
        //
        // The database will only be truly closed when:
        // 1. Explicitly calling SqliteWasmWorkerBridge.CloseDatabaseAsync()
        // 2. The web worker terminates (e.g., page unload)

        _state = ConnectionState.Closed;
    }

    public override Task CloseAsync()
    {
        // See Close() for explanation - we don't close the worker-side connection
        _state = ConnectionState.Closed;
        return Task.CompletedTask;
    }

    protected override DbCommand CreateDbCommand()
    {
        return new SqliteWasmCommand
        {
            Connection = this
        };
    }

    protected override DbTransaction BeginDbTransaction(IsolationLevel isolationLevel)
    {
        throw new NotSupportedException(
            "Synchronous transactions are not supported in WebAssembly. Use BeginTransactionAsync instead.");
    }

    protected override async ValueTask<DbTransaction> BeginDbTransactionAsync(
        IsolationLevel isolationLevel,
        CancellationToken cancellationToken)
    {
        if (_currentTransaction is not null)
        {
            throw new InvalidOperationException("A transaction is already active on this connection.");
        }

        var transaction = await SqliteWasmTransaction.CreateAsync(this, isolationLevel, cancellationToken);
        _currentTransaction = transaction;
        return transaction;
    }

    internal void ClearCurrentTransaction(SqliteWasmTransaction transaction)
    {
        if (_currentTransaction == transaction)
        {
            _currentTransaction = null;
        }
    }

    public override void ChangeDatabase(string databaseName)
    {
        throw new NotSupportedException("Changing database is not supported.");
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            Close();
        }
        base.Dispose(disposing);
    }
}
