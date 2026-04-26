// SqliteWasmBlazor - Minimal EF Core compatible provider
// MIT License

namespace SqliteWasmBlazor;

/// <summary>
/// Read-only view of the current database boot state. Razor consumers inject
/// this and switch on <see cref="State"/> / pattern-match on
/// <see cref="Failure"/> to render the right UI for each failure mode.
/// Subscribe to <see cref="Changed"/> for re-render notifications when the
/// state mutates outside the normal Razor lifecycle (e.g. after the user
/// clicks Reset and recovery succeeds).
/// </summary>
public interface IDbInitializationStatus
{
    /// <summary>Current lifecycle stage. <see cref="DbInitState.READY"/> when boot succeeded.</summary>
    DbInitState State { get; }

    /// <summary>
    /// Structured failure payload. Non-null whenever <see cref="State"/> is
    /// not <see cref="DbInitState.READY"/> and not
    /// <see cref="DbInitState.NOT_STARTED"/>/<see cref="DbInitState.INITIALIZING"/>.
    /// Concrete record types live in this assembly (see <c>DbInitFailures.cs</c>)
    /// or in downstream packages that opt into the unified surface.
    /// </summary>
    IDbInitFailure? Failure { get; }

    /// <summary>Raised when <see cref="State"/> or <see cref="Failure"/> changes.</summary>
    event Action? Changed;
}
