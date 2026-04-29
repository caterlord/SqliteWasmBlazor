using RxBlazorV2.Interface;
using RxBlazorV2.Model;
using RxBlazorV2.MudBlazor.Components;
using SqliteWasmBlazor.CryptoSync.UI.Services;

namespace SqliteWasmBlazor.CryptoSync.UI.Components.Shared;

/// <summary>
/// Backing model for <see cref="SessionExpiredPopover"/>. The host writes
/// <see cref="Visible"/> = <c>true</c> when its session-expiry detection
/// fires; the popover renders the overlay until one of the two commands
/// runs, both of which clear <see cref="Visible"/>.
/// </summary>
[ObservableModelScope(ModelScope.Scoped)]
[ObservableComponent]
public partial class SessionExpiredPopoverModel : ObservableModel
{
    public partial SessionExpiredPopoverModel(ISessionAuthenticator authenticator);

    public partial bool Visible { get; set; }

    [ObservableCommand(nameof(ReAuthenticateAsync))]
    public partial IObservableCommandAsync ReAuthenticate { get; }

    [ObservableCommand(nameof(DismissAsync))]
    public partial IObservableCommandAsync Dismiss { get; }

    private async Task ReAuthenticateAsync(CancellationToken cancellationToken)
    {
        await Authenticator.ReAuthenticateAsync(cancellationToken);
        Visible = false;
    }

    private async Task DismissAsync(CancellationToken cancellationToken)
    {
        await Authenticator.DismissAsync(cancellationToken);
        Visible = false;
    }
}
