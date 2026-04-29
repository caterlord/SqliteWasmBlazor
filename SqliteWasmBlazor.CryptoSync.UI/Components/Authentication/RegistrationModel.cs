using RxBlazorV2.Interface;
using RxBlazorV2.Model;
using RxBlazorV2.MudBlazor.Components;
using SqliteWasmBlazor.CryptoSync.UI.Services;

namespace SqliteWasmBlazor.CryptoSync.UI.Components.Authentication;

/// <summary>
/// First-time WebAuthn credential creation. The host wires
/// <see cref="IPrfAuthenticator.RegisterAsync"/>; the model surfaces the
/// returned <see cref="CredentialId"/> + <see cref="PublicKey"/> as
/// observable properties so RxBlazor hosts can react via internal
/// observers or <see cref="ObservableModelObserverAttribute"/>.
/// </summary>
[ObservableModelScope(ModelScope.Scoped)]
[ObservableComponent]
public partial class RegistrationModel : ObservableModel
{
    public partial RegistrationModel(IPrfAuthenticator authenticator);

    public partial bool? IsPrfSupported { get; set; }
    public partial string? DisplayName { get; set; }
    public partial string? CredentialId { get; set; }
    public partial string? PublicKey { get; set; }
    public partial string? ErrorMessage { get; set; }
    public partial string? SuccessMessage { get; set; }

    [ObservableCommand(nameof(CheckPrfSupportAsync))]
    public partial IObservableCommandAsync CheckPrfSupport { get; }

    [ObservableCommand(nameof(RegisterAsync), nameof(CanRegister))]
    public partial IObservableCommandAsync Register { get; }

    private bool CanRegister() => IsPrfSupported == true;

    private async Task CheckPrfSupportAsync()
    {
        try
        {
            IsPrfSupported = await Authenticator.CheckPrfSupportAsync();
        }
        catch (Exception ex)
        {
            IsPrfSupported = false;
            ErrorMessage = $"PRF support check failed: {ex.Message}";
        }
    }

    private async Task RegisterAsync(CancellationToken cancellationToken)
    {
        ErrorMessage = null;
        SuccessMessage = null;
        try
        {
            var hint = string.IsNullOrWhiteSpace(DisplayName) ? null : DisplayName;
            var result = await Authenticator.RegisterAsync(hint, cancellationToken);
            CredentialId = result.CredentialId;
            PublicKey = result.PublicKeyBase64;
            DisplayName = null;
            SuccessMessage = "Passkey registered.";
        }
        catch (Exception ex)
        {
            ErrorMessage = $"Registration failed: {ex.Message}";
        }
    }
}
