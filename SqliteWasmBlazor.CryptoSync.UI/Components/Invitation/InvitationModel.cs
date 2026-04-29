using RxBlazorV2.Interface;
using RxBlazorV2.Model;
using RxBlazorV2.MudBlazor.Components;
using SqliteWasmBlazor.CryptoSync.UI.Services;

namespace SqliteWasmBlazor.CryptoSync.UI.Components.Invitation;

/// <summary>
/// Composite invitation flow model — owns the create / accept / responses
/// surface. Talks to <see cref="ContactInvitationService"/> via the
/// host-supplied <see cref="IAdminInvitationContext"/> /
/// <see cref="IContactInvitationContext"/> seams that resolve the device's
/// WebAuthn-derived keys + salt + transport.
///
/// <para>
/// <b>Stage 2 status.</b> The panel ships in its three-file shape with
/// commands stubbed against the seams. Without a real
/// <see cref="IPrfAuthenticator"/>-backed seam impl (host-supplied,
/// post-Stage-2 demo step) the commands will surface a configuration
/// error rather than executing the underlying invitation flow. This is
/// deliberate — the Stage A wire contracts the service writes against
/// are stable; only the WebAuthn-key plumbing is missing.
/// </para>
/// </summary>
[ObservableModelScope(ModelScope.Scoped)]
[ObservableComponent]
public partial class InvitationModel : ObservableModel
{
    public partial InvitationModel(ContactInvitationService invitationService);

    public partial string? FormUsername { get; set; }
    public partial string? FormEmail { get; set; }
    public partial string? FormComment { get; set; }
    public partial string? CreatedBundleSummary { get; set; }
    public partial int IngestedCount { get; set; }
    public partial string? ErrorMessage { get; set; }

    [ObservableCommand(nameof(CreateInvitationAsync))]
    public partial IObservableCommandAsync<IAdminInvitationContext> CreateInvitation { get; }

    [ObservableCommand(nameof(IngestResponsesAsync))]
    public partial IObservableCommandAsync<IAdminInvitationContext> IngestResponses { get; }

    private async Task CreateInvitationAsync(IAdminInvitationContext adminContext)
    {
        ErrorMessage = null;
        CreatedBundleSummary = null;
        try
        {
            var adminKeys = await adminContext.GetAdminKeysAsync();
            var salt = await adminContext.GetDeploymentSaltBase64Async();

            if (string.IsNullOrWhiteSpace(FormUsername))
            {
                ErrorMessage = "Username is required.";
                return;
            }

            var bundle = await InvitationService.CreateInvitationAsync(
                adminKeys,
                salt,
                FormUsername,
                string.IsNullOrWhiteSpace(FormEmail) ? null : FormEmail,
                FormComment);

            CreatedBundleSummary =
                $"Invitation created for {FormUsername}. Group {bundle.GroupId:N}, "
                + $"expires {bundle.ExpiresAt:yyyy-MM-dd HH:mm} UTC.";
        }
        catch (Exception ex)
        {
            ErrorMessage = $"Failed to create invitation: {ex.Message}";
        }
    }

    private async Task IngestResponsesAsync(IAdminInvitationContext adminContext)
    {
        ErrorMessage = null;
        try
        {
            var adminKeys = await adminContext.GetAdminKeysAsync();
            var transport = await adminContext.GetSyncTransportAsync();
            IngestedCount = await InvitationService.IngestInvitationResponsesAsync(adminKeys, transport);
        }
        catch (Exception ex)
        {
            ErrorMessage = $"Failed to ingest responses: {ex.Message}";
        }
    }
}
