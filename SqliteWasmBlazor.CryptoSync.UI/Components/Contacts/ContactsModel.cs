using RxBlazorV2.Interface;
using RxBlazorV2.Model;
using RxBlazorV2.MudBlazor.Components;
using SqliteWasmBlazor.CryptoSync.UI.Models;

namespace SqliteWasmBlazor.CryptoSync.UI.Components.Contacts;

/// <summary>
/// Backing model for <see cref="ContactsPanel"/>. Owns the loaded
/// <see cref="TrustedContact"/> list, the per-row soft-delete command,
/// and a pubkey copy command.
///
/// <para>
/// <b>Scope.</b> Stage-2 absorption is intentionally read + local-soft-delete
/// only. End-to-end admin revocation (rotate every shared group, push
/// <c>Revoke</c> on the whitelist) requires <c>DualKeyPairFull</c> admin
/// keys and the deployment salt, neither of which a panel may hold. Real
/// admin tooling (post-Stage-2 admin-keyless seeding step) wraps that flow
/// and exposes a parameterized callback into this model if desired.
/// </para>
/// </summary>
[ObservableModelScope(ModelScope.Scoped)]
[ObservableComponent]
public partial class ContactsModel : ObservableModel
{
    public partial ContactsModel(ContactService contactService);

    public partial IReadOnlyList<TrustedContact>? Contacts { get; set; }
    public partial string? ErrorMessage { get; set; }

    /// <summary>
    /// Pending copy-to-clipboard signal. Set by <see cref="RequestCopyKey"/>;
    /// the component's component-trigger override does the JS interop +
    /// snackbar, then clears the signal so the next click re-fires.
    /// Tuple shape: <c>(PublicKey, Username)</c>.
    /// </summary>
    [ObservableComponentTriggerAsync]
    public partial CopyKeyRequest? PendingCopy { get; set; }

    [ObservableCommand(nameof(LoadContactsAsync))]
    public partial IObservableCommandAsync LoadContacts { get; }

    [ObservableCommand(nameof(DeleteContactAsync))]
    public partial IObservableCommandAsync<Guid> DeleteContact { get; }

    [ObservableCommand(nameof(RequestCopyKey))]
    public partial IObservableCommand<TrustedContact> RequestCopyKeyCommand { get; }

    private void RequestCopyKey(TrustedContact contact) =>
        PendingCopy = new CopyKeyRequest(contact.X25519PublicKey, contact.Username);

    private async Task LoadContactsAsync()
    {
        ErrorMessage = null;
        try
        {
            var list = await ContactService.GetAllAsync();
            Contacts = list
                .Where(c => !c.IsDeleted)
                .OrderByDescending(c => c.IsAdmin)
                .ThenBy(c => c.Username)
                .ToList();
        }
        catch (Exception ex)
        {
            ErrorMessage = $"Failed to load contacts: {ex.Message}";
            Contacts = Array.Empty<TrustedContact>();
        }
    }

    private async Task DeleteContactAsync(Guid contactId)
    {
        ErrorMessage = null;
        try
        {
            await ContactService.DeleteAsync(contactId);
            await LoadContactsAsync();
        }
        catch (Exception ex)
        {
            ErrorMessage = $"Failed to delete contact: {ex.Message}";
        }
    }
}
