using Microsoft.AspNetCore.Components;

namespace SqliteWasmBlazor.CryptoSync.UI.Components.Shared;

/// <summary>
/// Component-side glue for <see cref="SessionExpiredPopoverModel"/>.
/// Holds only label parameters (the host customizes the copy without
/// touching the model). All state and actions live in the model.
/// </summary>
public partial class SessionExpiredPopover
{
    [Parameter]
    public string Message { get; set; } =
        "Your session has expired for security reasons. Would you like to re-authenticate to continue working?";

    [Parameter]
    public string ReAuthenticateLabel { get; set; } = "Re-authenticate";

    [Parameter]
    public string DismissLabel { get; set; } = "Go Home";
}
