// Generated from the reference built-in action catalog. Do not edit: regenerate it from the reference catalog (a test compares every
// entry with it). Reversibility and blast radius are the effective values.
namespace AtlasPca;

public sealed partial class Catalog
{
    /// <summary>The built-in actions: the default catalog of <see cref="Facade.CompilePolicy"/> and <see cref="Agent.FromPrincipal"/> (the catalog test compares it with the reference).</summary>
    public static IReadOnlyList<CatalogAction> Builtin { get; } = new CatalogAction[]
    {
        new("stripe", "charge", "stripe.charge", "irreversible", 0.9, "amount", "Charge a customer. Refundable in practice, but a charge is treated as final.",
            new[] { "bill", "charge_customer" }, new[] { "pca.irreversible", "pca.money_moving" }),
        new("stripe", "refund", "stripe.refund", "irreversible", 0.9, "amount", "Returns money for a charge to the customer.",
            new[] { "issue_refund", "refund", "refund_charge", "reimburse" }, new[] { "pca.irreversible", "pca.money_moving" }),
        new("stripe", "payout", "stripe.payout", "irreversible", 0.9, "amount", "Moves funds from a Stripe balance to a bank account.",
            new[] { "pay_out", "payout" }, new[] { "pca.irreversible", "pca.money_moving" }),
        new("stripe", "create_customer", "stripe.create_customer", "rate_limited", 0.2, null, "Creates a customer record.",
            Array.Empty<string>(), new[] { "pca.pii_access" }),
        new("gmail", "send", "gmail.send", "irreversible", 0.8, null, "Sends an email to people outside your organisation.",
            new[] { "send_email" }, new[] { "pca.external_communication", "pca.irreversible", "pca.pii_access" }),
        new("gmail", "draft", "gmail.draft", "reversible", 0.2, null, "Saves an email draft without sending it.",
            Array.Empty<string>(), new[] { "pca.pii_access" }),
        new("gmail", "delete", "gmail.delete", "irreversible", 0.8, null, "Permanently deletes a message.",
            Array.Empty<string>(), new[] { "pca.destructive", "pca.irreversible" }),
        new("github", "read", "github.read", "reversible", 0.05, null, "Reads files from a repository.",
            Array.Empty<string>(), Array.Empty<string>()),
        new("github", "create_pr", "github.create_pr", "irreversible", 0.2, null, "Opens a pull request, which is visible to everyone with access to the repository.",
            Array.Empty<string>(), new[] { "pca.external_communication", "pca.irreversible" }),
        new("github", "comment", "github.comment", "irreversible", 0.2, null, "Posts a comment, visible to everyone with access to the repository.",
            Array.Empty<string>(), new[] { "pca.external_communication", "pca.irreversible" }),
        new("github", "merge_pr", "github.merge_pr", "irreversible", 0.5, null, "Merges a pull request, which can trigger deploys and other downstream effects.",
            Array.Empty<string>(), new[] { "pca.irreversible" }),
        new("github", "delete_repo", "github.delete_repo", "irreversible", 0.8, null, "Deletes a repository and everything in it.",
            Array.Empty<string>(), new[] { "pca.destructive", "pca.irreversible" }),
        new("slack", "post_message", "slack.post_message", "irreversible", 0.5, null, "Posts a message that members of the channel can read.",
            Array.Empty<string>(), new[] { "pca.bulk", "pca.external_communication", "pca.irreversible" }),
        new("slack", "read", "slack.read", "reversible", 0.05, null, "Reads the message history of a channel.",
            Array.Empty<string>(), Array.Empty<string>()),
        new("calendar", "create_event", "calendar.create_event", "irreversible", 0.2, null, "Creates an event and sends invitations to its attendees.",
            Array.Empty<string>(), new[] { "pca.external_communication", "pca.irreversible", "pca.pii_access" }),
        new("calendar", "delete_event", "calendar.delete_event", "rate_limited", 0.5, null, "Deletes a calendar event.",
            Array.Empty<string>(), new[] { "pca.destructive" }),
        new("files", "read", "files.read", "reversible", 0.05, null, "Reads files.",
            Array.Empty<string>(), new[] { "pca.bulk" }),
        new("files", "write", "files.write", "rate_limited", 0.5, null, "Writes or overwrites files.",
            Array.Empty<string>(), new[] { "pca.bulk" }),
        new("files", "delete", "files.delete", "irreversible", 0.8, null, "Deletes files.",
            Array.Empty<string>(), new[] { "pca.bulk", "pca.destructive", "pca.irreversible" }),
        new("http", "get", "http.get", "reversible", 0.05, null, "Fetches a URL.",
            Array.Empty<string>(), new[] { "pca.bulk", "pca.network_egress" }),
        new("http", "post", "http.post", "rate_limited", 0.5, null, "Posts a body to a URL.",
            Array.Empty<string>(), new[] { "pca.bulk", "pca.network_egress" }),
    };
}
