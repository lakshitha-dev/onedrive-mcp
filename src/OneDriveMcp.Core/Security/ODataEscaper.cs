namespace OneDriveMcp.Core.Security;

/// <summary>
/// Escapes values interpolated into OData expressions.
/// </summary>
/// <remarks>
/// This is attack surface the app-folder design never had. Search takes free text straight from
/// the model and drops it inside <c>search(q='...')</c>; an unescaped apostrophe -- in an ordinary
/// name like <c>O'Brien</c>, never mind a crafted one -- terminates the literal early and the rest
/// is parsed as OData.
/// </remarks>
public static class ODataEscaper
{
    /// <summary>
    /// Escapes a value for use inside a single-quoted OData string literal. Does not add the
    /// surrounding quotes.
    /// </summary>
    /// <exception cref="ArgumentException">The value contains control characters.</exception>
    public static string EscapeStringLiteral(string? value)
    {
        if (string.IsNullOrEmpty(value))
        {
            return string.Empty;
        }

        foreach (var character in value)
        {
            // Control characters have no legitimate place in a search term and can confuse both
            // the OData parser and any log that later renders the query.
            if (char.IsControl(character))
            {
                throw new ArgumentException(
                    "Value must not contain control characters.", nameof(value));
            }
        }

        // OData escapes a single quote by doubling it.
        return value.Replace("'", "''", StringComparison.Ordinal);
    }
}
