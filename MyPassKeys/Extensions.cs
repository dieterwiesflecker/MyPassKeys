namespace MyPassKeys;

public static class StringExtensions
{
    /// <summary>
    /// Canonical form of a username/email: trimmed and lower-cased. The Marten unique index on
    /// (TenantId, Username) is case-sensitive, so usernames are normalized to this form before
    /// storage (via <see cref="Fido2AppUser.Username"/>'s setter), lookup, and Redis key
    /// construction. Null collapses to an empty string.
    /// </summary>
    public static string NormalizeUsername(this string? username) =>
        (username ?? string.Empty).Trim().ToLowerInvariant();
}

public static class ByteArrayExtensions
{
    /// <summary>
    /// Converts a byte array to a Base64Url-encoded string, which is safe for use in URLs and Cosmos DB IDs.
    /// It replaces '+' with '-', '/' with '_', and removes padding '=' characters.
    /// </summary>
    /// <param name="bytes">The byte array to convert.</param>
    /// <returns>A Base64Url-encoded string.</returns>
    public static string ToBase64Url(this byte[] bytes)
    {
        return Convert.ToBase64String(bytes)
            .Replace('+', '-')
            .Replace('/', '_')
            .TrimEnd('=');
    }
}