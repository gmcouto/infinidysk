namespace UsenetSharp.Encryption;

/// <summary>
/// Classification of an encryption failure (plan §4.6, Body Standard §5).
/// </summary>
public enum YencEncryptionFailureKind
{
    /// <summary>Local-fatal (METADATA_VALIDATION): no password, bad local config/KDF. Never fail over.</summary>
    LocalFatal,

    /// <summary>Provider-failover (PROVIDER_FAILOVER): bytes in a fetched article failed validation/authentication.</summary>
    ProviderFailover,
}

/// <summary>
/// Local-fatal encryption failure: missing password or a local KDF/crypto failure.
/// Abort the job/read; never retry against another provider. No plaintext is released.
/// </summary>
public class YencEncryptionLocalException : Exception
{
    public YencEncryptionLocalException(string errorMessage)
        : base(errorMessage)
    {
    }

    public YencEncryptionLocalException(string errorMessage, Exception innerException)
        : base(errorMessage, innerException)
    {
    }

    public static YencEncryptionFailureKind Kind => YencEncryptionFailureKind.LocalFatal;
}

/// <summary>
/// Provider-failover encryption failure: a fetched article is corrupt or unauthenticated.
/// Eligible for retry against another provider/fallback. No plaintext is released.
/// </summary>
public class YencEncryptionFailoverException : Exception
{
    public YencEncryptionFailoverException(string errorMessage)
        : base(errorMessage)
    {
    }

    public YencEncryptionFailoverException(string errorMessage, Exception innerException)
        : base(errorMessage, innerException)
    {
    }

    public static YencEncryptionFailureKind Kind => YencEncryptionFailureKind.ProviderFailover;
}
