namespace OneDriveMcp.Core.Security;

/// <summary>Thrown when a path contains a traversal sequence or other escape attempt.</summary>
public sealed class PathTraversalException(string parameterName, string attemptedPath)
    : ArgumentException(
        $"Path traversal detected in '{parameterName}': the path contains a forbidden sequence.",
        parameterName)
{
    /// <summary>The path as supplied by the caller.</summary>
    public string AttemptedPath { get; } = attemptedPath;
}

/// <summary>Thrown when a path is well-formed but falls inside a configured denied prefix.</summary>
public sealed class PathDeniedException(string attemptedPath, string deniedPrefix)
    : ArgumentException($"Access to '{attemptedPath}' is denied by policy (prefix '{deniedPrefix}').")
{
    /// <summary>The path as supplied by the caller.</summary>
    public string AttemptedPath { get; } = attemptedPath;

    /// <summary>The configured prefix that rejected it.</summary>
    public string DeniedPrefix { get; } = deniedPrefix;
}
