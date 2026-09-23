using Microsoft.Extensions.Options;
using OneDriveMcp.Core.Configuration;
using OneDriveMcp.Core.Security;

namespace OneDriveMcp.Core.Tests.Security;

/// <summary>
/// The approot sandbox used to be the real boundary; addressing the whole drive means these
/// checks are the boundary. Traversal reaches the user's actual documents, and an unescaped
/// metacharacter can rewrite the Graph request itself.
/// </summary>
public class PathGuardTests
{
    private static PathGuard Guard(Action<OneDriveOptions>? configure = null)
    {
        var options = new OneDriveOptions();
        configure?.Invoke(options);
        return new PathGuard(Options.Create(options));
    }

    // ---------------------------------------------------------------- traversal

    [Theory]
    [InlineData("../secrets.txt")]
    [InlineData("../../etc/passwd")]
    [InlineData("Documents/../../Private/tax.pdf")]
    [InlineData("Documents/..")]
    [InlineData("..")]
    [InlineData("..\\..\\windows\\system32")]
    [InlineData("Documents\\..\\..\\Private")]
    public void Normalize_RejectsTraversal(string path)
    {
        Assert.Throws<PathTraversalException>(() => Guard().Normalize(path));
    }

    [Theory]
    [InlineData("%2E%2E%2Fsecrets.txt")]          // encoded ../
    [InlineData("%2e%2e/secrets.txt")]            // lowercase
    [InlineData("%252E%252E%252Fsecrets.txt")]    // double-encoded
    [InlineData("Documents%2F..%2FPrivate")]      // encoded separators around a traversal
    [InlineData("Documents%5C..%5CPrivate")]      // encoded backslashes
    public void Normalize_RejectsEncodedTraversal(string path)
    {
        Assert.Throws<PathTraversalException>(() => Guard().Normalize(path));
    }

    [Fact]
    public void Normalize_RejectsNullBytes()
    {
        Assert.Throws<PathTraversalException>(() => Guard().Normalize("report.pdf\0.txt"));
        Assert.Throws<PathTraversalException>(() => Guard().Normalize("report.pdf%00.txt"));
    }

    [Theory]
    [InlineData("a//..//b")]
    [InlineData("a/./../b")]
    [InlineData("./../b")]
    public void Normalize_RejectsTraversalHiddenBySlashRunsOrDotSegments(string path)
    {
        // Collapsing separators must not be able to reassemble a traversal that the pattern
        // check did not see in the raw form.
        Assert.Throws<PathTraversalException>(() => Guard().Normalize(path));
    }

    // ---------------------------------------------------------------- normalisation

    [Theory]
    [InlineData("Documents/report.pdf", "Documents/report.pdf")]
    [InlineData("/Documents/report.pdf", "Documents/report.pdf")]
    [InlineData("Documents/report.pdf/", "Documents/report.pdf")]
    [InlineData("Documents//report.pdf", "Documents/report.pdf")]
    [InlineData("Documents\\report.pdf", "Documents/report.pdf")]
    [InlineData("./Documents/./report.pdf", "Documents/report.pdf")]
    public void Normalize_CleansUpSeparatorsAndDotSegments(string input, string expected)
    {
        Assert.Equal(expected, Guard().Normalize(input));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("/")]
    public void Normalize_TreatsEmptyAsDriveRoot(string? input)
    {
        Assert.Equal(string.Empty, Guard().Normalize(input));
    }

    // ---------------------------------------------------------------- URL escaping

    [Theory]
    [InlineData("Q1 #1 notes.txt", "Q1%20%231%20notes.txt")]          // # would start a fragment
    [InlineData("50% done.txt", "50%25%20done.txt")]                  // % would form an escape
    [InlineData("what?.txt", "what%3F.txt")]                          // ? would start a query
    [InlineData("a+b.txt", "a%2Bb.txt")]                              // + decodes as a space
    [InlineData("notes:draft.txt", "notes%3Adraft.txt")]              // : delimits Graph addressing
    [InlineData("O'Brien report.txt", "O%27Brien%20report.txt")]
    [InlineData("a&b.txt", "a%26b.txt")]
    public void ToGraphPath_EscapesCharactersThatWouldRewriteTheRequest(string name, string expected)
    {
        // The implementation this was ported from interpolated the raw path straight into the
        // Graph URL. Inside the app folder with ASCII filenames that was survivable; against a
        // real drive each of these either breaks addressing or injects into the query string.
        Assert.Equal(expected, Guard().ToGraphPath(name));
    }

    [Fact]
    public void ToGraphPath_EscapesPerSegmentSoSeparatorsSurvive()
    {
        var result = Guard().ToGraphPath("My Folder/Sub #2/report v1.2.pdf");

        Assert.Equal("My%20Folder/Sub%20%232/report%20v1.2.pdf", result);
        Assert.Equal(2, result.Count(c => c == '/'));
    }

    [Fact]
    public void ToGraphPath_DoesNotEscapeTheSeparatorItself()
    {
        Assert.DoesNotContain("%2F", Guard().ToGraphPath("a/b/c"), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ToGraphPath_RootIsEmpty()
    {
        Assert.Equal(string.Empty, Guard().ToGraphPath(null));
    }

    [Fact]
    public void ToGraphPath_StillRejectsTraversal()
    {
        Assert.Throws<PathTraversalException>(() => Guard().ToGraphPath("../escape.txt"));
    }

    // ---------------------------------------------------------------- root confinement

    [Fact]
    public void Normalize_AppliesConfiguredRootPrefix()
    {
        var guard = Guard(o => o.RootPath = "Apps/OneDriveMcp");

        Assert.Equal("Apps/OneDriveMcp/report.pdf", guard.Normalize("report.pdf"));
        Assert.Equal("Apps/OneDriveMcp", guard.Normalize(null));
    }

    [Fact]
    public void Normalize_TraversalCannotEscapeTheConfiguredRoot()
    {
        var guard = Guard(o => o.RootPath = "Apps/OneDriveMcp");

        Assert.Throws<PathTraversalException>(() => guard.Normalize("../../Private/tax.pdf"));
    }

    // ---------------------------------------------------------------- deny-list

    [Fact]
    public void Normalize_RejectsDeniedPrefixes()
    {
        var guard = Guard(o => o.DeniedPathPrefixes = ["Apps", "Recordings"]);

        Assert.Throws<PathDeniedException>(() => guard.Normalize("Apps"));
        Assert.Throws<PathDeniedException>(() => guard.Normalize("Apps/secret/config.json"));
        Assert.Throws<PathDeniedException>(() => guard.Normalize("recordings/call.mp4"));
    }

    [Fact]
    public void Normalize_DeniedPrefixMatchesWholeSegmentsOnly()
    {
        // "Apps" must not also block "Applications".
        var guard = Guard(o => o.DeniedPathPrefixes = ["Apps"]);

        Assert.Equal("Applications/readme.md", guard.Normalize("Applications/readme.md"));
    }

    // ---------------------------------------------------------------- names

    [Theory]
    [InlineData("a/b")]
    [InlineData("a\\b")]
    [InlineData("..")]
    [InlineData("")]
    [InlineData("   ")]
    public void NormalizeName_RejectsAnythingThatIsNotASingleName(string name)
    {
        Assert.ThrowsAny<ArgumentException>(() => Guard().NormalizeName(name));
    }

    [Fact]
    public void NormalizeName_AcceptsOrdinaryNames()
    {
        Assert.Equal("Q1 Report.xlsx", Guard().NormalizeName("  Q1 Report.xlsx  "));
    }

    [Fact]
    public void Combine_JoinsParentAndChild()
    {
        var guard = Guard();

        Assert.Equal("Documents/report.pdf", guard.Combine("Documents", "report.pdf"));
        Assert.Equal("report.pdf", guard.Combine(null, "report.pdf"));
        Assert.Equal("a/b/c.txt", guard.Combine("/a/b/", "c.txt"));
    }

    [Fact]
    public void Combine_RejectsTraversalInEitherPart()
    {
        var guard = Guard();

        Assert.Throws<PathTraversalException>(() => guard.Combine("../escape", "file.txt"));
        Assert.ThrowsAny<ArgumentException>(() => guard.Combine("Documents", "../escape.txt"));
    }
}
