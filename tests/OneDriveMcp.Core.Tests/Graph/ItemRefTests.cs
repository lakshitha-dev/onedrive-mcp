using OneDriveMcp.Core.Graph;

namespace OneDriveMcp.Core.Tests.Graph;

public class ItemRefTests
{
    [Fact]
    public void Create_AcceptsAPath()
    {
        var reference = ItemRef.Create("Documents/a.txt", itemId: null);

        Assert.Equal("Documents/a.txt", reference.Path);
        Assert.False(reference.IsById);
    }

    [Fact]
    public void Create_AcceptsAnId()
    {
        var reference = ItemRef.Create(path: null, "01ABC");

        Assert.Equal("01ABC", reference.ItemId);
        Assert.True(reference.IsById);
    }

    [Fact]
    public void Create_RejectsBothTogether()
    {
        // Accepting both would leave it ambiguous which one the server acted on.
        Assert.Throws<ArgumentException>(() => ItemRef.Create("a.txt", "01ABC"));
    }

    [Fact]
    public void Create_RejectsNeitherByDefault()
    {
        Assert.Throws<ArgumentException>(() => ItemRef.Create(path: null, itemId: null));
    }

    [Fact]
    public void Create_AllowsNeitherWhenRootIsMeaningful()
    {
        // Listing has a sensible default -- the drive root. Deleting does not.
        var reference = ItemRef.Create(path: null, itemId: null, allowRoot: true);

        Assert.Equal(ItemRef.Root, reference);
    }

    [Fact]
    public void Create_RejectsADriveIdWithoutAnItemId()
    {
        // An item on someone else's drive has no path this server can address.
        Assert.Throws<ArgumentException>(
            () => ItemRef.Create("a.txt", itemId: null, driveId: "drive-2"));
    }

    [Fact]
    public void Create_AcceptsADriveIdAlongsideAnItemId()
    {
        var reference = ItemRef.Create(path: null, "item-9", "drive-7");

        Assert.Equal("drive-7", reference.DriveId);
        Assert.Equal("item-9", reference.ItemId);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void FromId_RejectsAnEmptyId(string itemId)
    {
        Assert.Throws<ArgumentException>(() => ItemRef.FromId(itemId));
    }

    [Fact]
    public void ToString_DescribesTheReferenceForLogs()
    {
        Assert.Equal("Documents/a.txt", ItemRef.FromPath("Documents/a.txt").ToString());
        Assert.Equal("item:01ABC", ItemRef.FromId("01ABC").ToString());
        Assert.Equal("drive:d1/item:i1", ItemRef.FromId("i1", "d1").ToString());
        Assert.Equal("(drive root)", ItemRef.Root.ToString());
    }
}
