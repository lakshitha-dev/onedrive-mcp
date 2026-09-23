using Xunit;

// These are integration tests, and each collection starts the real host through
// WebApplicationFactory, which drives the entry point via HostFactoryResolver and its
// process-wide diagnostic listener. Two collections starting a host at the same moment race on
// it, and one fails with "the entry point exited without ever building an IHost" -- on whichever
// test happened to get there first, so the failure appears to move around. Running collections
// one at a time removes the race; hosts are still shared within a collection, so the cost is
// small.
[assembly: CollectionBehavior(DisableTestParallelization = true)]
