using Xunit;

// Stryker.NET captures per-test mutant coverage with process-global counters: parallel test execution attributes coverage to
// the wrong tests (mutants covered only by snapshot tests were reported as survivors). Run the tests serially.
[assembly: CollectionBehavior(DisableTestParallelization = true)]
