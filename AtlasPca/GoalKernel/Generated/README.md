# Extracted goal kernel (generated, do not edit)

This directory holds the C# translation of the Dafny-proved goal compiler (`formal/dafny/Goal.dfy` in the flagship repository)
with the Dafny C# runtime, produced with the pinned Dafny (`formal/dafny/TOOLCHAIN.lock`) by `formal/dafny/build-native.sh cs`.
The file compiles into `AtlasPca` (namespaces `GoalApi`, `GoalIr`, ..., `Dafny`; nullable annotations and warnings disabled).
CI produces it: the "Goal kernel native extractions" workflow translates the same sources, fails when the files committed here
differ from a fresh translation, and uploads the fresh translation as an artifact to commit.

`AtlasPca.GoalPkg.GoalKernel` binds it by type name at first use, so the assembly builds while this directory holds only the
README; until then every kernel call throws `GoalKernelUnavailable` (there is no fallback) and `GoalKernelTests` pass without
running the kernel (set `PCA_GOAL_KERNEL_REQUIRE=1` to make them fail). Only this README is written by hand; `build-native.sh`
keeps it and replaces every other file.
