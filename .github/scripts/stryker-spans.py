#!/usr/bin/env python3
"""Shard K of N of the Stryker.NET run over AtlasPca/: prints one --mutate glob per line, fences the shard's files (CI copy
only) with Stryker comment directives so only the wanted members are mutated, and writes the shard's scope.

   python3 stryker-spans.py <k> <n> <AtlasPca dir> --scope <scope.json> [--baseline <baseline.json> --carry <carried.json>]
   python3 stryker-spans.py 0 <n> <AtlasPca dir> --scope <scope.json> --only <file>[#i/n]   (one file whole or span i of n of it: a Windows shard)
   python3 stryker-spans.py 0 0 <AtlasPca dir> --gen-plan      (prints PLAN entries for every .cs file the plan does not list yet)

A shard whose file set changed still works against an old targeted baseline: the baseline is read per file (sources / scope
keyed by file), so a file that moved into a shard has no baseline entry there and is mutated whole, a file that moved out is
simply not in scope, and the files that stayed keep their carried results.

PLAN lists every .cs file of AtlasPca/ exactly once: whole, or as spans "File.cs#i/n" (n near-equal line spans cut only at
member declarations, indent 0 or 4 in the file-scoped namespace, so no mutant crosses a cut and the spans partition the
file). A span that is too slow for one shard is cut again as "File.cs#i/n@j/m" (slice j of m inside span i of n, same cut rule). A .cs file missing from PLAN (or a planned file that is gone, or spans that do not partition a file) fails the
shard, so a new source file is never silently left out.

FENCING: a `// Stryker disable all` comment only disables the syntax node it is attached to (the declaration right below
it): it does NOT run on to a later `// Stryker restore all` across sibling members (0.4.2 run 38330673581: every Pca.cs
shard tested the whole file, 3x the work, and every Pca.cs survivor was reported three times). So a top-level type with no
live line gets its own directive line, and inside a type with live lines every member declaration (indent 4, its attribute
lines included) without one gets one. Live = the shard's span (full mode), or the lines that changed since the
baseline (targeted mode). A `--mutate Pca.cs{a..b}` line filter is not used: with it Stryker.NET 4.8 reported every in-span
mutant as a compile error. The inserted directive lines are whole lines `// Stryker disable all`; the report step drops
them again (line numbers of the original file).

--scope: {"AtlasPca/<file>.cs" | "AtlasPca.AspNetCore/<file>.cs": [first, last]} (original-file lines the shard owns). The report step counts and lists only
in-scope mutants: Stryker compiles (and reports CompileError for) the mutants of EVERY file of the project in every shard
(run 38330673581: ~1,489 CompileErrors in each of the 12 shards, 17,834 in all, whatever the shard mutated), so every
other file of the shard's project is fenced whole at its namespace line (below) and none of its mutants is compiled.

TARGETED mode (--baseline = the stryker-baseline.json the same shard uploaded in an earlier run: its sources, scope and
every in-scope mutant with its status): the lines of the current sources that are not an unchanged copy of an in-scope
baseline line are live (edited, added, next to a deletion, or newly in scope). Only the members holding a live line are
mutated by Stryker (none: no glob is printed and Stryker is skipped). Every baseline mutant that lies, unchanged, in a
fenced member is written to --carry with its line numbers moved to the current source; the report step keeps its
Killed / Timeout / tested CompileError result and re-tests the others (Survived, NoCoverage, untested CompileError) one by
one with stryker-isolate.py, so new kill tests are seen without re-running Stryker over the whole shard."""
import collections, difflib, json, os, posixpath, re, sys

# One shard per entry: "File.cs" (the whole file) or "File.cs#i/n" (line span i of n, cut at member declarations); paths are
# relative to AtlasPca/ (the middleware's start with ../AtlasPca.AspNetCore/, its own Stryker project: never mixed in a shard).
# Balanced on run 41748042249's per-shard Stryker minutes plus its survivor / CompileError counts (each is tested alone
# afterwards), Attest/ Ext/ and the middleware by size; the suite has since become ~6x faster (Ed25519 check).
PLAN = [
    ["Pca.cs#1/6@2/4"],
    ["Passport.cs"],
    ["ActionSchema.cs", "Ext/Optimistic.cs", "Ext/OptimisticOpen.cs"],
    ["Authorize.cs#1/5", "MissingContext.cs"],
    ["Authorize.cs#2/5@1/8", "Authorize.cs#2/5@2/8", "Authorize.cs#2/5@3/8", "Authorize.cs#2/5@4/8", "FreshAt.cs"],
    ["Ext/Mesh.cs#1/9", "Ext/PcaInternals.cs"],
    ["UndoCoordinator.cs#1/2@4/4"],
    ["Workflow.cs", "IntentRevocation.cs"],
    ["Attest/AttestNvidiaCollateral.cs#1/4@1/2"],
    ["Sigstore.cs#1/2@1/4", "Sigstore.cs#1/2@2/4", "Attest/AttestMaa.cs#2/2"],
    ["Sigstore.cs#2/2@1/2"],
    ["Attest/AttestAmd.cs#1/3"],
    ["Actions.cs#1/6@4/4"],
    ["Actions.cs#3/6@3/12", "Actions.cs#3/6@4/12"],
    ["Attest/AttestCert.cs#1/2@1/3"],
    ["StoreConformanceApproval.cs#1/2"],
    ["K3.cs#1/2@2/2"],
    ["PolicyAuthoring.cs#1/11"],
    ["CaveatLang.cs#1/2"],
    ["Attest/AttestIntelCollateral.cs#1/6"],
    ["IntentV2.cs#1/2@2/4"],
    ["../AtlasPca.AspNetCore/PcaMiddleware.cs", "../AtlasPca.AspNetCore/PcaOptions.cs", "../AtlasPca.AspNetCore/PcaProtect.cs", "../AtlasPca.AspNetCore/PcaExtensions.cs"],
    ["IntentSession.cs", "Decision.cs", "Assurance.cs", "PcaDomainSig.cs"],
    ["Lease.cs", "Attest/AttestGcp.cs"],
    ["Operations.cs"],
    ["ProvenanceGate.cs#1/10", "Ext/Ledger.cs#9/9"],
    ["K4.cs"],
    ["IntentJs.cs#1/7"],
    ["AtomicKv.cs", "Attest/AttestFactory.cs", "IntentWB.cs", "LessNative.cs", "Rx.cs", "DurableState.cs"],
    # run 41937170925: these shards passed their budget (12 in Stryker, 8/13/14/20 with mutants left untested); new ones go last, so the other numbers stay
    ["PlanLifecycle.cs#2/2"],
    ["Actions.cs#5/6@1/4"],
    ["Attest/AttestDer.cs#1/5"],
    ["Attest/AttestJws.cs#1/16"],
    ["Approval.cs#1/2"],
    ["Attest/AttestXml.cs#1/4"],
    ["Attest/AttestCertExts.cs"],
    # run 42149070759: Pca, Actions and AttestXml ran out of budget, AttestCert came near it
    ["Pca.cs#4/6@1/2"],
    ["Actions.cs#2/6"],
    ["Actions.cs#4/6"],
    ["Actions.cs#6/6@2/2"],
    ["Attest/AttestCert.cs#2/2@2/6"],
    ["Attest/AttestXml.cs#3/4@1/2"],
    ["RuntimeClaim.cs"],
    # run 42441751689: shard 17 (K3 + AttestIntel + PolicyClasses, 138 mutants untested) and shard 6 (3 untested) overran the budget: one file each, the old slots keep their numbers
    ["Attest/AttestIntel.cs#1/5"],
    ["PolicyClasses.cs"],
    ["Attest/AttestNvidia.cs#1/3"],
    # run 42636647633: shard 20 lost its runner a third time (shutdown signal after 90 min at 2 workers): one file each, the old slot keeps AttestIntelCollateral
    ["SafeRegex.cs#1/6@1/4"],
    ["Executor.cs"],
    # run 42720114305: SafeRegex alone lost its runner again (shutdown at 38 min): three spans, one worker each, so the span that does it is named
    ["SafeRegex.cs#3/6"],
    ["SafeRegex.cs#5/6@1/2"],
    # the 0.5 hardening files (new code, no baseline: they run in full)
    ["Risk.cs#1/2@3/4"],
    ["Prohibitions.cs"],
    ["ProhibitionPlane.cs#1/4"],
    ["Contracts.cs#1/2"],
    ["StoreConformanceKv.cs#1/6"],
    # Authorize.cs grew to ~2000 lines with the 0.5 options: its spans are their own shards
    ["Authorize.cs#3/5@3/4"],
    # run 43153719902: shards 51, 52 and 56 ran out of budget (53, 53 and 600 mutants untested): Taint + Beacons and
    # SafetyEvidence get their own shards, Authorize.cs is cut in five spans (the old slots keep their numbers)
    ["Beacons.cs"],
    ["SafetyEvidence.cs#1/2"],
    ["Authorize.cs#4/5"],
    ["Authorize.cs#5/5@1/4"],
    # 0.5 agent side: the facade (with the built-in catalog), the extra signers and the producer-vector driver
    ["Catalog.cs"],
    ["SignersMore.cs"],
    ["ProducerVectors.cs#2/2"],
    # run 43567210955: the whole facade ran out of budget at 66 of 297 mutants (~270 s each): seven spans, one shard each
    ["Facade.cs#2/7"],
    ["Facade.cs#3/7"],
    ["Facade.cs#4/7"],
    ["Facade.cs#5/7"],
    ["Facade.cs#6/7"],
    ["Facade.cs#7/7"],
    # run 44038700810: shards 1 (Pca.cs, 188 untested), 26 (962) and 47 (SafeRegex, 61) ran out of budget, 42, 18 and 28 used 85-95% of it.
    # Sized from that run at ~60% of the 305-minute budget: Pca.cs in six spans (~2 mutants/min, static mutants run apart), SafeRegex.cs
    # in six (one worker, ~0.7 mutants/min), AttestXml.cs in four (each isolated test ~4 min), the 26 / 18 / 28 groups in two or three
    ["Pca.cs#2/6@1/7"],
    ["Pca.cs#3/6@1/6"],
    ["Pca.cs#5/6"],
    ["Pca.cs#6/6"],
    ["IntentAcc.cs"],
    ["OracleFacts.cs#1/2", "IntentClassifier.cs"],
    ["ArgProvenance.cs#1/3"],
    ["IntentPrimitives.cs", "IntentArtifacts.cs"],
    ["Attest/AttestXml.cs#2/4@1/2"],
    ["Attest/AttestXml.cs#4/4"],
    ["SafeRegex.cs#2/6"],
    ["SafeRegex.cs#4/6"],
    ["SafeRegex.cs#6/6@1/6"],
    # the opt-in module projects (own Stryker project and oracle each, native libraries built on the runner): the shard number
    # of each is its position here, and the workflow's module-shard matrix names the same numbers
    ["../AtlasPca.Pairing/Abe/AbePolicy.cs"],
    ["../AtlasPca.Pairing/Bbs/Bbs.cs#1/3", "../AtlasPca.Pairing/Bbs/BbsCredential.cs#2/2"],
    ["../AtlasPca.Pairing/Aggsig/AggsigChain.cs"],
    ["../AtlasPca.Fhe/FheSeal.cs#1/2", "../AtlasPca.Fhe/NativeResolver.cs"],
    ["../AtlasPca.MpcLweOt/Lattice.cs"],
    ["../AtlasPca.Fndsa/NativeFnDsa.cs"],
    # every other shipped source file: generated by `stryker-spans.py 0 0 <AtlasPca dir> --gen-plan` (about 800 lines a shard, files over
    # 1200 lines in spans); they run in full (no baseline yet). Regenerate for new files, never hand-edit.
    ["../AtlasPca.AspNetCore/PcaFetchHandler.cs", "../AtlasPca.AspNetCore/PcaFilters.cs"],
    ["A2aPkg/A2aJws.cs", "A2aPkg/A2aCard.cs#2/2"],
    ["A2aPkg/A2aPca.cs#1/4"],
    ["Acp/Acp.cs#1/2"],
    ["Acp/X402V2.cs"],
    ["ActionsKit/ActionBuild.cs"],
    ["ActionsKit/ActionBusinessRules.cs#1/3"],
    ["ActionsKit/ActionDerive.cs#1/2", "ActionsKit/ActionData.g.cs"],
    ["ActionsKit/ActionDiff.cs"],
    ["ActionsKit/ActionLint.cs#1/2", "ActionsKit/ActionSelectors.cs"],
    ["ActionsKit/ActionsText.cs"],
    ["ActionsKit/ImportCommon.cs#1/3", "ActionsKit/Effective.cs"],
    ["ActionsKit/ImportCore.cs#1/2"],
    ["ActionsKit/ImportEval.cs#1/2"],
    ["ActionsKit/ImportGraphql.cs#1/2"],
    ["ActionsKit/ImportGrpc.cs#1/3"],
    ["ActionsKit/ImportJx.cs"],
    ["ActionsKit/ImportRulesData.g.cs", "ActionsKit/ImportReview.cs#2/2"],
    ["ActionsKit/ImportSuggest.cs#1/3"],
    ["ActionsKit/YamlEmit.cs#1/2"],
    ["Adapters/PcaAdapters.cs"],
    ["Analyzer/AnalyzerCore.cs"],
    ["Analyzer/Coverage.cs#1/2", "Analyzer/DagAnalysis.cs"],
    ["Analyzer/Enumerate.cs#1/2"],
    ["Analyzer/Exposure.cs#1/3", "Analyzer/Field.cs"],
    ["Analyzer/Flip.cs#1/2", "Analyzer/Filter.cs#2/2"],
    ["Analyzer/Residual.cs#1/2", "Analyzer/Narrowing.cs#2/2"],
    ["Analyzer/TestRunner.cs", "Analyzer/Validate.cs#2/2"],
    ["Ap2/Chain.cs#1/2"],
    ["Ap2/Constraints.cs#1/2", "Ap2/Mandates.cs#2/2"],
    ["Ap2/PcaBindingVerify.cs"],
    ["Approvals.cs"],
    ["AttestEat/PcaAttestEat.cs#1/2", "AttestEat/EatToken.cs#2/2"],
    ["Authzen/AuthzenPdp.cs"],
    ["Ciba/Ciba.cs#1/2"],
    ["Ciba/CibaApproval.cs#1/2"],
    ["Ciba/CibaClient.cs#1/2", "Ciba/CibaJs.cs"],
    ["Compliance/PcaComplianceReport.cs"],
    ["Connect/ConnectJs.cs"],
    ["Connect/ConnectStore.cs"],
    ["Connectors/PcaConnectors.cs"],
    ["Connectors/PcaConnectorsExchange.cs"],
    ["ControlEvals/PcaControlEvals.cs#1/2", "Dataflow/DataFlow.cs#2/2"],
    ["Doctor/DoctorJs.cs"],
    ["Doctor/PcaDoctor.cs#1/4"],
    ["Erc7715/Erc7715.cs", "Dpop/Dpop.cs#3/3"],
    ["Evidence/EvidenceReplay.cs#1/2", "Evidence/EvidenceVerify.cs"],
    ["Explain/Explainer.cs#1/4"],
    ["Ext/BondStore.cs#1/2", "Ext/BudgetLedger.cs#2/2"],
    ["Ext/LedgerStore.cs"],
    ["FheParts/FheRisk.cs"],
    ["Fndsa/Fndsa.cs"],
    ["Gateway/PcaGatewayAdapters.cs"],
    ["Gateway/PcaGatewayCore.cs#1/2", "Gateway/PcaGatewayWorker.cs"],
    ["Gnap/Gnap.cs#1/3"],
    ["Gnap/Interaction.cs#1/2"],
    ["Goal/G.cs"],
    ["Goal/GoalCodec.cs#1/3", "Goal/GoalCard.cs"],
    ["Goal/GoalDrift.cs", "Goal/GoalDigests.cs"],
    ["Goal/GoalExamples.cs#1/2", "Goal/GoalFmt.cs"],
    ["Goal/GoalInterpret.cs#1/3", "Goal/GoalLegacy.cs"],
    ["Goal/GoalNVersion.cs#1/2", "Goal/GoalOntologies.cs"],
    ["Goal/GoalOntology.cs#1/3"],
    ["Goal/GoalRefsem.cs"],
    ["Goal/GoalReview.cs#1/3", "Goal/GoalRoundTrip.cs"],
    ["Goal/GoalSelectors.cs#1/3", "Goal/GoalSign.cs"],
    ["GoalKernel/GoalKernel.cs"],
    ["Grants/GrantService.cs#1/2", "Grants/GrantSigning.cs"],
    ["Grants/Shadow.cs", "Grants/Sig.cs"],
    ["IdJag/IdJag.cs#1/2", "Harness/PcaHarness.cs#2/2"],
    ["Intent/IntentClassifierKit.cs"],
    ["Intent/IntentDerive.cs"],
    ["Intent/IntentJit.cs"],
    ["Intent/IntentLearner.cs#1/2@1/12", "Intent/IntentLearner.cs#1/2@2/12", "Intent/IntentLearner.cs#1/2@3/12", "Intent/IntentLearner.cs#1/2@4/12"],
    ["Intent/IntentLearner.cs#2/2@1/12", "Intent/IntentLearner.cs#2/2@2/12", "Intent/IntentLearner.cs#2/2@3/12", "Intent/IntentLearner.cs#2/2@4/12"],
    ["Intent/IntentMapKit.cs#1/3"],
    ["Intent/IntentMultiAgg.cs#1/2", "Intent/IntentMath.cs#2/2"],
    ["Intent/IntentOmega.cs#1/3", "Intent/IntentPolicyKit.cs"],
    ["Intent/IntentProfile.cs#1/2", "Intent/IntentRamp.cs#2/2"],
    ["Intent/IntentRefine.cs#1/2", "Intent/IntentRegion.cs"],
    ["Intent/IntentRender.cs#1/2"],
    ["Intent/IntentRuntime.cs#1/2"],
    ["Intent/IntentTrajectory.cs"],
    ["Invariants/InvariantProperties.cs#1/2"],
    ["Jose/Jose.cs#1/3", "Jose/JoseCanonicalExtras.cs"],
    ["Jose/JoseKeys.cs#1/2", "Jose/WhatwgUrl.cs#2/2"],
    ["Js/JsJson.cs"],
    ["Mcp/McpDraft.cs#1/2", "Native/Sodium.cs"],
    ["Notary/PcaNotary.cs#1/2", "Oauth/Oauth.cs#2/2"],
    ["Oidc/Oidc.cs#1/2"],
    ["Otel/OtelGuard.cs"],
    ["Payments/Payments.cs#1/2"],
    ["PolicyBridgeKit/Cedar.cs#1/2"],
    ["PolicyBridgeKit/Cel.cs#1/3"],
    ["PolicyBridgeKit/Rego.cs"],
    ["PolicyCi/CiCli.cs#1/2", "PolicyCi/ActionLintRules.cs"],
    ["PolicyCi/PcaPolicyCi.cs"],
    ["PqThreshold/PqThreshold.cs"],
    ["Ratchet/RiskAccumulator.cs#1/2", "Ratchet/Ggm.cs"],
    ["Research/Immune.cs#1/2", "Ratchet/Ristretto255.cs"],
    ["Rotate/Rotate.cs"],
    ["Sandbox/PcaSandbox.cs#1/3"],
    ["Sandbox/SandboxEgressProxy.cs#1/2"],
    ["Schema/PcaSchema.cs#1/2"],
    ["Scim/Scim.cs#1/3"],
    ["Scitt/Durable.cs"],
    ["Scitt/Scitt.cs#1/2", "Scitt/Rfc9162.cs"],
    ["Sdjwt/Sdjwt.cs#1/3"],
    ["Siem/SiemExport.cs#1/3"],
    ["Signals/Signals.cs#1/2"],
    ["Signals/SsfManage.cs#1/2", "Signals/SsfStream.cs#2/2"],
    ["Spiffe/SpiffeBridge.cs#1/4"],
    ["StoreConformanceBond.cs#1/3", "Spiffe/SpiffeDer.cs"],
    ["StoreConformanceBudget.cs#1/3"],
    ["StoreConformanceLedger.cs#1/2", "StoreConformanceMeshWitness.cs#2/2"],
    ["StoreConformancePkg/StoreCheck.cs"],
    ["StoreConformanceSuite.cs"],
    ["Testing/PcaTesting.cs#1/2", "TxnTokens/TxnTokens.cs#2/2"],
    ["Vc/Vc.cs#1/3", "Vdf/Timelock.cs"],
    ["Vdf/Vdf.cs#1/2"],
    ["Wallet/TrustedChannel.cs#1/3"],
    ["Wallet/WalletCard.cs#1/3"],
    ["Wallet/WalletCore.cs#1/3"],
    ["Wallet/WalletPopulation.cs"],
    ["WebBotAuth/SignedDirectory.cs", "WebBotAuth/WbaJs.cs"],
    ["WebBotAuth/WebBotAuth.cs#1/3"],
    ["Webauthn/Webauthn.cs#1/2"],
    ["AgentNative.cs#1/3"],
    ["SiblingPortsSmall.cs#1/2", "Ap2/Ap2KeyGen.cs"],
    ["Ext/BondSettlementPlanner.cs"],
    ["Ext/LedgerIssue.cs"],
    ["Ext/Kem.cs#1/2"],
    ["Ext/Entropy.cs#1/3"],
    # the opt-in Groth16 module (own Stryker project, oracle AtlasPca.Zk.Tests over libpcazk): a module shard, named by number in the workflow's module-shard matrix
    ["../AtlasPca.Zk/ZkNative.cs", "../AtlasPca.Zk/NativeResolver.cs"],
    ["Ext/ZkCeremony.cs"],
    # the deterministic math and the small files added since the plan was cut (stryker-spans.py 0 0 <dir> --gen-plan), one shard in place of the removed Ext/FdLibmPow.cs
    ["Attest/AttestVendors.cs#1/2", "PcaReferenceNames.cs"],
    ["StoreConformancePkg/StoreCli.cs"],
    ["Ext/ZkCompliance.cs#1/2"],
    ["Ext/ZkPolicyVm.cs#1/2"],
    ["CatalogSpecs.cs"],
    ["Ext/MeshIssuing.cs#1/2"],
    ["Ext/PqQuorum.cs#1/2"],
    ["Ext/SafetyCertificate.cs"],
    ["Ext/Reputation.cs"],
    ["Ext/BudgetForecast.cs"],
    ["Research/PolicySim.cs", "Research/AgentConsole.cs#2/2"],
    ["Ext/AttestationSoft.cs#1/3"],
    ["Ext/PolicyDebug.cs"],
    ["Ext/SevSnp.cs"],
    ["Ext/AttestPuf.cs#1/2"],
    ["Ext/GuardianHa.cs#1/2"],
    ["Ext/TaintTree.cs"],
    ["Ext/AttestAllowlist.cs#1/2"],
    ["Ext/FrontierSignals.cs"],
    ["Ext/AttestMaaKeys.cs#1/3", "Ext/AttestMaaPinsData.cs"],
    ["Ext/AttestPqSoftware.cs"],
    ["Ext/SemanticThreshold.cs"],
    ["Ext/ObjectiveRisk.cs#1/4"],
    ["Ext/PassportOps.cs"],
    ["Ext/BeaconOps.cs"],
    ["Ext/ActionSchemaOps.cs", "Mcp/McpDraftOpenApi.cs"],
    ["Ext/ActionPinOps.cs"],
    ["Ext/Progress.cs#1/4"],
    ["Ext/NlApproval.cs"],
    ["Ext/WhatwgUrl.cs"],
    ["Ext/IntentMisc2.cs#1/2"],
    ["Ext/FrostNet.cs#1/3"],
    ["Ext/FrostDkgChannel.cs#1/2"],
    ["Attest/AttestNvidiaApi.cs#1/2"],
    ["VerifyPcactn.cs#1/2@2/2"],
    ["Ext/FrostNetHttp.cs#2/2@1/2"],
    ["Ext/FrostDkgTls.cs#1/2@3/4"],
    # 0.6 mutation split (every shard <= ~40 min wall): the slots above that were predicted over that keep their number with the first part,
    # the other parts are numbered from here (File.cs#i/n@j/m = slice j of m of span i of n); core and module shards (workflow matrices) by project
    ["Authorize.cs#2/5@8/8"],
    ["Ext/Mesh.cs#2/9"],
    ["Ext/Mesh.cs#3/9"],
    ["Ext/Mesh.cs#4/9@2/2"],
    ["Ext/Mesh.cs#5/9"],
    ["Ext/Mesh.cs#6/9"],
    ["Ext/Mesh.cs#7/9"],
    ["Ext/Mesh.cs#8/9"],
    ["Ext/Mesh.cs#9/9"],
    ["UndoCoordinator.cs#2/2@1/4"],
    ["ActionsRegistry.cs#1/2@2/2"],
    ["UndoStore.cs"],
    ["Attest/AttestNvidiaCollateral.cs#2/4@1/2"],
    ["Attest/AttestNvidiaCollateral.cs#3/4"],
    ["Attest/AttestNvidiaCollateral.cs#4/4@1/2"],
    ["Sigstore.cs#1/2@4/4"],
    ["Attest/AttestMaa.cs#1/2@1/2"],
    ["Sigstore.cs#2/2@2/2"],
    ["Keys.cs#1/2"],
    ["Attest/AttestAmd.cs#2/3"],
    ["Attest/AttestAmd.cs#3/3"],
    ["Predicates.cs#1/4"],
    ["Predicates.cs#2/4@2/2"],
    ["Predicates.cs#3/4"],
    ["Predicates.cs#4/4@2/2"],
    ["Actions.cs#3/6@5/12", "Actions.cs#3/6@6/12", "Actions.cs#3/6@7/12", "Actions.cs#3/6@8/12"],
    ["Actions.cs#3/6@9/12"],
    ["Attest/AttestCert.cs#1/2@2/3"],
    ["Attest/AttestCert.cs#1/2@3/3"],
    ["Issue.cs#1/2"],
    ["Issue.cs#2/2"],
    ["StoreConformance.cs#1/2"],
    ["StoreConformance.cs#2/2"],
    ["PolicyAuthoring.cs#2/11"],
    ["PolicyAuthoring.cs#3/11"],
    ["PolicyAuthoring.cs#4/11"],
    ["PolicyAuthoring.cs#5/11"],
    ["PolicyAuthoring.cs#6/11"],
    ["PolicyAuthoring.cs#7/11"],
    ["PolicyAuthoring.cs#8/11"],
    ["PolicyAuthoring.cs#9/11"],
    ["PolicyAuthoring.cs#10/11"],
    ["PolicyAuthoring.cs#11/11"],
    ["Attest/AttestIntelCollateral.cs#2/6"],
    ["Attest/AttestIntelCollateral.cs#3/6"],
    ["Attest/AttestIntelCollateral.cs#4/6"],
    ["Attest/AttestIntelCollateral.cs#5/6"],
    ["Attest/AttestIntelCollateral.cs#6/6"],
    ["IntentV2.cs#2/2@4/4"],
    ["ParamProvenance.cs#2/2"],
    ["ProvenanceGate.cs#2/10"],
    ["ProvenanceGate.cs#3/10"],
    ["ProvenanceGate.cs#4/10"],
    ["ProvenanceGate.cs#5/10"],
    ["ProvenanceGate.cs#6/10"],
    ["ProvenanceGate.cs#7/10"],
    ["ProvenanceGate.cs#8/10"],
    ["ProvenanceGate.cs#9/10"],
    ["ProvenanceGate.cs#10/10"],
    ["Ext/Ledger.cs#1/9"],
    ["Ext/Ledger.cs#2/9"],
    ["Ext/Ledger.cs#3/9"],
    ["Ext/Ledger.cs#4/9"],
    ["Ext/Ledger.cs#5/9"],
    ["Ext/Ledger.cs#6/9"],
    ["Ext/Ledger.cs#7/9"],
    ["Ext/Ledger.cs#8/9"],
    ["A2a.cs"],
    ["Attest/AttestCommon.cs"],
    ["IntentMap.cs#1/3", "IntentHistory.cs#2/2"],
    ["IntentMap.cs#2/3"],
    ["IntentMap.cs#3/3"],
    ["IntentHistory.cs#1/2", "Agent.cs"],
    ["IntentJs.cs#2/7"],
    ["IntentJs.cs#3/7"],
    ["IntentJs.cs#4/7"],
    ["IntentJs.cs#5/7"],
    ["IntentJs.cs#6/7"],
    ["IntentJs.cs#7/7"],
    ["Blueprint.cs#1/6"],
    ["Blueprint.cs#2/6"],
    ["Blueprint.cs#3/6"],
    ["Blueprint.cs#4/6"],
    ["Blueprint.cs#5/6"],
    ["Blueprint.cs#6/6"],
    ["PcaGrant.cs#1/3", "Ext/JsCanon.cs#3/4"],
    ["PcaGrant.cs#2/3", "Ext/JsCanon.cs#4/4"],
    ["PcaGrant.cs#3/3"],
    ["Ext/JsCanon.cs#1/4"],
    ["Ext/JsCanon.cs#2/4"],
    ["Actions.cs#5/6@2/4"],
    ["Actions.cs#5/6@3/4"],
    ["Actions.cs#5/6@4/4"],
    ["Attest/AttestDer.cs#2/5"],
    ["Attest/AttestDer.cs#3/5"],
    ["Attest/AttestDer.cs#4/5"],
    ["Attest/AttestDer.cs#5/5"],
    ["Attest/AttestJws.cs#2/16"],
    ["Attest/AttestJws.cs#3/16"],
    ["Attest/AttestJws.cs#4/16"],
    ["Attest/AttestJws.cs#5/16"],
    ["Attest/AttestJws.cs#6/16"],
    ["Attest/AttestJws.cs#7/16"],
    ["Attest/AttestJws.cs#8/16"],
    ["Attest/AttestJws.cs#9/16"],
    ["Attest/AttestJws.cs#10/16"],
    ["Attest/AttestJws.cs#11/16"],
    ["Attest/AttestJws.cs#12/16"],
    ["Attest/AttestJws.cs#13/16"],
    ["Attest/AttestJws.cs#14/16"],
    ["Attest/AttestJws.cs#15/16"],
    ["Attest/AttestJws.cs#16/16"],
    ["Approval.cs#2/2"],
    ["Pca.cs#4/6@2/2"],
    ["Attest/AttestCert.cs#2/2@3/6", "Attest/AttestCert.cs#2/2@4/6"],
    ["Attest/AttestCert.cs#2/2@5/6", "Attest/AttestCert.cs#2/2@6/6"],
    ["Attest/AttestXml.cs#3/4@2/2"],
    ["Attest/AttestIntel.cs#2/5"],
    ["Attest/AttestIntel.cs#3/5"],
    ["Attest/AttestIntel.cs#4/5"],
    ["Attest/AttestIntel.cs#5/5"],
    ["Attest/AttestNvidia.cs#2/3"],
    ["Attest/AttestNvidia.cs#3/3"],
    ["SafeRegex.cs#1/6@2/4"],
    ["SafeRegex.cs#1/6@3/4"],
    ["SafeRegex.cs#1/6@4/4"],
    ["SafeRegex.cs#5/6@2/2"],
    ["Risk.cs#2/2"],
    ["ProhibitionPlane.cs#2/4"],
    ["ProhibitionPlane.cs#3/4"],
    ["ProhibitionPlane.cs#4/4"],
    ["Contracts.cs#2/2"],
    ["ContractEnforcer.cs"],
    ["StoreConformanceKv.cs#2/6"],
    ["StoreConformanceKv.cs#3/6"],
    ["StoreConformanceKv.cs#4/6"],
    ["StoreConformanceKv.cs#5/6"],
    ["StoreConformanceKv.cs#6/6"],
    ["Pca.cs#2/6@2/7"],
    ["Pca.cs#2/6@3/7"],
    ["Pca.cs#2/6@4/7"],
    ["Pca.cs#2/6@5/7"],
    ["Pca.cs#2/6@6/7"],
    ["Pca.cs#2/6@7/7"],
    ["Pca.cs#3/6@2/6"],
    ["Pca.cs#3/6@3/6"],
    ["Pca.cs#3/6@4/6"],
    ["Pca.cs#3/6@5/6"],
    ["Pca.cs#3/6@6/6"],
    ["OracleFacts.cs#2/2"],
    ["ArgProvenance.cs#2/3"],
    ["ArgProvenance.cs#3/3"],
    ["Caveats.cs", "Escalation.cs", "Refusals.cs"],
    ["Attest/AttestXml.cs#2/4@2/2"],
    ["SafeRegex.cs#6/6@2/6"],
    ["SafeRegex.cs#6/6@3/6"],
    ["SafeRegex.cs#6/6@4/6"],
    ["SafeRegex.cs#6/6@5/6"],
    ["SafeRegex.cs#6/6@6/6"],
    ["../AtlasPca.Pairing/Abe/Abe.cs#1/4", "../AtlasPca.Pairing/Abe/Fame.cs#3/3"],
    ["../AtlasPca.Pairing/Abe/Abe.cs#2/4"],
    ["../AtlasPca.Pairing/Abe/Abe.cs#3/4"],
    ["../AtlasPca.Pairing/Abe/Abe.cs#4/4"],
    ["../AtlasPca.Pairing/Abe/Fame.cs#1/3"],
    ["../AtlasPca.Pairing/Abe/Fame.cs#2/3"],
    ["../AtlasPca.Pairing/Bbs/Bbs.cs#2/3"],
    ["../AtlasPca.Pairing/Bbs/Bbs.cs#3/3"],
    ["../AtlasPca.Pairing/Bbs/BbsCredential.cs#1/2"],
    ["../AtlasPca.Pairing/Aggsig/AggsigCore.cs"],
    ["../AtlasPca.Pairing/Bls12.cs", "../AtlasPca.Pairing/Aggsig/RegisteredKey.cs"],
    ["../AtlasPca.Pairing/Aggsig/Aggsig.cs", "../AtlasPca.Pairing/Aggsig/KeyRegistry.cs", "../AtlasPca.Pairing/NativeResolver.cs"],
    ["../AtlasPca.Pairing/Aggsig/AggsigWitness.cs", "../AtlasPca.Pairing/Gt.cs"],
    ["../AtlasPca.Fhe/FheSeal.cs#2/2"],
    ["../AtlasPca.MpcLweOt/EndemicOt.cs#1/2", "../AtlasPca.MpcLweOt/EndemicOtNet.cs"],
    ["../AtlasPca.MpcLweOt/EndemicOt.cs#2/2"],
    ["A2aPkg/A2aCard.cs#1/2"],
    ["A2aPkg/A2aPca.cs#2/4"],
    ["A2aPkg/A2aPca.cs#3/4"],
    ["A2aPkg/A2aPca.cs#4/4"],
    ["Acp/Acp.cs#2/2"],
    ["Acp/X402Http.cs", "Acp/Spt.cs"],
    ["ActionsKit/ActionAuthor.cs#1/2"],
    ["ActionsKit/ActionAuthor.cs#2/2"],
    ["ActionsKit/ActionBuiltin.cs", "ActionsKit/ActionDefConstants.cs"],
    ["ActionsKit/ActionBusinessRules.cs#2/3"],
    ["ActionsKit/ActionBusinessRules.cs#3/3"],
    ["ActionsKit/ActionDerive.cs#2/2"],
    ["ActionsKit/ActionBusinessRulesDiff.cs", "ActionsKit/ActionCompat.cs"],
    ["ActionsKit/ActionHosted.cs#1/2", "ActionsKit/ActionEvolve.cs"],
    ["ActionsKit/ActionHosted.cs#2/2"],
    ["ActionsKit/ActionLint.cs#2/2", "ActionsKit/ActionIdPattern.cs"],
    ["ActionsKit/ActionPacks.cs", "ActionsKit/ActionRender.cs"],
    ["ActionsKit/ActionTestRunner.cs"],
    ["ActionsKit/ActionSync.cs", "ActionsKit/ActionUndo.cs", "ActionsKit/ActionUndoEngine.cs", "ActionsKit/Ak.cs"],
    ["ActionsKit/ImportCommon.cs#2/3"],
    ["ActionsKit/ImportCommon.cs#3/3"],
    ["ActionsKit/ImportCore.cs#2/2"],
    ["ActionsKit/ImportEval.cs#2/2"],
    ["ActionsKit/ImportGraphql.cs#2/2"],
    ["ActionsKit/ImportGrpc.cs#2/3"],
    ["ActionsKit/ImportGrpc.cs#3/3"],
    ["ActionsKit/ImportPipeline.cs", "ActionsKit/ImportModel.cs#2/2"],
    ["ActionsKit/ImportModel.cs#1/2", "ActionsKit/ImportLimits.cs"],
    ["ActionsKit/ImportReview.cs#1/2"],
    ["ActionsKit/ImportSuggest.cs#2/3"],
    ["ActionsKit/ImportSuggest.cs#3/3"],
    ["ActionsKit/YamlEmit.cs#2/2"],
    ["ChainCompact.cs", "ActionScopes.cs"],
    ["ApprovalChannels.cs", "Adapters/GuardedTool.cs"],
    ["AuthorizeExecution.cs", "ActionReceipts.cs", "PcaCheapClaims.cs"],
    ["ThresholdVerify.cs", "Adapters/OpenAiAdapter.cs"],
    ["PcaReplay.cs", "Adapters/AnthropicAdapter.cs", "ObligationsCollect.cs"],
    ["PolicyLinkTemplates.cs", "PcaDiscovery.cs", "PcaPolicyVm.cs"],
    ["Adapters/OpenAiAgentsGuard.cs#1/2"],
    ["Adapters/OpenAiAgentsGuard.cs#2/2"],
    ["AgentCard/AgentCards.cs#1/2", "AgentClient/PcaAgent.cs#2/2"],
    ["AgentCard/AgentCards.cs#2/2", "Analyzer/Constitution.cs"],
    ["AgentClient/PcaAgent.cs#1/2", "Analyzer/CaveatAnalysis.cs"],
    ["Analyzer/Coverage.cs#2/2"],
    ["Analyzer/Enumerate.cs#2/2"],
    ["Analyzer/Exposure.cs#2/3"],
    ["Analyzer/Exposure.cs#3/3"],
    ["Analyzer/Flip.cs#2/2"],
    ["Analyzer/Filter.cs#1/2", "Analyzer/Jx.cs"],
    ["Analyzer/Residual.cs#2/2"],
    ["Analyzer/Narrowing.cs#1/2"],
    ["Analyzer/Validate.cs#1/2"],
    ["Ap2/Chain.cs#2/2"],
    ["Ap2/Constraints.cs#2/2"],
    ["Ap2/Mandates.cs#1/2"],
    ["Ap2/Sdjwt.cs#1/2"],
    ["Ap2/Sdjwt.cs#2/2"],
    ["Ap2/PcaBinding.cs", "Ap2/Settlement.cs"],
    ["AttestEat/EatAmd.cs", "AttestEat/EatProvenance.cs"],
    ["AttestEat/EatFresh.cs", "AttestEat/EatPqCoSign.cs"],
    ["AttestEat/PcaAttestEat.cs#2/2"],
    ["AttestEat/EatToken.cs#1/2", "Authzen/AuthzenGuards.cs"],
    ["Authzen/PolicyVmDecide.cs"],
    ["Authzen/AuthzenSearch.cs", "Ciba/AdaIdna.cs"],
    ["Ciba/Ciba.cs#2/2"],
    ["Ciba/CibaApproval.cs#2/2"],
    ["Ciba/CibaClient.cs#2/2"],
    ["Ciba/CibaKv.cs", "Compliance/ComplianceTable.cs"],
    ["Compliance/PcaCompliance.cs#1/2", "Compliance/PcaComplianceFramework.cs"],
    ["Compliance/PcaCompliance.cs#2/2"],
    ["Connect/ConnectProxy.cs", "Connect/ConnectAuthority.cs"],
    ["Connect/ConnectRefresh.cs", "Connect/ConnectReplayGuard.cs"],
    ["Connect/TokenVault.cs#1/2"],
    ["Connect/TokenVault.cs#2/2"],
    ["Connectors/ConnectorProviders.cs#1/2", "Connect/VaultErrors.cs"],
    ["Connectors/ConnectorProviders.cs#2/2"],
    ["Connectors/PcaConnectorsAuthorize.cs"],
    ["ControlEvals/ControlEvalsExample.cs", "Connectors/ProviderRegistry.cs"],
    ["ControlEvals/PcaControlEvals.cs#2/2"],
    ["Dataflow/DataFlow.cs#1/2"],
    ["Dataflow/Detectors.cs"],
    ["Dataflow/TraceRules.cs#1/2", "Dataflow/DetectorReceipts.cs"],
    ["Dataflow/TraceRules.cs#2/2"],
    ["Doctor/PcaDoctor.cs#2/4"],
    ["Doctor/PcaDoctor.cs#3/4"],
    ["Doctor/PcaDoctor.cs#4/4"],
    ["Dpop/Dpop.cs#1/3"],
    ["Dpop/Dpop.cs#2/3"],
    ["Evidence/EvidenceReplay.cs#2/2"],
    ["Events/Events.cs", "Evidence/EvidenceBundle.cs", "Explain/ExplainJs.cs"],
    ["Explain/Explainer.cs#2/4@3/4"],
    ["Explain/Explainer.cs#3/4@2/2"],
    ["Explain/Explainer.cs#4/4@1/4"],
    ["Ext/BondStore.cs#2/2"],
    ["Ext/BudgetLedger.cs#1/2"],
    ["Ext/Budgets.cs#2/2"],
    ["Ext/MeshDomain.cs#2/2"],
    ["Ext/MeshWitness.cs#2/2@2/2"],
    ["Ext/StoredLedger.cs#2/2", "Ext/FileMeshWitnessStore.cs"],
    ["Ext/MeshWitness.cs#1/2"],
    ["Frost/Frost.cs#1/2@2/2"],
    ["Frost/Frost.cs#2/2@2/4"],
    ["Gateway/PcaGateway.cs#1/2@3/4"],
    ["Gateway/PcaGateway.cs#2/2@1/2"],
    ["Gateway/PcaGatewayCore.cs#2/2@1/2"],
    ["Gnap/Gnap.cs#2/3@1/4"],
    ["Gnap/Gnap.cs#3/3@1/4"],
    ["Gnap/Interaction.cs#2/2@2/4"],
    ["Gnap/GnapThreshold.cs"],
    ["Goal/GoalBench.cs#1/2@3/4"],
    ["Goal/GoalBench.cs#2/2@4/4"],
    ["Goal/GoalCodec.cs#2/3@1/4"],
    ["Goal/GoalCodec.cs#3/3@4/4"],
    ["Goal/GoalDisambiguate.cs#2/2"],
    ["Goal/GoalExamples.cs#2/2@1/4"],
    ["Goal/GoalInterpret.cs#2/3@4/4"],
    ["Goal/GoalInterpret.cs#3/3@2/4"],
    ["Goal/GoalNVersion.cs#2/2@1/2"],
    ["Goal/GoalOntology.cs#2/3@1/2"],
    ["Goal/GoalOntology.cs#3/3@2/2"],
    ["Goal/GoalPrecedent.cs#2/2"],
    ["Goal/GoalReview.cs#2/3@4/4"],
    ["Goal/GoalReview.cs#3/3@2/4"],
    ["Goal/GoalSelectors.cs#2/3@2/2"],
    ["Goal/GoalSelectors.cs#3/3@4/4"],
    ["Grants/Bundle.cs#2/2"],
    ["Grants/FreshAtOps.cs#2/2"],
    ["Grants/GrantsUtil.cs"],
    ["Grants/LeaseOps.cs", "Grants/GrantHttp.cs"],
    ["Grants/LeaseStoreConformance.cs"],
    ["IdJag/IdJag.cs#2/2@4/4"],
    ["Harness/PcaHarness.cs#1/2@2/2"],
    ["Intent/IntentCompilers.cs#1/2@2/4"],
    ["Intent/IntentCompilers.cs#2/2@3/4"],
    ["Intent/IntentEffects.cs", "Intent/IntentFrames.cs#2/2"],
    ["Intent/IntentFrames.cs#1/2@2/4"],
    ["Intent/IntentLayers.cs#1/2@3/4"],
    ["Intent/IntentLayers.cs#2/2@4/4"],
    ["Intent/IntentLearner.cs#1/2@5/12", "Intent/IntentLearner.cs#1/2@6/12", "Intent/IntentLearner.cs#1/2@7/12", "Intent/IntentLearner.cs#1/2@8/12"],
    ["Intent/IntentLearner.cs#1/2@10/12"],
    ["Intent/IntentLearner.cs#2/2@7/12"],
    ["Intent/IntentLearner.cs#2/2@9/12", "Intent/IntentLearner.cs#2/2@10/12", "Intent/IntentLearner.cs#2/2@11/12", "Intent/IntentLearner.cs#2/2@12/12"],
    ["Intent/IntentMapKit.cs#2/3@4/4"],
    ["Intent/IntentMapKit.cs#3/3@2/4"],
    ["Intent/IntentMultiAgg.cs#2/2@1/4"],
    ["Intent/IntentMath.cs#1/2@4/4"],
    ["Intent/IntentOmega.cs#2/3", "Intent/IntentOutcome.cs"],
    ["Intent/IntentOmega.cs#3/3@3/4"],
    ["Intent/IntentProfile.cs#2/2@1/2"],
    ["Intent/IntentRamp.cs#1/2@2/2"],
    ["Intent/IntentRefine.cs#2/2@4/4"],
    ["Intent/IntentRender.cs#2/2@4/4"],
    ["Intent/IntentRuntime.cs#2/2"],
    ["Intent/IntentSchema.cs"],
    ["Intent/IntentUx.cs"],
    ["Intent/IntentStats.cs", "Intent/IntentStatement.cs"],
    ["Invariants/InvariantProperties.cs#2/2"],
    ["Invariants/InvariantArbitraries.cs", "Invariants/InvariantsRng.cs"],
    ["InteropJs/JsX.cs", "Intent/IntentWorld.cs"],
    ["Intent/IntentWitnesses.cs", "Invariants/PcaInvariants.cs"],
    ["Jose/Jose.cs#2/3"],
    ["Jose/Jose.cs#3/3"],
    ["Jose/JoseKeys.cs#2/2"],
    ["Jose/WhatwgUrl.cs#1/2"],
    ["Mcp/Mcp.cs#1/2", "Mcp/PcaFetch.cs"],
    ["Mcp/Mcp.cs#2/2"],
    ["Mcp/McpDraft.cs#2/2@1/2"],
    ["Notary/PcaNotary.cs#2/2"],
    ["Oauth/Oauth.cs#1/2"],
    ["Oidc/Oidc.cs#2/2"],
    ["Oauth/WhatwgUrl.cs"],
    ["Oprf/Oprf.cs#1/2", "Oprf/OprfPca.cs"],
    ["Oprf/Oprf.cs#2/2", "Oprf/Ristretto255.cs"],
    ["Payments/Payments.cs#2/2"],
    ["Payments/NetworkToken.cs", "Payments/NetworkTokenProviders.cs"],
    ["Payments/PaymentsJs.cs", "Payments/PaymentsAtomic.cs"],
    ["PolicyBridgeKit/Cedar.cs#2/2"],
    ["Payments/Rails.cs", "Payments/RailAuthorizer.cs"],
    ["PolicyBridgeKit/Cel.cs#2/3"],
    ["PolicyBridgeKit/Cel.cs#3/3"],
    ["PolicyBridgeKit/PbJs.cs", "PolicyBridgeKit/OpenFga.cs#2/2"],
    ["PolicyBridgeKit/OpenFga.cs#1/2", "PolicyBridgeKit/PolicyBridge.cs"],
    ["PolicyCi/CiCli.cs#2/2", "PolicyCi/CiJs.cs"],
    ["PolicyCi/CiAuthoring.cs", "PolicyCi/CiNormalize.cs"],
    ["PolicyCi/CiRules.cs#1/2", "PqThreshold/HybridThreshold.cs"],
    ["PolicyCi/CiRules.cs#2/2"],
    ["PqSuites.cs"],
    ["Rag/RagFilter.cs"],
    ["Ratchet/CapabilityRatchet.cs"],
    ["PcaCore.cs#1/2", "Ratchet/EdwardsPoint.cs"],
    ["PcaCore.cs#2/2"],
    ["PcaConstants.cs", "KvStateStore.cs"],
    ["PcaServer.cs", "PqThreshold/LatticeThresholdExperimental.cs"],
    ["Ratchet/RiskAccumulator.cs#2/2", "Ratchet/RatchetGroup.cs"],
    ["Ratchet/RatchetBinding.cs", "Ratchet/RatchetAdapters.cs"],
    ["Research/Immune.cs#2/2"],
    ["Research/Dlp.cs", "Revoke/FileRevocationStore.cs"],
    ["Revoke/RevocationConformance.cs", "Revoke/Revoke.cs#2/2"],
    ["Revoke/Revoke.cs#1/2"],
    ["Sandbox/PcaSandbox.cs#2/3"],
    ["Sandbox/PcaSandbox.cs#3/3"],
    ["Sandbox/SandboxEgressProxy.cs#2/2"],
    ["Sandbox/SandboxEgress.cs"],
    ["Sandbox/SandboxUrl.cs#1/2", "Sandbox/SandboxHandles.cs"],
    ["Sandbox/SandboxUrl.cs#2/2"],
    ["Schema/PcaSchema.cs#2/2"],
    ["Scim/Scim.cs#2/3"],
    ["Scim/Scim.cs#3/3"],
    ["Scitt/Cbor.cs#1/2", "Scitt/FileLogStore.cs"],
    ["Scitt/Cbor.cs#2/2", "Scitt/MemoryLog.cs"],
    ["Scitt/Scitt.cs#2/2"],
    ["Sdjwt/Sdjwt.cs#2/3"],
    ["Sdjwt/Sdjwt.cs#3/3"],
    ["Siem/SiemExport.cs#2/3"],
    ["Siem/SiemExport.cs#3/3"],
    ["Signals/Signals.cs#2/2"],
    ["Signals/SsfManage.cs#2/2"],
    ["Signals/SsfStream.cs#1/2"],
    ["Spiffe/SpiffeBridge.cs#2/4"],
    ["Spiffe/SpiffeBridge.cs#3/4"],
    ["Spiffe/SpiffeBridge.cs#4/4"],
    ["StoreConformanceBond.cs#2/3"],
    ["StoreConformanceBond.cs#3/3"],
    ["StoreConformanceBudget.cs#2/3"],
    ["StoreConformanceBudget.cs#3/3"],
    ["StoreConformanceLedger.cs#2/2"],
    ["StoreConformanceMeshWitness.cs#1/2"],
    ["StoreConformancePcaState.cs#1/3", "StoreConformancePkg/StoreInventories.cs"],
    ["StoreConformancePcaState.cs#2/3"],
    ["StoreConformancePcaState.cs#3/3"],
    ["StoreConformancePkg/StoreModel.cs"],
    ["StoreConformancePkg/StoreReport.cs", "StoreConformancePkg/StoreRecorder.cs"],
    ["Testing/PcaTesting.cs#2/2"],
    ["TxnTokens/TxnTokens.cs#1/2"],
    ["Vc/Vc.cs#2/3"],
    ["Vc/Vc.cs#3/3"],
    ["Vdf/Vdf.cs#2/2"],
    ["Wallet/TrustedChannel.cs#2/3"],
    ["Wallet/TrustedChannel.cs#3/3"],
    ["Wallet/WalletCard.cs#2/3"],
    ["Wallet/WalletCard.cs#3/3"],
    ["Wallet/WalletCore.cs#2/3"],
    ["Wallet/WalletCore.cs#3/3"],
    ["Wallet/WalletDelivery.cs", "WebBotAuth/DirectoryFetch.cs"],
    ["Wallet/WalletPricing.cs", "WebBotAuth/ContentDigest.cs"],
    ["WebBotAuth/WebBotAuth.cs#2/3"],
    ["WebBotAuth/WebBotAuth.cs#3/3"],
    ["Webauthn/Webauthn.cs#2/2"],
    ["AgentNative.cs#2/3"],
    ["AgentNative.cs#3/3"],
    ["SiblingPortsSmall.cs#2/2", "Connect/ConnectStoreOps.cs"],
    ["Ext/OptimisticAdjudication.cs#1/2"],
    ["Ext/OptimisticAdjudication.cs#2/2"],
    ["Ext/StoreBondLedger.cs", "Ext/BondSettlement.cs#2/2"],
    ["Ext/BondSettlement.cs#1/2"],
    ["RegexBudget.cs", "PackageConstants.cs"],
    ["Ext/Kem.cs#2/2"],
    ["Ext/Entropy.cs#2/3"],
    ["Ext/Entropy.cs#3/3"],
    ["Attest/AttestVendors.cs#2/2", "NoDuplicateKeys.cs", "ReplayClock.cs"],
    ["Intent/DetMath.cs", "OwnerOnly.cs"],
    ["Ext/ZkCompliance.cs#2/2"],
    ["Ext/ZkPolicyVm.cs#2/2"],
    ["Ext/MeshIssuing.cs#2/2"],
    ["Ext/PqQuorum.cs#2/2"],
    ["Research/AgentConsole.cs#1/2"],
    ["Ext/AttestationSoft.cs#2/3"],
    ["Ext/AttestationSoft.cs#3/3"],
    ["Ext/AttestPuf.cs#2/2"],
    ["Ext/GuardianHa.cs#2/2"],
    ["Ext/AttestAllowlist.cs#2/2"],
    ["Ext/AttestMaaKeys.cs#2/3"],
    ["Ext/AttestMaaKeys.cs#3/3"],
    ["Ext/ObjectiveRisk.cs#2/4"],
    ["Ext/ObjectiveRisk.cs#3/4"],
    ["Ext/ObjectiveRisk.cs#4/4"],
    ["Ext/Progress.cs#2/4"],
    ["Ext/Progress.cs#3/4"],
    ["Ext/Progress.cs#4/4"],
    ["Ext/IntentMisc2.cs#2/2"],
    ["Ext/FrostNet.cs#2/3"],
    ["Ext/FrostNet.cs#3/3"],
    ["Ext/FrostPq.cs", "Ext/FrostNonceStore.cs"],
    ["Ext/FrostDkgChannel.cs#2/2"],
    ["Ext/FrostDkg.cs#1/3"],
    ["Ext/FrostDkg.cs#2/3"],
    ["Ext/FrostDkg.cs#3/3"],
    ["Attest/AttestNvidiaApi.cs#2/2"],
    ["VerifyPcactn.cs#2/2"],
    ["Ext/FrostDkgTls.cs#2/2"],
    # run 45873188747 (Linux shards ran ~5 h, mutants left untested): the 100 costliest measured shards cut in up to 4 by their survivors / retests (stryker-reshard.py); the old slots keep their numbers
    ["Pca.cs#1/6@4/4"],
    ["Pca.cs#1/6@3/4"],
    ["Pca.cs#1/6@1/4"],
    ["UndoCoordinator.cs#1/2@3/4"],
    ["UndoCoordinator.cs#1/2@2/4"],
    ["UndoCoordinator.cs#1/2@1/4"],
    ["Attest/AttestNvidiaCollateral.cs#1/4@2/2"],
    ["Actions.cs#1/6@2/4"],
    ["Actions.cs#1/6@1/4", "Actions.cs#1/6@3/4"],
    ["Actions.cs#3/6@1/12", "Actions.cs#3/6@2/12"],
    ["StoreConformanceApproval.cs#2/2"],
    ["K3.cs#2/2@1/2"],
    ["K3.cs#2/2@2/2"],
    ["K3.cs#1/2@1/2"],
    ["ReadSide.cs"],
    ["CaveatLang.cs#2/2@2/2"],
    ["CaveatLang.cs#2/2@1/2"],
    ["IntentV2.cs#1/2@4/4"],
    ["IntentV2.cs#1/2@3/4", "IntentV2.cs#1/2@1/4"],
    ["RevocationFreshness.cs"],
    ["BreakGlass.cs"],
    ["ReadVault.cs"],
    ["PlanLifecycle.cs#1/2"],
    ["Obligations.cs"],
    ["Actions.cs#6/6@1/2"],
    ["Attest/AttestCert.cs#2/2@1/6"],
    ["Risk.cs#1/2@2/4"],
    ["Risk.cs#1/2@4/4"],
    ["Risk.cs#1/2@1/4"],
    ["Forbid.cs#2/2"],
    ["Forbid.cs#1/2"],
    ["Authorize.cs#3/5@1/4"],
    ["Authorize.cs#3/5@2/4"],
    ["Authorize.cs#3/5@4/4"],
    ["Taint.cs"],
    ["SafetyEvidence.cs#2/2@2/2"],
    ["SafetyEvidence.cs#2/2@1/2"],
    ["Authorize.cs#5/5@3/4"],
    ["Authorize.cs#5/5@4/4"],
    ["Authorize.cs#5/5@2/4"],
    ["Facade.cs#1/7"],
    ["ProducerVectors.cs#1/2"],
    ["VerifyPcactn.cs#1/2@1/2"],
    ["Ext/FrostNetHttp.cs#2/2@2/2"],
    ["Ext/FrostNetHttp.cs#1/2@2/2"],
    ["Ext/FrostNetHttp.cs#1/2@1/2"],
    ["Ext/FrostDkgTls.cs#1/2@4/4"],
    ["Ext/FrostDkgTls.cs#1/2@2/4"],
    ["Ext/FrostDkgTls.cs#1/2@1/4"],
    ["Authorize.cs#2/5@5/8"],
    ["Authorize.cs#2/5@6/8"],
    ["Authorize.cs#2/5@7/8"],
    ["Ext/Mesh.cs#4/9@1/2"],
    ["UndoCoordinator.cs#2/2@2/4"],
    ["UndoCoordinator.cs#2/2@4/4"],
    ["UndoCoordinator.cs#2/2@3/4"],
    ["ActionsRegistry.cs#1/2@1/2"],
    ["ActionsRegistry.cs#2/2@1/2"],
    ["ActionsRegistry.cs#2/2@2/2"],
    ["Undo.cs#1/2"],
    ["Undo.cs#2/2@2/2"],
    ["Undo.cs#2/2@1/2"],
    ["Attest/AttestNvidiaCollateral.cs#2/4@2/2"],
    ["Attest/AttestNvidiaCollateral.cs#4/4@2/2"],
    ["Sigstore.cs#1/2@3/4"],
    ["Attest/AttestMaa.cs#1/2@2/2"],
    ["Keys.cs#2/2@2/2"],
    ["Keys.cs#2/2@1/2"],
    ["Predicates.cs#2/4@1/2"],
    ["Predicates.cs#4/4@1/2"],
    ["Actions.cs#3/6@10/12"],
    ["Actions.cs#3/6@12/12", "Actions.cs#3/6@11/12"],
    ["IntentV2.cs#2/2@1/4"],
    ["IntentV2.cs#2/2@2/4"],
    ["IntentV2.cs#2/2@3/4"],
    ["ParamProvenance.cs#1/2"],
    ["StepUp.cs#2/2"],
    ["StepUp.cs#1/2"],
    ["Evidence/EvidenceScitt.cs"],
    ["Explain/Explainer.cs#2/4@1/4"],
    ["Explain/Explainer.cs#2/4@4/4", "Explain/Explainer.cs#2/4@2/4"],
    ["Explain/Explainer.cs#3/4@1/2"],
    ["Explain/Explainer.cs#4/4@2/4"],
    ["Explain/Explainer.cs#4/4@3/4", "Explain/Explainer.cs#4/4@4/4"],
    ["Ext/Budgets.cs#1/2"],
    ["Ext/MeshRevocationSet.cs"],
    ["Ext/MerkleLog.cs#2/2"],
    ["Ext/MeshDomain.cs#1/2"],
    ["Ext/MerkleLog.cs#1/2"],
    ["Ext/StoredLedger.cs#1/2@2/2"],
    ["Ext/MeshWitness.cs#2/2@1/2"],
    ["Ext/StoredLedger.cs#1/2@1/2"],
    ["FheParts/FheOrigin.cs#2/2"],
    ["FheParts/FheOrigin.cs#1/2"],
    ["Frost/Frost.cs#1/2@1/2"],
    ["Frost/CtScalar.cs#2/2"],
    ["Frost/CtScalar.cs#1/2"],
    ["Frost/Frost.cs#2/2@4/4"],
    ["Frost/Frost.cs#2/2@1/4"],
    ["Frost/Frost.cs#2/2@3/4"],
    ["Gateway/PcaGateway.cs#1/2@2/4"],
    ["Gateway/PcaGateway.cs#1/2@4/4"],
    ["Gateway/PcaGateway.cs#1/2@1/4"],
    ["Gateway/PcaGateway.cs#2/2@2/2"],
    ["Gateway/PcaGatewayCore.cs#2/2@2/2"],
    ["Gnap/Gnap.cs#2/3@3/4"],
    ["Gnap/Gnap.cs#2/3@2/4"],
    ["Gnap/Gnap.cs#2/3@4/4"],
    ["Gnap/Gnap.cs#3/3@2/4"],
    ["Gnap/Gnap.cs#3/3@4/4"],
    ["Gnap/Gnap.cs#3/3@3/4"],
    ["Gnap/Interaction.cs#2/2@4/4"],
    ["Gnap/Interaction.cs#2/2@1/4"],
    ["Gnap/Interaction.cs#2/2@3/4"],
    ["Gnap/GnapJs.cs#2/2"],
    ["Gnap/GnapJs.cs#1/2"],
    ["Gnap/GnapProfile.cs"],
    ["Goal/GoalBench.cs#1/2@4/4"],
    ["Goal/GoalBench.cs#1/2@2/4"],
    ["Goal/GoalBench.cs#1/2@1/4"],
    ["Goal/GoalBench.cs#2/2@2/4"],
    ["Goal/GoalBench.cs#2/2@3/4"],
    ["Goal/GoalBench.cs#2/2@1/4"],
    ["Goal/GoalBinding.cs"],
    ["Goal/GoalCodec.cs#2/3@3/4"],
    ["Goal/GoalCodec.cs#2/3@2/4", "Goal/GoalCodec.cs#2/3@4/4"],
    ["Goal/GoalCodec.cs#3/3@2/4"],
    ["Goal/GoalCodec.cs#3/3@1/4"],
    ["Goal/GoalCodec.cs#3/3@3/4", "Goal/GoalCompiler.cs"],
    ["Goal/GoalCrc.cs#1/2"],
    ["Goal/GoalCrc.cs#2/2"],
    ["Goal/GoalDisambiguate.cs#1/2"],
    ["Goal/GoalExamples.cs#2/2@3/4"],
    ["Goal/GoalExamples.cs#2/2@4/4"],
    ["Goal/GoalExamples.cs#2/2@2/4"],
    ["Goal/GoalInterpret.cs#2/3@1/4"],
    ["Goal/GoalInterpret.cs#2/3@2/4"],
    ["Goal/GoalInterpret.cs#2/3@3/4"],
    ["Goal/GoalInterpret.cs#3/3@4/4"],
    ["Goal/GoalInterpret.cs#3/3@3/4"],
    ["Goal/GoalInterpret.cs#3/3@1/4"],
    ["Goal/GoalNVersion.cs#2/2@2/2"],
    ["Goal/GoalNormalize.cs"],
    ["Goal/GoalOntology.cs#2/3@2/2"],
    ["Goal/GoalOntology.cs#3/3@1/2"],
    ["Goal/GoalPrecedent.cs#1/2"],
    ["Goal/GoalReview.cs#2/3@2/4"],
    ["Goal/GoalReview.cs#2/3@1/4"],
    ["Goal/GoalReview.cs#2/3@3/4"],
    ["Goal/GoalReview.cs#3/3@4/4"],
    ["Goal/GoalReview.cs#3/3@1/4"],
    ["Goal/GoalReview.cs#3/3@3/4"],
    ["Goal/GoalSelectors.cs#2/3@1/2"],
    ["Goal/GoalSelectors.cs#3/3@2/4"],
    ["Goal/GoalSelectors.cs#3/3@1/4"],
    ["Goal/GoalSelectors.cs#3/3@3/4"],
    ["Grants/Bundle.cs#1/2"],
    ["Grants/GrantClient.cs#1/2"],
    ["Grants/GrantClient.cs#2/2"],
    ["Grants/BlueprintOps.cs#1/2"],
    ["Grants/FreshAtOps.cs#1/2"],
    ["Grants/BlueprintOps.cs#2/2"],
    ["Grants/GrantService.cs#2/2@2/4"],
    ["Grants/GrantService.cs#2/2@4/4"],
    ["Grants/GrantService.cs#2/2@1/4", "Grants/GrantService.cs#2/2@3/4"],
    ["Grants/ListAuthorized.cs"],
    ["IdJag/IdJag.cs#2/2@2/4"],
    ["IdJag/IdJag.cs#2/2@3/4"],
    ["IdJag/IdJag.cs#2/2@1/4"],
    ["Harness/PcaHarness.cs#1/2@1/2"],
    ["Intent/IntentCompilers.cs#1/2@1/4"],
    ["Intent/IntentCompilers.cs#1/2@4/4", "Intent/IntentCompilers.cs#1/2@3/4"],
    ["Intent/IntentCompilers.cs#2/2@1/4"],
    ["Intent/IntentCompilers.cs#2/2@2/4"],
    ["Intent/IntentCompilers.cs#2/2@4/4"],
    ["Intent/IntentFrames.cs#1/2@4/4"],
    ["Intent/IntentFrames.cs#1/2@3/4", "Intent/IntentFrames.cs#1/2@1/4"],
    ["Intent/IntentLayers.cs#1/2@4/4"],
    ["Intent/IntentLayers.cs#1/2@1/4"],
    ["Intent/IntentLayers.cs#1/2@2/4"],
    ["Intent/IntentLayers.cs#2/2@2/4"],
    ["Intent/IntentLayers.cs#2/2@1/4"],
    ["Intent/IntentLayers.cs#2/2@3/4"],
    ["Intent/IntentLearner.cs#1/2@12/12"],
    ["Intent/IntentLearner.cs#1/2@9/12"],
    ["Intent/IntentLearner.cs#1/2@11/12"],
    ["Intent/IntentLearner.cs#2/2@5/12"],
    ["Intent/IntentLearner.cs#2/2@6/12"],
    ["Intent/IntentLearner.cs#2/2@8/12"],
    ["Intent/IntentMapKit.cs#2/3@2/4"],
    ["Intent/IntentMapKit.cs#2/3@1/4"],
    ["Intent/IntentMapKit.cs#2/3@3/4"],
    ["Intent/IntentMapKit.cs#3/3@3/4"],
    ["Intent/IntentMapKit.cs#3/3@4/4"],
    ["Intent/IntentMapKit.cs#3/3@1/4"],
    ["Intent/IntentMultiAgg.cs#2/2@4/4"],
    ["Intent/IntentMultiAgg.cs#2/2@2/4", "Intent/IntentMultiAgg.cs#2/2@3/4"],
    ["Intent/IntentMath.cs#1/2@2/4"],
    ["Intent/IntentMath.cs#1/2@1/4"],
    ["Intent/IntentMath.cs#1/2@3/4"],
    ["Intent/IntentOmega.cs#3/3@4/4"],
    ["Intent/IntentOmega.cs#3/3@2/4"],
    ["Intent/IntentOmega.cs#3/3@1/4"],
    ["Intent/IntentProfile.cs#2/2@2/2"],
    ["Intent/IntentRamp.cs#1/2@1/2"],
    ["Intent/IntentProvenance.cs#2/2"],
    ["Intent/IntentProvenance.cs#1/2"],
    ["Intent/IntentRefine.cs#2/2@2/4"],
    ["Intent/IntentRefine.cs#2/2@1/4"],
    ["Intent/IntentRefine.cs#2/2@3/4"],
    ["Intent/IntentRender.cs#2/2@2/4"],
    ["Intent/IntentRender.cs#2/2@1/4"],
    ["Intent/IntentRender.cs#2/2@3/4"],
    ["Mcp/McpDraft.cs#2/2@2/2"],
]

def opt(name):
    if name in sys.argv:
        return sys.argv[sys.argv.index(name) + 1]
    return None

k, n, d = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3]
scope_out, baseline_in, carry_out = opt("--scope"), opt("--baseline"), opt("--carry")
if "--gen-plan" not in sys.argv and (not scope_out or bool(baseline_in) != bool(carry_out)):
    sys.exit("usage: stryker-spans.py <k> <n> <AtlasPca dir> --scope <json> [--baseline <json> --carry <json>] [--only <file>]")
# every .cs file of the verifier (subdirectories included: Ext/, Attest/) and of the ASP.NET Core middleware project, as paths
# relative to AtlasPca/ (the middleware's start with ../AtlasPca.AspNetCore/)
# Blst/ is the upstream blst C# binding that Pairing/Native/build.sh copies in on the runner (third-party, never shipped from here)
# GoalKernel/Generated/ is the Dafny translation of the proved goal kernel plus the Dafny runtime (generated code, not ours; reason in
# sdks/dotnet-pca/mutation-excluded.json): never mutated. The hand-written GoalKernel/GoalKernel.cs bridge stays in the plan.
SKIP = {"bin", "obj", "StrykerOutput", ".mutwork", "Blst", "Generated"}
MODULES = ("AtlasPca.AspNetCore", "AtlasPca.Pairing", "AtlasPca.Fhe", "AtlasPca.MpcLweOt", "AtlasPca.Fndsa", "AtlasPca.Zk")
files = sorted(os.path.relpath(os.path.join(r, f), d).replace(os.sep, "/") for top in (d, *(os.path.join(d, "..", m) for m in MODULES))
               for r, ds, fs in os.walk(top) if not ds.__setitem__(slice(None), [x for x in ds if x not in SKIP])
               for f in fs if f.endswith(".cs"))
if "--gen-plan" in sys.argv:
    # The entries for files the plan lacks, generated (never hand-written): per Stryker project, in path order, packed greedily
    # into shards of about GEN_LINES lines; a file over GEN_SPLIT lines is cut into spans of about GEN_LINES, one shard each.
    # Paste the output at the end of PLAN (after the opt-in module shards, whose numbers the workflow names) and set the
    # workflow's shard counts to len(PLAN).
    GEN_LINES, GEN_SPLIT = 800, 1200
    have = {it.partition("#")[0] for sh in PLAN for it in sh}
    proj = lambda f: os.path.normpath("AtlasPca/" + f).split("/")[0]
    out, cur, size, cp = [], [], 0, None
    flush = lambda: out.append(cur[:]) if cur else None
    for f in (x for x in files if x not in have):
        nl = len(open(os.path.join(d, f), encoding="utf-8").read().split("\n"))
        if cur and (proj(f) != cp or size + nl > GEN_LINES or nl > GEN_SPLIT):
            flush(); cur, size = [], 0
        cp = proj(f)
        if nl > GEN_SPLIT:
            m = -(-nl // GEN_LINES)
            out.extend([f"{f}#{i}/{m}"] for i in range(1, m + 1))
        else:
            cur.append(f); size += nl
    flush()
    for sh in out:
        print("    [" + ", ".join(json.dumps(x) for x in sh) + "],")
    sys.exit(0)
if n != len(PLAN):
    sys.exit(f"the workflow runs {n} shards but the plan has {len(PLAN)}: keep SHARDS in step with stryker-spans.py")
key = lambda f: posixpath.normpath("AtlasPca/" + f)  # scope / ledger path: AtlasPca/Ext/Mesh.cs, AtlasPca.AspNetCore/PcaMiddleware.cs
def parse(it):
    """'File.cs' | 'File.cs#i/n' | 'File.cs#i/n@j/m' -> (file, (i, n), (j, m)): span i of n, and inside it slice j of m (a span that is too slow for
    one shard is cut again at member declarations; (1, 1) = not sliced)."""
    f, _, sp = it.partition("#")
    sp, _, sub = sp.partition("@")
    return f, tuple(map(int, sp.split("/"))) if sp else (1, 1), tuple(map(int, sub.split("/"))) if sub else (1, 1)

parts = collections.defaultdict(list)  # file -> [(i, n, j, m)] of its plan entries
for it in (x for sh in PLAN for x in sh):
    f, (i, n_), (j, m) = parse(it)
    parts[f].append((i, n_, j, m))
if sorted(parts) != files:
    sys.exit(f"AtlasPca/ has {files}, the plan covers {sorted(parts)}: append the output of `stryker-spans.py 0 0 <dir> --gen-plan` to PLAN in stryker-spans.py")
for f, ps in parts.items():
    n_ = ps[0][1]
    # every span 1..n of the file exactly once, either whole (j/m = 1/1) or as slices 1..m of one m
    for i in range(1, n_ + 1):
        sl = sorted((j, m) for (i2, n2, j, m) in ps if (i2, n2) == (i, n_))
        if not sl or sl != [(j, sl[0][1]) for j in range(1, sl[0][1] + 1)] or any(p[1] != n_ for p in ps):
            sys.exit(f"{f}: plan spans {sorted(ps)} do not partition the file")

def read(f):
    return open(os.path.join(d, f), encoding="utf-8").read().split("\n")

def units(lines):
    """[(type_start, type_end, [(member_start, member_end), ...])]: top-level types (indent 0) and their members (indent 4);
    attribute lines belong to the declaration below them. Ranges are 1-based and inclusive; a member runs to the line
    before the next declaration of indent 0 or 4."""
    cand = [i + 1 for i, l in enumerate(lines) if re.match(r"^( {4})?[A-Za-z\[]", l) and not l.startswith(("using ", "namespace "))]
    starts = []
    for x in cand:
        prev = starts[-1] if starts else None
        ind = len(lines[x - 1]) - len(lines[x - 1].lstrip(" "))
        # a declaration right below its own attribute lines (same indent, only attributes / blanks / comments between)
        if prev is not None and lines[prev - 1].lstrip().startswith("[") and len(lines[prev - 1]) - len(lines[prev - 1].lstrip(" ")) == ind \
                and all(re.match(r"^\s*(\[.*|//.*)?$", lines[j - 1]) for j in range(prev, x)):
            continue
        starts.append(x)
    out = []
    for j, s in enumerate(starts):
        end = starts[j + 1] - 1 if j + 1 < len(starts) else len(lines)
        if not lines[s - 1].startswith(" "):
            out.append([s, None, []])
        elif out:
            out[-1][2].append((s, end))
    for j, u in enumerate(out):
        u[1] = out[j + 1][0] - 1 if j + 1 < len(out) else len(lines)
        u[2] = [(a, min(b, u[1])) for a, b in u[2]]
    return out

def fence(lines, live):
    """(directive lines to insert before, fenced line ranges) for a file whose `live` lines are mutated."""
    ins, fenced = set(), []
    for t, end, members in units(lines):
        if not any(t <= x <= end for x in live):
            ins.add(t); fenced.append((t, end))
            continue
        for a, b in members:
            if not any(a <= x <= b for x in live):
                ins.add(a); fenced.append((a, b))
    return ins, fenced

def write_fenced(f, lines, ins):
    out = []
    for i, l in enumerate(lines, 1):
        if i in ins:
            out.append("// Stryker disable all")
        out.append(l)
    open(os.path.join(d, f), "w", encoding="utf-8", newline="").write("\n".join(out))

for f in files:
    if any(l.strip().startswith("// Stryker") for l in read(f)):
        sys.exit(f"{f} already has Stryker directives")

def cut(starts, lo, hi, n, i):
    """Lines [a, b] of part i of n of the lines lo..hi: n near-equal parts cut only at member declarations (`starts`)."""
    if n == 1:
        return [lo, hi]
    cuts = []
    for j in range(1, n):
        target = lo + j * (hi - lo + 1) / n
        c = [x for x in starts if lo < x <= hi and x > (cuts[-1] if cuts else lo)]
        if not c:
            sys.exit(f"lines {lo}..{hi} have no member declaration left to cut part {j + 1} of {n} at: use fewer parts")
        cuts.append(min(c, key=lambda x: abs(x - target)))
    bounds = [lo] + cuts + [hi + 1]
    return [bounds[i - 1], bounds[i] - 1]

def span(f, i, n, j=1, m=1):
    """Lines [a, b] of span i of n of f (n near-equal parts cut only at member declarations, indent 0 or 4), and inside it slice j of m (cut the same way)."""
    lines = read(f)
    starts = [t for t, _, ms in units(lines) for t in [t] + [a for a, _ in ms]]
    a, b = cut(starts, 1, len(lines), n, i)
    return cut(starts, a, b, m, j)

# the shard's scope (original-file lines); one Stryker project per shard. --only <file>[#i/n]: that one file whole, or its span i of n
# cut as the plan's spans are (the Windows shards; the merge checks that a file's Windows parts partition its lines)
only = opt("--only")
if only is not None and parse(only)[0] not in files:
    sys.exit(f"--only {only}: not a planned source file")
entries = [only] if only is not None else PLAN[k - 1]
if len({key(it.partition("#")[0]).split("/")[0] for it in entries}) != 1:
    sys.exit(f"shard {k} mixes projects: {entries}")
scope = {}
for it in entries:
    f, (i, n_), (j, m) = parse(it)
    scope[key(f)] = span(f, i, n_, j, m)
json.dump(scope, open(scope_out, "w"))

base = json.load(open(baseline_in)) if baseline_in else None
carried, globs = [], []
for rel, (a, b) in scope.items():
    f = posixpath.relpath(rel, "AtlasPca")
    lines = read(f)
    whole = (a, b) == (1, len(lines))
    if base is None:
        if whole:
            globs.append(f)  # the whole file: no fencing
            continue
        live = set(range(a, b + 1))
    else:
        old = base.get("sources", {}).get(rel)
        olds = base.get("scope", {}).get(rel)
        same = {}  # old line -> current line, for unchanged in-scope baseline lines
        live = set()
        if old is not None and olds is not None:
            old = old.split("\n")
            sm = difflib.SequenceMatcher(None, old, lines, autojunk=False)
            for tag, i1, i2, j1, j2 in sm.get_opcodes():
                if tag == "equal":
                    for o, c in zip(range(i1, i2), range(j1, j2)):
                        if olds[0] <= o + 1 <= olds[1]:
                            same[o + 1] = c + 1
                elif tag == "delete":
                    live.update({j1, j1 + 1})  # the lines around a deletion
        cur_same = set(same.values())
        live |= {x for x in range(a, b + 1) if x not in cur_same}
        live = {x for x in live if a <= x <= b}
        _, fenced = fence(lines, live)
        infence = lambda x: any(p <= x <= q for p, q in fenced) and a <= x <= b
        for m in base.get("mutants", []):
            if m["file"] != rel:
                continue
            s, e = same.get(m["start"]["line"]), same.get(m["end"]["line"])
            if s is None or e is None or not (infence(s) and infence(e)):
                continue  # changed, or in a member Stryker mutates again
            carried.append(dict(m, start=dict(m["start"], line=s), end=dict(m["end"], line=e), carried=True))
        if not live:
            continue  # nothing to mutate in this file: every in-scope mutant is carried
    ins, _ = fence(lines, live)
    write_fenced(f, lines, ins)
    print(f"{f}: lines {a}..{b}, {len(live)} live line(s), {len(ins)} directive(s)", file=sys.stderr)
    globs.append(f)
# Stryker mutates and compiles EVERY file of the project whatever --mutate says (the glob only filters the report afterwards),
# so an unrollbackable mutant in any other file aborted the shard ("Internal error due to compile error"). Every file of the
# shard's project that gets no glob (out of scope, or in scope with nothing live in targeted mode) gets one `// Stryker disable
# all` line before its file-scoped `namespace` line: the directive holds for the namespace node and every member below it, so
# none of their mutants is injected (stryker-report.py collect fails the shard if one was).
sproj, globbed = next(iter(scope)).split("/")[0], {key(g) for g in globs}
for f in files:
    if key(f) in globbed or key(f).split("/")[0] != sproj:
        continue
    lines = read(f)
    ns = [i for i, l in enumerate(lines) if re.match(r"^namespace [A-Za-z0-9_.]+;", l)]
    if len(ns) != 1:
        sys.exit(f"{f}: no single file-scoped namespace line to fence the file at")
    open(os.path.join(d, f), "w", encoding="utf-8", newline="").write("\n".join(lines[:ns[0]] + ["// Stryker disable all"] + lines[ns[0]:]))
if carry_out:
    json.dump(carried, open(carry_out, "w"))
    print(f"targeted: {len(carried)} baseline mutant(s) carried forward", file=sys.stderr)
for f in globs:
    print(f"**/{key(f)}")
