#!/usr/bin/env python3
"""Shard K of N of the Stryker.NET run over AtlasPca/: prints one --mutate glob per line, fences the shard's files (CI copy
only) with Stryker comment directives so only the wanted members are mutated, and writes the shard's scope.

   python3 stryker-spans.py <k> <n> <AtlasPca dir> --scope <scope.json> [--baseline <baseline.json> --carry <carried.json>]
   python3 stryker-spans.py 0 0 <AtlasPca dir> --gen-plan      (prints PLAN entries for every .cs file the plan does not list yet)

A shard whose file set changed still works against an old targeted baseline: the baseline is read per file (sources / scope
keyed by file), so a file that moved into a shard has no baseline entry there and is mutated whole, a file that moved out is
simply not in scope, and the files that stayed keep their carried results.

PLAN lists every .cs file of AtlasPca/ exactly once: whole, or as spans "File.cs#i/n" (n near-equal line spans cut only at
member declarations, indent 0 or 4 in the file-scoped namespace, so no mutant crosses a cut and the spans partition the
file). A .cs file missing from PLAN (or a planned file that is gone, or spans that do not partition a file) fails the
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
(run 38330673581: ~1,489 CompileErrors in each of the 12 shards, 17,834 in all, whatever the shard mutated).

TARGETED mode (--baseline = the stryker-baseline.json the same shard uploaded in an earlier run: its sources, scope and
every in-scope mutant with its status): the lines of the current sources that are not an unchanged copy of an in-scope
baseline line are live (edited, added, next to a deletion, or newly in scope). Only the members holding a live line are
mutated by Stryker (none: no glob is printed and Stryker is skipped). Every baseline mutant that lies, unchanged, in a
fenced member is written to --carry with its line numbers moved to the current source; the report step keeps its
Killed / Timeout / tested CompileError result and re-tests the others (Survived, NoCoverage, untested CompileError) one by
one with stryker-isolate.py, so new kill tests are seen without re-running Stryker over the whole shard."""
import collections, difflib, json, os, re, sys

# One shard per entry: "File.cs" (the whole file) or "File.cs#i/n" (line span i of n, cut at member declarations); paths are
# relative to AtlasPca/ (the middleware's start with ../AtlasPca.AspNetCore/, its own Stryker project: never mixed in a shard).
# Balanced on run 41748042249's per-shard Stryker minutes plus its survivor / CompileError counts (each is tested alone
# afterwards), Attest/ Ext/ and the middleware by size; the suite has since become ~6x faster (Ed25519 check).
PLAN = [
    ["Pca.cs#1/6"],
    ["Passport.cs"],
    ["ActionSchema.cs", "Ext/Optimistic.cs", "Ext/OptimisticOpen.cs"],
    ["Authorize.cs#1/5", "MissingContext.cs"],
    ["Authorize.cs#2/5", "FreshAt.cs"],
    ["Ext/Mesh.cs", "Ext/PcaInternals.cs"],
    ["ActionsRegistry.cs", "Undo.cs", "UndoStore.cs", "UndoCoordinator.cs"],
    ["Workflow.cs", "IntentRevocation.cs"],
    ["Attest/AttestNvidiaCollateral.cs"],
    ["Sigstore.cs#1/2", "Attest/AttestMaa.cs"],
    ["Sigstore.cs#2/2", "Keys.cs"],
    ["Predicates.cs", "Attest/AttestAmd.cs"],
    ["Actions.cs#1/6"],
    ["Actions.cs#3/6"],
    ["Attest/AttestCert.cs#1/2"],
    ["Issue.cs", "StoreConformance.cs", "StoreConformanceApproval.cs"],
    ["K3.cs"],
    ["PolicyAuthoring.cs"],
    ["ReadSide.cs", "CaveatLang.cs"],
    ["Attest/AttestIntelCollateral.cs"],
    ["IntentV2.cs"],
    ["../AtlasPca.AspNetCore/PcaMiddleware.cs", "../AtlasPca.AspNetCore/PcaOptions.cs", "../AtlasPca.AspNetCore/PcaProtect.cs", "../AtlasPca.AspNetCore/PcaExtensions.cs"],
    ["IntentSession.cs", "Decision.cs", "Assurance.cs", "PcaDomainSig.cs"],
    ["Lease.cs", "Attest/AttestGcp.cs", "StepUp.cs", "ParamProvenance.cs"],
    ["Operations.cs", "ReadVault.cs", "RevocationFreshness.cs", "BreakGlass.cs"],
    ["ProvenanceGate.cs", "Ext/Ledger.cs"],
    ["A2a.cs", "IntentMap.cs", "IntentHistory.cs", "Attest/AttestCommon.cs", "K4.cs", "Agent.cs"],
    ["Blueprint.cs", "IntentJs.cs", "PcaGrant.cs", "Ext/JsCanon.cs"],
    ["AtomicKv.cs", "Attest/AttestFactory.cs", "IntentWB.cs", "LessNative.cs", "Rx.cs", "DurableState.cs"],
    # run 41937170925: these shards passed their budget (12 in Stryker, 8/13/14/20 with mutants left untested); new ones go last, so the other numbers stay
    ["PlanLifecycle.cs"],
    ["Actions.cs#5/6"],
    ["Attest/AttestDer.cs"],
    ["Attest/AttestJws.cs"],
    ["Approval.cs"],
    ["Attest/AttestXml.cs#1/4"],
    ["Obligations.cs", "Attest/AttestCertExts.cs"],
    # run 42149070759: Pca, Actions and AttestXml ran out of budget, AttestCert came near it
    ["Pca.cs#4/6"],
    ["Actions.cs#2/6"],
    ["Actions.cs#4/6"],
    ["Actions.cs#6/6"],
    ["Attest/AttestCert.cs#2/2"],
    ["Attest/AttestXml.cs#3/4"],
    ["RuntimeClaim.cs"],
    # run 42441751689: shard 17 (K3 + AttestIntel + PolicyClasses, 138 mutants untested) and shard 6 (3 untested) overran the budget: one file each, the old slots keep their numbers
    ["Attest/AttestIntel.cs"],
    ["PolicyClasses.cs"],
    ["Attest/AttestNvidia.cs"],
    # run 42636647633: shard 20 lost its runner a third time (shutdown signal after 90 min at 2 workers): one file each, the old slot keeps AttestIntelCollateral
    ["SafeRegex.cs#1/6"],
    ["Executor.cs"],
    # run 42720114305: SafeRegex alone lost its runner again (shutdown at 38 min): three spans, one worker each, so the span that does it is named
    ["SafeRegex.cs#3/6"],
    ["SafeRegex.cs#5/6"],
    # the 0.5 hardening files (new code, no baseline: they run in full)
    ["Risk.cs"],
    ["Forbid.cs", "Prohibitions.cs"],
    ["ProhibitionPlane.cs"],
    ["Contracts.cs", "ContractEnforcer.cs"],
    ["StoreConformanceKv.cs"],
    # Authorize.cs grew to ~2000 lines with the 0.5 options: its spans are their own shards
    ["Authorize.cs#3/5"],
    # run 43153719902: shards 51, 52 and 56 ran out of budget (53, 53 and 600 mutants untested): Taint + Beacons and
    # SafetyEvidence get their own shards, Authorize.cs is cut in five spans (the old slots keep their numbers)
    ["Taint.cs", "Beacons.cs"],
    ["SafetyEvidence.cs"],
    ["Authorize.cs#4/5"],
    ["Authorize.cs#5/5"],
    # 0.5 agent side: the facade (with the built-in catalog), the extra signers and the producer-vector driver
    ["Facade.cs#1/7", "Catalog.cs"],
    ["SignersMore.cs"],
    ["ProducerVectors.cs"],
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
    ["Pca.cs#2/6"],
    ["Pca.cs#3/6"],
    ["Pca.cs#5/6"],
    ["Pca.cs#6/6"],
    ["IntentAcc.cs"],
    ["OracleFacts.cs", "IntentClassifier.cs"],
    ["ArgProvenance.cs"],
    ["IntentPrimitives.cs", "Escalation.cs", "IntentArtifacts.cs", "Refusals.cs", "Caveats.cs"],
    ["Attest/AttestXml.cs#2/4"],
    ["Attest/AttestXml.cs#4/4"],
    ["SafeRegex.cs#2/6"],
    ["SafeRegex.cs#4/6"],
    ["SafeRegex.cs#6/6"],
    # the opt-in module projects (own Stryker project and oracle each, native libraries built on the runner): the shard number
    # of each is its position here, and the workflow's module-shard matrix names the same numbers
    ["../AtlasPca.Pairing/Abe/Abe.cs", "../AtlasPca.Pairing/Abe/AbePolicy.cs", "../AtlasPca.Pairing/Abe/Fame.cs"],
    ["../AtlasPca.Pairing/Bbs/Bbs.cs", "../AtlasPca.Pairing/Bbs/BbsCredential.cs"],
    ["../AtlasPca.Pairing/Aggsig/Aggsig.cs", "../AtlasPca.Pairing/Aggsig/AggsigChain.cs", "../AtlasPca.Pairing/Aggsig/AggsigCore.cs",
     "../AtlasPca.Pairing/Aggsig/AggsigWitness.cs", "../AtlasPca.Pairing/Aggsig/KeyRegistry.cs", "../AtlasPca.Pairing/Aggsig/RegisteredKey.cs",
     "../AtlasPca.Pairing/Bls12.cs", "../AtlasPca.Pairing/Gt.cs", "../AtlasPca.Pairing/NativeResolver.cs"],
    ["../AtlasPca.Fhe/FheSeal.cs", "../AtlasPca.Fhe/NativeResolver.cs"],
    ["../AtlasPca.MpcLweOt/EndemicOt.cs", "../AtlasPca.MpcLweOt/EndemicOtNet.cs", "../AtlasPca.MpcLweOt/Lattice.cs"],
    ["../AtlasPca.Fndsa/NativeFnDsa.cs"],
    # every other shipped source file: generated by `stryker-spans.py 0 0 <AtlasPca dir> --gen-plan` (about 800 lines a shard, files over
    # 1200 lines in spans); they run in full (no baseline yet). Regenerate for new files, never hand-edit.
    ["../AtlasPca.AspNetCore/PcaFetchHandler.cs", "../AtlasPca.AspNetCore/PcaFilters.cs"],
    ["A2aPkg/A2aCard.cs", "A2aPkg/A2aJws.cs"],
    ["A2aPkg/A2aPca.cs"],
    ["Acp/Acp.cs", "Acp/Spt.cs", "Acp/X402Http.cs"],
    ["Acp/X402V2.cs", "ActionsKit/ActionAuthor.cs"],
    ["ActionsKit/ActionBuild.cs", "ActionsKit/ActionBuiltin.cs", "ActionsKit/ActionDefConstants.cs"],
    ["ActionsKit/ActionBusinessRules.cs"],
    ["ActionsKit/ActionBusinessRulesDiff.cs", "ActionsKit/ActionCompat.cs", "ActionsKit/ActionData.g.cs", "ActionsKit/ActionDerive.cs"],
    ["ActionsKit/ActionDiff.cs", "ActionsKit/ActionEvolve.cs", "ActionsKit/ActionHosted.cs"],
    ["ActionsKit/ActionIdPattern.cs", "ActionsKit/ActionLint.cs", "ActionsKit/ActionPacks.cs", "ActionsKit/ActionRender.cs", "ActionsKit/ActionSelectors.cs"],
    ["ActionsKit/ActionSync.cs", "ActionsKit/ActionTestRunner.cs", "ActionsKit/ActionUndo.cs", "ActionsKit/ActionUndoEngine.cs", "ActionsKit/ActionsText.cs", "ActionsKit/Ak.cs"],
    ["ActionsKit/Effective.cs", "ActionsKit/ImportCommon.cs"],
    ["ActionsKit/ImportCore.cs"],
    ["ActionsKit/ImportEval.cs"],
    ["ActionsKit/ImportGraphql.cs"],
    ["ActionsKit/ImportGrpc.cs"],
    ["ActionsKit/ImportJx.cs", "ActionsKit/ImportLimits.cs", "ActionsKit/ImportModel.cs", "ActionsKit/ImportPipeline.cs"],
    ["ActionsKit/ImportReview.cs", "ActionsKit/ImportRulesData.g.cs"],
    ["ActionsKit/ImportSuggest.cs"],
    ["ActionReceipts.cs", "ApprovalChannels.cs", "ChainCompact.cs", "PcaCheapClaims.cs", "ThresholdVerify.cs", "ObligationsCollect.cs", "ActionScopes.cs", "AuthorizeExecution.cs", "PcaPolicyVm.cs", "PcaDiscovery.cs", "PcaReplay.cs", "PolicyLinkTemplates.cs", "ActionsKit/YamlEmit.cs", "Adapters/AnthropicAdapter.cs", "Adapters/GuardedTool.cs", "Adapters/OpenAiAdapter.cs"],
    ["Adapters/OpenAiAgentsGuard.cs", "Adapters/PcaAdapters.cs"],
    ["AgentCard/AgentCards.cs", "AgentClient/PcaAgent.cs", "Analyzer/AnalyzerCore.cs", "Analyzer/CaveatAnalysis.cs", "Analyzer/Constitution.cs"],
    ["Analyzer/Coverage.cs", "Analyzer/DagAnalysis.cs"],
    ["Analyzer/Enumerate.cs"],
    ["Analyzer/Exposure.cs", "Analyzer/Field.cs"],
    ["Analyzer/Filter.cs", "Analyzer/Flip.cs", "Analyzer/Jx.cs"],
    ["Analyzer/Narrowing.cs", "Analyzer/Residual.cs"],
    ["Analyzer/TestRunner.cs", "Analyzer/Validate.cs"],
    ["Ap2/Chain.cs"],
    ["Ap2/Constraints.cs", "Ap2/Mandates.cs"],
    ["Ap2/PcaBinding.cs", "Ap2/PcaBindingVerify.cs", "Ap2/Sdjwt.cs", "Ap2/Settlement.cs"],
    ["Approvals.cs", "AttestEat/EatAmd.cs", "AttestEat/EatFresh.cs", "AttestEat/EatPqCoSign.cs", "AttestEat/EatProvenance.cs"],
    ["AttestEat/EatToken.cs", "AttestEat/PcaAttestEat.cs", "Authzen/AuthzenGuards.cs"],
    ["Authzen/AuthzenPdp.cs", "Authzen/AuthzenSearch.cs", "Authzen/PolicyVmDecide.cs", "Ciba/AdaIdna.cs"],
    ["Ciba/Ciba.cs"],
    ["Ciba/CibaApproval.cs"],
    ["Ciba/CibaClient.cs", "Ciba/CibaJs.cs", "Ciba/CibaKv.cs", "Compliance/ComplianceTable.cs"],
    ["Compliance/PcaCompliance.cs", "Compliance/PcaComplianceFramework.cs", "Compliance/PcaComplianceReport.cs"],
    ["Connect/ConnectAuthority.cs", "Connect/ConnectJs.cs", "Connect/ConnectProxy.cs", "Connect/ConnectRefresh.cs", "Connect/ConnectReplayGuard.cs"],
    ["Connect/ConnectStore.cs", "Connect/TokenVault.cs"],
    ["Connect/VaultErrors.cs", "Connectors/ConnectorProviders.cs", "Connectors/PcaConnectors.cs"],
    ["Connectors/PcaConnectorsAuthorize.cs", "Connectors/PcaConnectorsExchange.cs", "Connectors/ProviderRegistry.cs", "ControlEvals/ControlEvalsExample.cs"],
    ["ControlEvals/PcaControlEvals.cs", "Dataflow/DataFlow.cs"],
    ["Dataflow/DetectorReceipts.cs", "Dataflow/Detectors.cs", "Dataflow/TraceRules.cs", "Doctor/DoctorJs.cs"],
    ["Doctor/PcaDoctor.cs"],
    ["Dpop/Dpop.cs", "Erc7715/Erc7715.cs"],
    ["Events/Events.cs", "Evidence/EvidenceBundle.cs", "Evidence/EvidenceScitt.cs", "Evidence/EvidenceVerify.cs", "Evidence/EvidenceReplay.cs", "Explain/ExplainJs.cs"],
    ["Explain/Explainer.cs"],
    ["Ext/BondStore.cs", "Ext/BudgetLedger.cs"],
    ["Ext/Budgets.cs", "Ext/LedgerStore.cs", "Ext/MerkleLog.cs", "Ext/MeshDomain.cs", "Ext/MeshRevocationSet.cs"],
    ["Ext/FileMeshWitnessStore.cs", "Ext/MeshWitness.cs", "Ext/StoredLedger.cs", "FheParts/FheOrigin.cs", "FheParts/FheRisk.cs"],
    ["Fndsa/Fndsa.cs", "Frost/CtScalar.cs", "Frost/Frost.cs"],
    ["Gateway/PcaGateway.cs", "Gateway/PcaGatewayAdapters.cs"],
    ["Gateway/PcaGatewayCore.cs", "Gateway/PcaGatewayWorker.cs"],
    ["Gnap/Gnap.cs"],
    ["Gnap/GnapJs.cs", "Gnap/GnapProfile.cs", "Gnap/GnapThreshold.cs", "Gnap/Interaction.cs"],
    ["Goal/G.cs", "Goal/GoalBench.cs"],
    ["Goal/GoalBinding.cs", "Goal/GoalCard.cs", "Goal/GoalCodec.cs", "Goal/GoalCompiler.cs"],
    ["Goal/GoalCrc.cs", "Goal/GoalDigests.cs", "Goal/GoalDisambiguate.cs", "Goal/GoalDrift.cs"],
    ["Goal/GoalExamples.cs", "Goal/GoalFmt.cs"],
    ["Goal/GoalInterpret.cs", "Goal/GoalLegacy.cs"],
    ["Goal/GoalNVersion.cs", "Goal/GoalNormalize.cs", "Goal/GoalOntologies.cs"],
    ["Goal/GoalOntology.cs"],
    ["Goal/GoalPrecedent.cs", "Goal/GoalRefsem.cs"],
    ["Goal/GoalReview.cs", "Goal/GoalRoundTrip.cs"],
    ["Goal/GoalSelectors.cs", "Goal/GoalSign.cs"],
    ["GoalKernel/GoalKernel.cs", "Grants/BlueprintOps.cs", "Grants/Bundle.cs", "Grants/FreshAtOps.cs", "Grants/GrantClient.cs"],
    ["Grants/GrantHttp.cs", "Grants/GrantService.cs", "Grants/GrantSigning.cs", "Grants/GrantsUtil.cs", "Grants/LeaseOps.cs"],
    ["Grants/LeaseStoreConformance.cs", "Grants/ListAuthorized.cs", "Grants/Shadow.cs", "Grants/Sig.cs"],
    ["Harness/PcaHarness.cs", "IdJag/IdJag.cs"],
    ["Intent/IntentClassifierKit.cs", "Intent/IntentCompilers.cs"],
    ["Intent/IntentDerive.cs", "Intent/IntentEffects.cs", "Intent/IntentFrames.cs"],
    ["Intent/IntentJit.cs", "Intent/IntentLayers.cs"],
    ["Intent/IntentLearner.cs#1/2"],
    ["Intent/IntentLearner.cs#2/2"],
    ["Intent/IntentMapKit.cs"],
    ["Intent/IntentMath.cs", "Intent/IntentMultiAgg.cs"],
    ["Intent/IntentOmega.cs", "Intent/IntentOutcome.cs", "Intent/IntentPolicyKit.cs"],
    ["Intent/IntentProfile.cs", "Intent/IntentProvenance.cs", "Intent/IntentRamp.cs"],
    ["Intent/IntentRefine.cs", "Intent/IntentRegion.cs"],
    ["Intent/IntentRender.cs"],
    ["Intent/IntentRuntime.cs", "Intent/IntentSchema.cs"],
    ["Intent/IntentStatement.cs", "Intent/IntentStats.cs", "Intent/IntentTrajectory.cs", "Intent/IntentUx.cs"],
    ["Intent/IntentWitnesses.cs", "Intent/IntentWorld.cs", "InteropJs/JsX.cs", "Invariants/PcaInvariants.cs", "Invariants/InvariantsRng.cs", "Invariants/InvariantArbitraries.cs", "Invariants/InvariantProperties.cs"],
    ["Jose/Jose.cs", "Jose/JoseCanonicalExtras.cs"],
    ["Jose/JoseKeys.cs", "Jose/WhatwgUrl.cs"],
    ["Js/JsJson.cs", "Mcp/Mcp.cs", "Mcp/PcaFetch.cs"],
    ["Mcp/McpDraft.cs", "Native/Sodium.cs"],
    ["Notary/PcaNotary.cs", "Oauth/Oauth.cs"],
    ["Oauth/WhatwgUrl.cs", "Oidc/Oidc.cs"],
    ["Oprf/Oprf.cs", "Oprf/OprfPca.cs", "Oprf/Ristretto255.cs", "Otel/OtelGuard.cs"],
    ["Payments/NetworkToken.cs", "Payments/NetworkTokenProviders.cs", "Payments/Payments.cs", "Payments/PaymentsAtomic.cs", "Payments/PaymentsJs.cs"],
    ["Payments/RailAuthorizer.cs", "Payments/Rails.cs", "PolicyBridgeKit/Cedar.cs"],
    ["PolicyBridgeKit/Cel.cs"],
    ["PolicyBridgeKit/OpenFga.cs", "PolicyBridgeKit/PbJs.cs", "PolicyBridgeKit/PolicyBridge.cs", "PolicyBridgeKit/Rego.cs"],
    ["PolicyCi/ActionLintRules.cs", "PolicyCi/CiAuthoring.cs", "PolicyCi/CiCli.cs", "PolicyCi/CiJs.cs", "PolicyCi/CiNormalize.cs"],
    ["PolicyCi/CiRules.cs", "PolicyCi/PcaPolicyCi.cs", "PqThreshold/HybridThreshold.cs"],
    ["KvStateStore.cs", "PcaConstants.cs", "PcaServer.cs", "PcaCore.cs", "PqSuites.cs", "PqThreshold/PqThreshold.cs", "PqThreshold/LatticeThresholdExperimental.cs", "Rag/RagFilter.cs", "Ratchet/CapabilityRatchet.cs", "Ratchet/EdwardsPoint.cs"],
    ["Ratchet/Ggm.cs", "Ratchet/RatchetAdapters.cs", "Ratchet/RatchetBinding.cs", "Ratchet/RatchetGroup.cs", "Ratchet/RiskAccumulator.cs"],
    ["Ratchet/Ristretto255.cs", "Research/Dlp.cs", "Research/Immune.cs", "Revoke/FileRevocationStore.cs"],
    ["Revoke/Revoke.cs", "Revoke/RevocationConformance.cs", "Rotate/Rotate.cs"],
    ["Sandbox/PcaSandbox.cs"],
    ["Sandbox/SandboxEgress.cs", "Sandbox/SandboxHandles.cs", "Sandbox/SandboxUrl.cs", "Sandbox/SandboxEgressProxy.cs"],
    ["Schema/PcaSchema.cs"],
    ["Scim/Scim.cs"],
    ["Scitt/Cbor.cs", "Scitt/Durable.cs", "Scitt/FileLogStore.cs", "Scitt/MemoryLog.cs"],
    ["Scitt/Rfc9162.cs", "Scitt/Scitt.cs"],
    ["Sdjwt/Sdjwt.cs"],
    ["Siem/SiemExport.cs"],
    ["Signals/Signals.cs"],
    ["Signals/SsfManage.cs", "Signals/SsfStream.cs"],
    ["Spiffe/SpiffeBridge.cs"],
    ["Spiffe/SpiffeDer.cs", "StoreConformanceBond.cs"],
    ["StoreConformanceBudget.cs"],
    ["StoreConformanceLedger.cs", "StoreConformanceMeshWitness.cs"],
    ["StoreConformancePcaState.cs", "StoreConformancePkg/StoreCheck.cs", "StoreConformancePkg/StoreInventories.cs"],
    ["StoreConformancePkg/StoreModel.cs", "StoreConformancePkg/StoreRecorder.cs", "StoreConformancePkg/StoreReport.cs", "StoreConformanceSuite.cs"],
    ["Testing/PcaTesting.cs", "TxnTokens/TxnTokens.cs"],
    ["Vc/Vc.cs", "Vdf/Timelock.cs"],
    ["Vdf/Vdf.cs"],
    ["Wallet/TrustedChannel.cs"],
    ["Wallet/WalletCard.cs"],
    ["Wallet/WalletCore.cs"],
    ["Wallet/WalletDelivery.cs", "Wallet/WalletPopulation.cs", "Wallet/WalletPricing.cs", "WebBotAuth/ContentDigest.cs", "WebBotAuth/DirectoryFetch.cs"],
    ["WebBotAuth/SignedDirectory.cs", "WebBotAuth/WbaJs.cs"],
    ["WebBotAuth/WebBotAuth.cs"],
    ["Webauthn/Webauthn.cs"],
    ["AgentNative.cs"],
    ["SiblingPortsSmall.cs", "Connect/ConnectStoreOps.cs", "Ap2/Ap2KeyGen.cs"],
    ["Ext/BondSettlement.cs", "Ext/BondSettlementPlanner.cs", "Ext/StoreBondLedger.cs", "Ext/OptimisticAdjudication.cs"],
    ["PackageConstants.cs", "RegexBudget.cs", "Ext/LedgerIssue.cs"],
    ["Ext/Kem.cs"],
    ["Ext/Entropy.cs"],
    # the opt-in Groth16 module (own Stryker project, oracle AtlasPca.Zk.Tests over libpcazk): a module shard, named by number in the workflow's module-shard matrix
    ["../AtlasPca.Zk/ZkNative.cs", "../AtlasPca.Zk/NativeResolver.cs"],
    ["Ext/ZkCeremony.cs"],
    ["Ext/FdLibmPow.cs"],
    ["StoreConformancePkg/StoreCli.cs"],
    ["Ext/ZkCompliance.cs"],
    ["Ext/ZkPolicyVm.cs"],
    ["CatalogSpecs.cs"],
    ["Ext/MeshIssuing.cs"],
    ["Ext/PqQuorum.cs"],
    ["Ext/SafetyCertificate.cs"],
    ["Ext/Reputation.cs"],
    ["Ext/BudgetForecast.cs"],
    ["Research/AgentConsole.cs", "Research/PolicySim.cs"],
    ["Ext/AttestationSoft.cs"],
    ["Ext/PolicyDebug.cs"],
    ["Ext/SevSnp.cs"],
    ["Ext/AttestPuf.cs"],
    ["Ext/GuardianHa.cs"],
    ["Ext/TaintTree.cs"],
    ["Ext/AttestAllowlist.cs"],
    ["Ext/FrontierSignals.cs"],
    ["Ext/AttestMaaKeys.cs", "Ext/AttestMaaPinsData.cs"],
    ["Ext/AttestPqSoftware.cs"],
    ["Ext/SemanticThreshold.cs"],
    ["Ext/ObjectiveRisk.cs"],
    ["Ext/PassportOps.cs"],
    ["Ext/BeaconOps.cs"],
    ["Ext/ActionSchemaOps.cs", "Mcp/McpDraftOpenApi.cs"],
    ["Ext/ActionPinOps.cs"],
    ["Ext/Progress.cs"],
    ["Ext/NlApproval.cs"],
    ["Ext/WhatwgUrl.cs"],
    ["Ext/IntentMisc2.cs"],
    ["Ext/FrostNet.cs", "Ext/FrostNonceStore.cs", "Ext/FrostPq.cs"],
    ["Ext/FrostDkg.cs", "Ext/FrostDkgChannel.cs"],
    ["Attest/AttestNvidiaApi.cs"],
    ["VerifyPcactn.cs"],
    ["Ext/FrostNetHttp.cs"],
    ["Ext/FrostDkgTls.cs"],
]

def opt(name):
    if name in sys.argv:
        return sys.argv[sys.argv.index(name) + 1]
    return None

k, n, d = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3]
scope_out, baseline_in, carry_out = opt("--scope"), opt("--baseline"), opt("--carry")
if "--gen-plan" not in sys.argv and (not scope_out or bool(baseline_in) != bool(carry_out)):
    sys.exit("usage: stryker-spans.py <k> <n> <AtlasPca dir> --scope <json> [--baseline <json> --carry <json>]")
# every .cs file of the verifier (subdirectories included: Ext/, Attest/) and of the ASP.NET Core middleware project, as paths
# relative to AtlasPca/ (the middleware's start with ../AtlasPca.AspNetCore/)
# Blst/ is the upstream blst C# binding that Pairing/Native/build.sh copies in on the runner (third-party, never shipped from here)
# GoalKernel/Generated/ is the Dafny translation of the proved goal kernel plus the Dafny runtime (generated code, not ours; reason in
# sdks/dotnet-pca/mutation-excluded.json): never mutated. The hand-written GoalKernel/GoalKernel.cs bridge stays in the plan.
SKIP = {"bin", "obj", "StrykerOutput", ".mutwork", "Blst", "Generated"}
MODULES = ("AtlasPca.AspNetCore", "AtlasPca.Pairing", "AtlasPca.Fhe", "AtlasPca.MpcLweOt", "AtlasPca.Fndsa", "AtlasPca.Zk")
files = sorted(os.path.relpath(os.path.join(r, f), d) for top in (d, *(os.path.join(d, "..", m) for m in MODULES))
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
key = lambda f: os.path.normpath("AtlasPca/" + f)  # scope / ledger path: AtlasPca/Ext/Mesh.cs, AtlasPca.AspNetCore/PcaMiddleware.cs
parts = collections.defaultdict(list)  # file -> [(i, n)] of its plan entries
for it in (x for sh in PLAN for x in sh):
    f, _, sp = it.partition("#")
    parts[f].append(tuple(map(int, sp.split("/"))) if sp else (1, 1))
if sorted(parts) != files:
    sys.exit(f"AtlasPca/ has {files}, the plan covers {sorted(parts)}: append the output of `stryker-spans.py 0 0 <dir> --gen-plan` to PLAN in stryker-spans.py")
for f, ps in parts.items():
    if sorted(ps) != [(i, ps[0][1]) for i in range(1, ps[0][1] + 1)]:
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
    open(os.path.join(d, f), "w", encoding="utf-8").write("\n".join(out))

for f in files:
    if any(l.strip().startswith("// Stryker") for l in read(f)):
        sys.exit(f"{f} already has Stryker directives")

def span(f, i, n):
    """Lines [a, b] of span i of n of f: n near-equal parts cut only at member declarations (indent 0 or 4)."""
    lines = read(f)
    if n == 1:
        return [1, len(lines)]
    starts = [t for t, _, ms in units(lines) for t in [t] + [a for a, _ in ms]]
    cuts = []
    for j in range(1, n):
        target = j * len(lines) / n
        cuts.append(min((x for x in starts if x > (cuts[-1] if cuts else 1)), key=lambda x: abs(x - target)))
    bounds = [1] + cuts + [len(lines) + 1]
    return [bounds[i - 1], bounds[i] - 1]

# the shard's scope (original-file lines); one Stryker project per shard
if len({key(it.partition("#")[0]).split("/")[0] for it in PLAN[k - 1]}) != 1:
    sys.exit(f"shard {k} mixes projects: {PLAN[k - 1]}")
scope = {}
for it in PLAN[k - 1]:
    f, _, sp = it.partition("#")
    scope[key(f)] = span(f, *map(int, sp.split("/"))) if sp else [1, len(read(f))]
json.dump(scope, open(scope_out, "w"))

base = json.load(open(baseline_in)) if baseline_in else None
carried, globs = [], []
for rel, (a, b) in scope.items():
    f = os.path.relpath(rel, "AtlasPca")
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
if carry_out:
    json.dump(carried, open(carry_out, "w"))
    print(f"targeted: {len(carried)} baseline mutant(s) carried forward", file=sys.stderr)
for f in globs:
    print(f"**/{key(f)}")
