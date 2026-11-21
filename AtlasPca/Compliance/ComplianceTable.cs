using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Compliance;

/// <summary>The control-mapping table: EU AI Act Art. 12 / 50, ISO/IEC 42001 clauses and SOC 2 CC6, each tied to the evidence fields that satisfy it.</summary>
public static partial class PcaCompliance
{
    static D Map(string framework, string id, string title, string clause, string requirement, string pcaEvidence, params string[] fields) => new()
    {
        ["framework"] = framework,
        ["controlId"] = id,
        ["controlTitle"] = title,
        ["clause"] = clause,
        ["requirement"] = requirement,
        ["pcaEvidence"] = pcaEvidence,
        ["evidenceFields"] = fields.Cast<object?>().ToList(),
    };

    /// <summary>A fresh copy of the whole table.</summary>
    static List<D> Table() => new()
    {
            Map("eu-ai-act",
                "eu-ai-act:art-12",
                "Record-keeping — automatic, traceable logging of events",
                "EU AI Act, Article 12",
                "High-risk AI systems must automatically record events (\"logs\") over their lifetime, enabling traceability of the system's functioning.",
                "Every action is a signed PCActn; each log entry CITES its proof (the PCActn digest + the verifying leaf signature), so the record is tamper-evident and cannot be back-dated or fabricated.",
                "evidence.pcactnDigest", "evidence.leafSignature", "evidence.cryptographicallyVerifiable", "timestamps.issuedAt"),
            Map("eu-ai-act",
                "eu-ai-act:art-50",
                "Transparency — disclosure of automated decisions and the acting agent",
                "EU AI Act, Article 50",
                "Providers/deployers must ensure natural persons are informed that they are interacting with / affected by an AI system; interactions and automated decisions must be disclosed.",
                "Each entry discloses the acting AGENT identity (leaf holder), the PRINCIPAL it acts for (root issuer), the exact action, and the automated decision outcome + reason — a complete, attributable disclosure per action.",
                "agent.holder", "agent.principal", "action.summary", "decision.outcome", "decision.reason"),
            Map("iso-42001",
                "iso-42001:A.6.2.8",
                "Reasoning trace — AI system event logging",
                "ISO/IEC 42001 Annex A.6.2.8 (AI system event logs / recording)",
                "The organization shall record events produced by the AI system so that its decisions can be examined and explained after the fact.",
                "Each entry carries the Policy-VM decision with its decisive reason, the risk score r, the required tier and the trust-budget state — a complete, machine-checked reasoning trace, not a free-text note.",
                "decision.reason", "risk.r", "risk.tier", "risk.budget", "decision.checks"),
            Map("iso-42001",
                "iso-42001:A.9.2",
                "Delegation & authorization chain",
                "ISO/IEC 42001 Annex A.9.2 (authorization / responsible use of AI systems)",
                "Use of the AI system must be authorized; the authority under which an automated action is taken must be identifiable and bounded.",
                "The delegation chain is EXPLICIT: each hop records issuer → holder and the scope (caveats) it narrowed, rooted at the principal — authority is attenuated and provable, never ambient.",
                "delegation.hops", "delegation.depth", "agent.principal", "delegation.hops[].scope"),
            Map("iso-42001",
                "iso-42001:A.9.3",
                "Human oversight of AI systems",
                "ISO/IEC 42001 Annex A.9.3 (human oversight)",
                "Mechanisms for human oversight of the AI system must exist and be exercised for higher-impact decisions.",
                "Human oversight is a SIGNED CO-SIGNATURE: a step-up is approved by a principal threshold share naming the human approver (cryptographic, not a free-text \"approved by\"); denials and step-up requirements show the oversight boundary being enforced.",
                "humanOverride.humanApproved", "humanOverride.approvers", "decision.outcome", "risk.tier"),
            Map("iso-42001",
                "iso-42001:A.6.2.2",
                "Intended use — action bound to a committed plan",
                "ISO/IEC 42001 Annex A.6.2.2 (AI system requirements / intended purpose)",
                "The AI system must operate within its intended purpose; actions outside the specified scope must be prevented.",
                "Every action proves inclusion in a committed plan (the signed plan root): an off-plan action fails verification. The plan root in each entry binds the action to its intended, pre-committed purpose.",
                "evidence.planRoot", "action.verb", "action.resource", "decision.checks"),
            Map("soc2",
                "soc2:CC6.1",
                "Logical access security — least privilege",
                "SOC 2 CC6.1",
                "The entity implements logical access controls to protect against unauthorized access, enforcing least privilege.",
                "Access is deny-by-default: actions are constrained by signed predicates and capability attenuation. Denied entries evidence the control actively refusing out-of-scope access.",
                "decision.outcome", "delegation.hops[].scope", "decision.checks", "evidence.cryptographicallyVerifiable"),
            Map("soc2",
                "soc2:CC6.2",
                "Registration & authorization of credentials / identities",
                "SOC 2 CC6.2",
                "Prior to issuing access, the entity registers and authorizes new identities; access is traceable to an authorizing principal.",
                "Each agent identity (leaf holder) is bound into a delegation chain rooted at an authorizing principal, with every hop signed — access is always traceable to who authorized it.",
                "agent.principal", "agent.holder", "delegation.hops", "evidence.grantRef"),
            Map("soc2",
                "soc2:CC6.3",
                "Access modification & removal (attenuation / revocation)",
                "SOC 2 CC6.3",
                "The entity modifies and removes access based on roles/need; access rights are narrowed or withdrawn appropriately.",
                "Delegation is append-only attenuation: a child hop can only narrow scope, never widen it. Narrowing caveats per hop (and denied actions) evidence access being bounded and withdrawn.",
                "delegation.hops[].scope", "delegation.hops[].budgetAlloc", "decision.outcome"),
    };
}
