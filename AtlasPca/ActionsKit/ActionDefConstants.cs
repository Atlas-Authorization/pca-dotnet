// The action-definition schema constants (packages/pca-actions def.ts): the definition version, the parameter types and sensitivity levels a definition may use, and
// the taint-context rule.
using System.Text.RegularExpressions;

namespace AtlasPca.ActionsKit;

public static class ActionDefConstants
{
    /// <summary>The definition schema version.</summary>
    public const int ActionDefVersion = 1;

    /// <summary>The parameter types of a version 1 definition.</summary>
    public static readonly IReadOnlyList<string> ParamTypesV1 = new[] { "string", "integer", "boolean", "date", "datetime", "duration", "set", "array", "object_ref" };

    /// <summary>The parameter sensitivity levels, least to most sensitive.</summary>
    public static readonly IReadOnlyList<string> SensitivityLevels = new[] { "free", "material", "critical" };

    /// <summary>A taint-context rule: <c>session_taint_max:</c> and a name of 1 to 16 lowercase letters or underscores.</summary>
    public static Regex TaintContextRe => Rx.Get(@"^session_taint_max:[a-z_]{1,16}\z", RegexOptions.CultureInvariant);
}
