using AtlasPca.GoalPkg;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Behaviour tests of the intent ontology well-formedness checker: every defect code with its exact where and message.</summary>
public class GoalOntologyKillCheckTests
{
    const string W = "template:t.g";
    static string Q(string s) => s.Replace('\'', '"');
    static object? Val(string json) => Pca.ParseJson(Q(json));
    static D Obj(string json) => (D)Val(json)!;
    static D Dd(object? o) => (D)o!;
    static L Ll(object? o) => (L)o!;
    static D Tp(D o) => Dd(Ll(o["templates"])[0]);

    const string PRMS = "{'amt':{'kind':'money','ccys':['USD']},'n':{'kind':'count'},'e':{'kind':'enum','values':['x','y']},'i':{'kind':'id','of':'doc'},'tx':{'kind':'text'}}";
    const string SLOT_E = "{'name':'s','kind':'enum','values':['x','y'],'mandatory':true}";
    const string BOUNDS = "[{'bid':'b','agg':'count','over':'all','cap':{'u':{'k':'count'},'n':1},'onExceed':'deny'}]";
    const string TRUE = "{'k':'true'}";
    const string EXACT = "{'k':'exact','id':'d_1'}";

    // a one-template ontology whose single grant 'g' carries the cond and resource under test; the example is empty, so the
    // mandatory slot is a hole and the example instantiation never reaches the allow-witness search
    static D Mini(string slot = SLOT_E, string cond = TRUE, string res = EXACT, string bounds = BOUNDS, string example = "{}", string prms = PRMS) =>
        Obj("{'id':'m','version':1,'domain':'m','types':[{'id':'doc','id_prefix':'d_'},{'id':'owner','id_prefix':'o_'}],"
            + "'units':{'USD':{'kind':'money','exponent':2},'EUR':{'kind':'money','exponent':2},'count':{'kind':'count'}},"
            + "'relations':[{'id':'owns','from':'owner','to':'doc'}],"
            + "'verbs':[{'id':'act','effect':'reversible','resource_type':'doc','params':" + prms + "}],'aliases':{},"
            + "'templates':[{'id':'t','title':'t','phrases':[],'slots':[" + slot + "],"
            + "'grants':[{'gid':'g','verb':'act','res':" + res + ",'cond':" + cond + "}],'prohibits':[],'bounds':" + bounds + ",'example':" + example + "}]}");

    static List<string> Iss(D o) => GoalOntology.CheckOntology(o).Select(x =>
    {
        D m = Dd(x);
        return (string)m["code"]! + "|" + (m.TryGetValue("where", out var w) ? G.jsStr(w) : "~") + "|" + (string)m["msg"]!;
    }).ToList();

    static void Has(D o, string expected)
    {
        List<string> l = Iss(o);
        Assert.True(l.Contains(expected), "missing: " + expected + "\nissues: " + string.Join("\n  ", l));
    }

    static void NoCode(D o, params string[] codes)
    {
        List<string> l = Iss(o).Where(x => codes.Any(c => x.StartsWith(c + "|", StringComparison.Ordinal))).ToList();
        Assert.True(l.Count == 0, "unexpected: " + string.Join("\n  ", l));
    }

    static string E(string code, string msg, string where = W) => code + "|" + where + "|" + msg;

    // ---------------- units, aliases ----------------

    [Fact]
    public void MoneyUnitExponentIsAnIntegerFromZeroToFour()
    {
        foreach (long ok in new long[] { 0, 1, 4 })
        {
            D o = Mini();
            Dd(Dd(o["units"])["USD"])["exponent"] = G.num(ok);
            NoCode(o, "unit_exponent");
        }
        foreach (string bad in new[] { "5", "-1", "2.5" })
        {
            D o = Mini();
            Dd(Dd(o["units"])["USD"])["exponent"] = new Num(bad);
            Has(o, E("unit_exponent", "money unit needs an integer exponent 0..4", "USD"));
        }
        D s = Mini();
        Dd(Dd(s["units"])["USD"])["exponent"] = "2";
        Has(s, E("unit_exponent", "money unit needs an integer exponent 0..4", "USD"));
        D c = Mini();
        Dd(Dd(c["units"])["count"])["exponent"] = G.num(2);
        Has(c, E("unit_exponent", "only money units carry an exponent", "count"));
    }

    [Fact]
    public void AliasKeysMustBeNormalizedButMayHoldNormalizedNonAscii()
    {
        D ok = Mini();
        Dd(ok["aliases"])["é"] = "act";
        NoCode(ok, "alias_key");
        D up = Mini();
        Dd(up["aliases"])["Act"] = "act";
        Has(up, "alias_key|Act|alias key is not in normalized form");
    }

    // ---------------- slots ----------------

    [Fact]
    public void IdSlotsNeedADeclaredType()
    {
        D bad = Mini("{'name':'s','kind':'id','of':'zzz','mandatory':true}");
        Has(bad, "slot_type|template:t.s|id slot type is not declared");
        D lst = Mini("{'name':'s','kind':'id_list','mandatory':true}");
        Has(lst, "slot_type|template:t.s|id slot type is not declared");
        NoCode(Mini("{'name':'s','kind':'id','of':'doc','mandatory':true}"), "slot_type");
        NoCode(Mini("{'name':'s','kind':'id_list','of':'doc','mandatory':true}"), "slot_type");
    }

    [Fact]
    public void MoneySlotsNeedADeclaredMoneyUnit()
    {
        Has(Mini("{'name':'s','kind':'money','ccy':'XXX','mandatory':true}"), "slot_ccy|template:t.s|money slot currency is not a declared unit");
        Has(Mini("{'name':'s','kind':'money','ccy':'count','mandatory':true}"), "slot_ccy|template:t.s|money slot currency is not a declared unit");
        NoCode(Mini("{'name':'s','kind':'money','ccy':'USD','mandatory':true}"), "slot_ccy");
        Has(Mini("{'name':'s','kind':'money','mandatory':true}"), "slot_ccy|template:t.s|money slot currency is not a declared unit");
    }

    [Fact]
    public void AMoneySlotWithoutACurrencyLooksUpTheEmptyUnit()
    {
        foreach (string slot in new[] { "{'name':'s','kind':'money','mandatory':true}", "{'name':'s','kind':'money','ccy':5,'mandatory':true}" })
        {
            D o = Mini(slot);
            Dd(o["units"])[""] = Val("{'kind':'money','exponent':2}");
            NoCode(o, "slot_ccy");
        }
    }

    [Fact]
    public void ACondOnAMoneySlotWithoutACurrencyChecksTheEmptyCurrency()
    {
        const string prms = "{'amt':{'kind':'money','ccys':['','USD']}}";
        string cond = "{'k':'cmp','op':'lte','l':{'k':'param','path':'amt'},'r':{'k':'slot','slot':'s'}}";
        D o = Mini("{'name':'s','kind':'money','mandatory':true}", cond, prms: prms);
        Dd(o["units"])[""] = Val("{'kind':'money','exponent':2}");
        NoCode(o, "cond_unit", "slot_ccy", "unit_unknown");
        Has(Mini("{'name':'s','kind':'money','mandatory':true}", cond), E("cond_unit", "slot currency is not accepted by the parameter"));
    }

    [Fact]
    public void EnumSlotsNeedValues()
    {
        Has(Mini("{'name':'s','kind':'enum','values':[],'mandatory':true}"), "slot_enum|template:t.s|enum slot has no values");
        Has(Mini("{'name':'s','kind':'enum_list','mandatory':true}"), "slot_enum|template:t.s|enum slot has no values");
        NoCode(Mini("{'name':'s','kind':'enum_list','values':['a'],'mandatory':true}"), "slot_enum");
    }

    [Fact]
    public void DuplicateGrantIdsAreRefused()
    {
        D o = Mini();
        NoCode(o, "dup_gid");
        Ll(Tp(o)["grants"]).Add(Obj("{'gid':'g','verb':'act','res':{'k':'exact','id':'d_1'},'cond':{'k':'true'}}"));
        Has(o, "dup_gid|template:t|duplicate grant id");
    }

    // ---------------- grants: wildcard and related sets ----------------

    [Fact]
    public void WildcardResourcesNeedAReadVerbAndABound()
    {
        const string any = "{'k':'any','reason':'x'}";
        string msg = "wildcard resource in a template";
        Has(Mini(res: any), E("unbounded", msg));
        D readNoBound = Mini(res: any, bounds: "[]");
        Dd(Ll(readNoBound["verbs"])[0])["effect"] = "read";
        Has(readNoBound, E("unbounded", msg));
        D readBound = Mini(res: any);
        Dd(Ll(readBound["verbs"])[0])["effect"] = "read";
        NoCode(readBound, "unbounded");
    }

    [Fact]
    public void NonReadGrantsOnRelatedSetsNeedABound()
    {
        const string rel = "{'k':'related','rel':'owns','anchor':'o_1'}";
        Has(Mini(res: rel, bounds: "[]"), E("unbounded", "non-read grant on a related set needs an aggregate bound"));
        NoCode(Mini(res: rel), "unbounded");
        D read = Mini(res: rel, bounds: "[]");
        Dd(Ll(read["verbs"])[0])["effect"] = "read";
        NoCode(read, "unbounded");
    }

    // ---------------- prohibits ----------------

    [Fact]
    public void ProhibitsNameADeclaredVerbOrEffectClass()
    {
        D v = Mini();
        Tp(v)["prohibits"] = Val("[{'pid':'p1','target':{'k':'verb','verb':'ghost'},'res':{'k':'any','reason':'x'},'cond':{'k':'true'}}]");
        Has(v, "prohibit_verb|template:t.p1|prohibit verb is not in the ontology");
        D e = Mini();
        Tp(e)["prohibits"] = Val("[{'pid':'p1','target':{'k':'effect','cls':'bogus'},'res':{'k':'any','reason':'x'},'cond':{'k':'true'}}]");
        Has(e, "prohibit_effect|template:t.p1|unknown effect class");
        D ok = Mini();
        Tp(ok)["prohibits"] = Val("[{'pid':'p1','target':{'k':'verb','verb':'act'},'res':{'k':'any','reason':'x'},'cond':{'k':'true'}},"
            + "{'pid':'p2','target':{'k':'effect','cls':'read'},'res':{'k':'any','reason':'x'},'cond':{'k':'true'}}]");
        NoCode(ok, "prohibit_verb", "prohibit_effect");
    }

    // ---------------- bounds ----------------

    const string BSLOTS = "{'name':'s','kind':'money','ccy':'USD','mandatory':true},{'name':'c','kind':'count','mandatory':true},{'name':'x','kind':'id','of':'doc','mandatory':true}";

    static string Bd(string bid, string agg, string over, string? capSlot, string? param) =>
        "{'bid':'" + bid + "','agg':'" + agg + "','over':" + over + ",'cap':{'u':{'k':'count'},'n':1},'onExceed':'deny'"
        + (capSlot != null ? ",'cap_slot':'" + capSlot + "'" : "") + (param != null ? ",'param':'" + param + "'" : "") + "}";

    static D Bounded(params string[] bounds) => Mini(BSLOTS, bounds: "[" + string.Join(",", bounds) + "]");

    [Fact]
    public void BoundsSelectDeclaredGrants()
    {
        Has(Bounded(Bd("b1", "count", "['nope']", null, null)), "bound_over|template:t.b1|bound selects an unknown grant");
        Has(Bounded(Bd("b1", "count", "['g','nope']", null, null)), "bound_over|template:t.b1|bound selects an unknown grant");
        NoCode(Bounded(Bd("b1", "count", "['g']", null, null)), "bound_over");
        NoCode(Bounded(Bd("b1", "count", "'all'", null, null)), "bound_over");
    }

    [Fact]
    public void ACapSlotMustBeDeclared()
    {
        D o = Bounded(Bd("b1", "count", "'all'", "ghost", null));
        Has(o, "slot_undeclared|template:t|cap slot ghost is not declared");
        NoCode(o, "bound_cap");
    }

    [Fact]
    public void ACapSlotMustMatchTheAggregate()
    {
        D id = Bounded(Bd("b3", "count", "'all'", "x", null));
        Has(id, "bound_cap|template:t.b3|cap slot must be money or count");
        Has(id, "bound_cap|template:t.b3|count bound needs a count slot");
        Has(Bounded(Bd("b4", "sum", "'all'", "c", "amt")), "bound_cap|template:t.b4|sum bound over money needs a money slot");
        Has(Bounded(Bd("b5", "count", "'all'", "s", null)), "bound_cap|template:t.b5|count bound needs a count slot");
        NoCode(Bounded(Bd("b6", "count", "'all'", "c", null)), "bound_cap");
        NoCode(Bounded(Bd("b7", "sum", "'all'", "s", "amt")), "bound_cap");
        Assert.DoesNotContain("bound_cap|template:t.b3|sum bound over money needs a money slot", Iss(id));
    }

    [Fact]
    public void ASumBoundNeedsAValueParameter()
    {
        Has(Bounded(Bd("b6", "sum", "'all'", "s", null)), "bound_value|template:t.b6|sum bound has no value parameter");
        NoCode(Bounded(Bd("b6", "sum", "'all'", "s", "amt")), "bound_value");
        NoCode(Bounded(Bd("b6", "count", "'all'", "c", null)), "bound_value");
    }

    [Fact]
    public void ASurvivingSumBoundWithoutAParameterCannotBeInstantiated()
    {
        const string slots = "{'name':'s','kind':'money','ccy':'USD','mandatory':true},{'name':'u','kind':'id','of':'doc','mandatory':true}";
        D o = Mini(slots, bounds: "[" + Bd("b", "sum", "'all'", "s", null) + "]", example: "{'s':{'ccy':'USD','minor':5}}");
        var e = Assert.Throws<IrError>(() => GoalOntology.CheckOntology(o));
        Assert.Equal("pca-goal: parameter undefined is not declared by any verb", e.Message);
    }

    // ---------------- the example instantiation ----------------

    [Fact]
    public void AnExampleThatLeavesHolesNamesThemSorted()
    {
        Has(Mini(), "example_holes|template:t|example leaves holes: s");
        const string two = "{'name':'u','kind':'enum','values':['x'],'mandatory':true}," + SLOT_E;
        Has(Mini(two), "example_holes|template:t|example leaves holes: s,u");
    }

    // ---------------- resources ----------------

    [Fact]
    public void ExactResourcesCarryTheTypePrefix()
    {
        Has(Mini(res: "{'k':'exact','id':'x_1'}"), E("resource_type", "exact resource id has the wrong type prefix"));
        NoCode(Mini(res: "{'k':'exact','id':'d_1'}"), "resource_type");
        NoCode(Mini("{'name':'s','kind':'id','of':'doc','mandatory':true}", res: "{'k':'exact','id':'$s'}"), "resource_type");
        D ghost = Mini(res: "{'k':'exact','id':'d_9'}");
        Dd(Ll(ghost["verbs"])[0])["resource_type"] = "ghost";
        Has(ghost, E("resource_type", "exact resource id has the wrong type prefix"));
    }

    [Fact]
    public void OneOfResourcesCarryTheTypePrefixAndAreNotEmpty()
    {
        D o = Mini(res: "{'k':'oneof','ids':['d_1','x_2']}");
        Has(o, E("resource_type", "one_of member has the wrong type prefix"));
        Assert.Equal(1, Iss(o).Count(x => x == E("resource_type", "one_of member has the wrong type prefix")));
        NoCode(Mini(res: "{'k':'oneof','ids':['d_1','d_2']}"), "resource_type", "resource_empty");
        Has(Mini(res: "{'k':'oneof','ids':[]}"), E("resource_empty", "one_of is empty"));
    }

    [Fact]
    public void RelatedResourcesNeedAKnownRelationOfTheVerbTypeAndAnAnchorPrefix()
    {
        NoCode(Mini(res: "{'k':'related','rel':'owns','anchor':'o_1'}"), "resource_type", "relation_unknown", "relation_type");
        Has(Mini(res: "{'k':'related','rel':'owns','anchor':'x_1'}"), E("resource_type", "relation anchor has the wrong type prefix"));
        Has(Mini(res: "{'k':'related','rel':'nope','anchor':'o_1'}"), E("relation_unknown", "relation nope is not declared"));
        D o = Mini(res: "{'k':'related','rel':'owns','anchor':'o_1'}");
        Dd(Ll(o["relations"])[0])["to"] = "owner";
        Has(o, E("relation_type", "relation target type differs from the verb resource type"));
    }

    [Fact]
    public void AllOfResourcesNeedTwoPartsAndCheckEachPart()
    {
        Has(Mini(res: "{'k':'all_of','parts':[{'k':'exact','id':'d_1'}]}"), E("all_of_arity", "all_of needs at least two parts"));
        NoCode(Mini(res: "{'k':'all_of','parts':[{'k':'exact','id':'d_1'},{'k':'exact','id':'d_2'}]}"), "all_of_arity", "resource_type");
        Has(Mini(res: "{'k':'all_of','parts':[{'k':'exact','id':'d_1'},{'k':'exact','id':'x_2'}]}"), E("resource_type", "exact resource id has the wrong type prefix"));
    }

    // ---------------- conditions ----------------

    static string Sl(string kind, string extra = "") => "{'name':'s','kind':'" + kind + "'," + extra + "'mandatory':true}";
    static string SlotOf(string kind) => kind switch
    {
        "enum" or "enum_list" => Sl(kind, "'values':['x','y'],"),
        "id" or "id_list" => Sl(kind, "'of':'doc',"),
        "money" => Sl(kind, "'ccy':'USD',"),
        "money EUR" => Sl("money", "'ccy':'EUR',"),
        "money none" => Sl("money"),
        _ => Sl(kind),
    };
    static string CmpC(string path, string op, string r) => "{'k':'cmp','op':'" + op + "','l':{'k':'param','path':'" + path + "'},'r':" + r + "}";
    const string SLOT_S = "{'k':'slot','slot':'s'}";
    static string LitS(string s) => "{'k':'lit','v':{'k':'s','s':'" + s + "'}}";
    static string LitQ(string unit) => "{'k':'lit','v':{'k':'q','q':{'u':" + unit + ",'n':1}}}";
    const string U_COUNT = "{'k':'count'}";
    const string U_USD = "{'k':'money','ccy':'USD'}";
    static string Set(string items) => "{'k':'lit','v':{'k':'set','items':[" + items + "]}}";
    static string S1(string s) => "{'k':'s','s':'" + s + "'}";
    const string CONDS = "cond_type|cond_unit|cond_enum|cond_order|cond_param|cond_term";
    static void NoCond(D o) => NoCode(o, CONDS.Split('|'));

    [Theory]
    [InlineData("e", "enum", "eq")]
    [InlineData("e", "enum_list", "in")]
    [InlineData("e", "enum_list", "nin")]
    [InlineData("i", "id", "eq")]
    [InlineData("i", "id_list", "in")]
    [InlineData("i", "id_list", "nin")]
    [InlineData("tx", "text", "eq")]
    [InlineData("tx", "text_list", "in")]
    [InlineData("amt", "money", "lte")]
    [InlineData("n", "count", "lte")]
    public void CompatibleSlotsAreAccepted(string param, string slot, string op) =>
        NoCond(Mini(SlotOf(slot), CmpC(param, op, SLOT_S)));

    [Theory]
    [InlineData("e", "count", "eq", "count", "enum")]
    [InlineData("e", "id", "eq", "id", "enum")]
    [InlineData("e", "id_list", "in", "id_list", "enum")]
    [InlineData("e", "text", "eq", "text", "enum")]
    [InlineData("i", "enum", "eq", "enum", "id")]
    [InlineData("i", "enum_list", "in", "enum_list", "id")]
    [InlineData("tx", "count", "eq", "count", "text")]
    [InlineData("n", "text_list", "in", "text_list", "count")]
    [InlineData("n", "money", "lte", "money", "count")]
    [InlineData("amt", "count", "lte", "count", "money")]
    public void IncompatibleSlotsAreRefused(string param, string slot, string op, string slotKind, string paramKind) =>
        Has(Mini(SlotOf(slot), CmpC(param, op, SLOT_S)),
            E("cond_type", "slot s (" + slotKind + ") does not type-check against parameter kind " + paramKind));

    [Theory]
    [InlineData("e", "enum", "in")]
    [InlineData("e", "enum_list", "eq")]
    [InlineData("i", "id", "nin")]
    [InlineData("i", "id_list", "eq")]
    [InlineData("tx", "text_list", "eq")]
    [InlineData("tx", "text", "in")]
    [InlineData("n", "count", "nin")]
    public void ListSlotsPairWithInAndNin(string param, string slot, string op) =>
        Has(Mini(SlotOf(slot), CmpC(param, op, SLOT_S)), E("cond_type", "list slots pair with in/nin and scalar slots with the other operators"));

    [Fact]
    public void AMoneySlotCurrencyMustBeAcceptedByTheParameter()
    {
        string cond = CmpC("amt", "lte", SLOT_S);
        Has(Mini(SlotOf("money EUR"), cond), E("cond_unit", "slot currency is not accepted by the parameter"));
        Has(Mini(SlotOf("money none"), cond), E("cond_unit", "slot currency is not accepted by the parameter"));
        NoCode(Mini(SlotOf("money"), cond), "cond_unit");
    }

    [Fact]
    public void AnUndeclaredSlotIsLeftToTheSlotChecks()
    {
        D o = Mini(SLOT_E, CmpC("e", "eq", "{'k':'slot','slot':'ghost'}"));
        NoCond(o);
        Has(o, "slot_undeclared|template:t|slot ghost is used but not declared");
    }

    [Fact]
    public void QuantityLiteralsMatchTheParameterKindAndCurrency()
    {
        NoCond(Mini(cond: CmpC("n", "eq", LitQ(U_COUNT))));
        NoCond(Mini(cond: CmpC("amt", "lte", LitQ(U_USD))));
        Has(Mini(cond: CmpC("amt", "lte", LitQ("{'k':'money','ccy':'EUR'}"))), E("cond_unit", "literal currency is not accepted by the parameter"));
        NoCode(Mini(cond: CmpC("amt", "lte", LitQ("{'k':'money','ccy':'EUR'}"))), "cond_type");
        D o = Mini(cond: CmpC("n", "lte", LitQ(U_USD)));
        Has(o, E("cond_type", "literal kind differs from the parameter kind"));
        Has(o, E("cond_unit", "literal currency is not accepted by the parameter"));
    }

    [Fact]
    public void TextLiteralsNeedATextualParameterAndEnumLiteralsAMember()
    {
        NoCond(Mini(cond: CmpC("e", "eq", LitS("x"))));
        NoCond(Mini(cond: CmpC("i", "eq", LitS("d_1"))));
        NoCond(Mini(cond: CmpC("tx", "eq", LitS("anything"))));
        Has(Mini(cond: CmpC("n", "eq", LitS("x"))), E("cond_type", "literal kind differs from the parameter kind"));
        Has(Mini(cond: CmpC("amt", "eq", LitS("x"))), E("cond_type", "literal kind differs from the parameter kind"));
        Has(Mini(cond: CmpC("e", "eq", LitS("z"))), E("cond_enum", "enum literal is not a member"));
    }

    [Fact]
    public void LiteralSetsPairWithInAndNin()
    {
        NoCond(Mini(cond: CmpC("e", "in", Set(S1("x") + "," + S1("y")))));
        NoCond(Mini(cond: CmpC("e", "nin", Set(S1("x")))));
        Has(Mini(cond: CmpC("e", "eq", Set(S1("x")))), E("cond_type", "a literal set pairs with in/nin"));
        Has(Mini(cond: CmpC("e", "in", Set(""))), E("cond_type", "empty literal list"));
        Has(Mini(cond: CmpC("e", "in", LitS("x"))), E("cond_type", "in/nin needs a list"));
        Has(Mini(cond: CmpC("e", "in", Set("{'k':'set','items':[]}"))), E("cond_type", "nested literal set"));
        Has(Mini(cond: CmpC("e", "in", Set(S1("z")))), E("cond_enum", "enum literal is not a member"));
    }

    [Fact]
    public void OtherRightHandTermsAreUnsupported() =>
        Has(Mini(cond: CmpC("e", "eq", "{'k':'param','path':'n'}")), E("cond_term", "unsupported right-hand term"));

    [Theory]
    [InlineData("e", "lt")]
    [InlineData("e", "lte")]
    [InlineData("e", "gt")]
    [InlineData("e", "gte")]
    [InlineData("tx", "lt")]
    [InlineData("i", "gte")]
    public void OrderingATextualParameterIsRefused(string param, string op)
    {
        string lit = param == "e" ? LitS("x") : param == "i" ? LitS("d_1") : LitS("a");
        Has(Mini(cond: CmpC(param, op, lit)), E("cond_order", "ordering on a text/enum/id parameter"));
    }

    [Theory]
    [InlineData("e", "eq")]
    [InlineData("e", "in")]
    [InlineData("tx", "eq")]
    [InlineData("n", "lt")]
    [InlineData("n", "gte")]
    [InlineData("amt", "gt")]
    public void OtherOperatorsAndKindsMayOrder(string param, string op)
    {
        string lit = param == "e" ? (op == "in" ? Set(S1("x")) : LitS("x")) : param == "tx" ? LitS("a") : param == "n" ? LitQ(U_COUNT) : LitQ(U_USD);
        NoCode(Mini(cond: CmpC(param, op, lit)), "cond_order");
    }

    static string BadLeft => "{'k':'cmp','op':'lte','l':" + LitQ(U_COUNT) + ",'r':" + LitQ(U_COUNT) + "}";
    const string COND_PARAM = "left side of a comparison must be a declared parameter of the verb";

    [Fact]
    public void TheLeftSideMustBeADeclaredParameter()
    {
        Has(Mini(cond: BadLeft), E("cond_param", COND_PARAM));
        // an unknown path (the grant is dropped by its unbound slot, so the instantiation does not reach it)
        Has(Mini(cond: CmpC("nope", "lte", SLOT_S)), E("cond_param", COND_PARAM));
        // not a parameter although it carries a declared path
        D o = Mini(cond: "{'k':'cmp','op':'eq','l':{'k':'slot','slot':'s','path':'e'},'r':" + LitS("x") + "}");
        Has(o, E("cond_param", COND_PARAM));
        NoCode(Mini(cond: CmpC("e", "eq", LitS("x"))), "cond_param");
    }

    [Theory]
    [InlineData("and", "a")]
    [InlineData("and", "b")]
    [InlineData("or", "a")]
    [InlineData("or", "b")]
    public void ConnectivesCheckBothOperands(string kind, string side)
    {
        string good = TRUE;
        string cond = "{'k':'" + kind + "','a':" + (side == "a" ? BadLeft : good) + ",'b':" + (side == "b" ? BadLeft : good) + "}";
        Has(Mini(cond: cond), E("cond_param", COND_PARAM));
    }

    [Fact]
    public void NegationChecksItsOperand()
    {
        Has(Mini(cond: "{'k':'not','c':" + BadLeft + "}"), E("cond_param", COND_PARAM));
        NoCode(Mini(cond: "{'k':'not','c':" + TRUE + "}"), "cond_param");
    }
}
