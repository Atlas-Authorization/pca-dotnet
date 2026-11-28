using AtlasPca.GoalPkg;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Behaviour tests of the amount parsers, the slot typing and the template instantiation of the intent ontology.</summary>
public class GoalOntologyKillTests
{
    static string Q(string s) => s.Replace('\'', '"');
    static object? Val(string json) => Pca.ParseJson(Q(json));
    static D Obj(string json) => (D)Val(json)!;
    static D Dd(object? o) => (D)o!;
    static L Ll(object? o) => (L)o!;
    static string J(object? v) => G.stringify(v);

    // ---------------- ParseHumanAmount ----------------

    [Theory]
    [InlineData("20", 2, null, "{'ok':true,'minor':2000}")]
    [InlineData("1,000.50", 2, null, "{'ok':true,'minor':100050}")]
    [InlineData("1.000,50", 2, null, "{'ok':true,'minor':100050}")]
    [InlineData("1,000.50", 2, "de", "{'ok':true,'minor':100050}")]
    [InlineData("$20", 2, null, "{'ok':true,'minor':2000}")]
    [InlineData("20 dollars", 0, null, "{'ok':true,'minor':20}")]
    [InlineData("  20 ", 0, null, "{'ok':true,'minor':20}")]
    [InlineData("abc", 2, null, "{'ok':false,'reason':'not a number'}")]
    [InlineData("", 2, null, "{'ok':false,'reason':'not a number'}")]
    [InlineData("12", 0, null, "{'ok':true,'minor':12}")]
    [InlineData("5", 0, null, "{'ok':true,'minor':5}")]
    [InlineData("100", 0, null, "{'ok':true,'minor':100}")]
    [InlineData("1000", 0, null, "{'ok':true,'minor':1000}")]
    [InlineData("1..5", 2, null, "{'ok':false,'reason':'not a number'}")]
    [InlineData("1,,5", 2, null, "{'ok':false,'reason':'not a number'}")]
    [InlineData(".5", 2, null, "{'ok':false,'reason':'not a number'}")]
    [InlineData("1.50", 2, null, "{'ok':true,'minor':150}")]
    [InlineData("1,5", 1, null, "{'ok':true,'minor':15}")]
    [InlineData("1.5", 1, null, "{'ok':true,'minor':15}")]
    [InlineData("1,5", 2, null, "{'ok':true,'minor':150}")]
    [InlineData("0.5", 1, null, "{'ok':true,'minor':5}")]
    [InlineData("1.5", 0, null, "{'ok':false,'reason':'more decimals than the currency allows'}")]
    [InlineData("1,000", 2, null, "{'ok':false,'reason':'ambiguous separator'}")]
    [InlineData("1,000", 2, "", "{'ok':false,'reason':'ambiguous separator'}")]
    [InlineData("1,000", 2, "en", "{'ok':true,'minor':100000}")]
    [InlineData("1,000", 2, "de", "{'ok':false,'reason':'more decimals than the currency allows'}")]
    [InlineData("1.000", 2, "de", "{'ok':true,'minor':100000}")]
    [InlineData("1.000", 2, "en", "{'ok':false,'reason':'more decimals than the currency allows'}")]
    [InlineData("1,000,000", 0, null, "{'ok':true,'minor':1000000}")]
    [InlineData("1.000.000", 0, null, "{'ok':true,'minor':1000000}")]
    [InlineData("1.5.5", 2, null, "{'ok':false,'reason':'malformed grouping'}")]
    [InlineData("1234,567.89", 2, null, "{'ok':false,'reason':'malformed grouping'}")]
    [InlineData("1,000,00", 0, null, "{'ok':false,'reason':'malformed grouping'}")]
    [InlineData("1,5.000,5", 2, null, "{'ok':false,'reason':'out of range'}")]
    [InlineData("9007199254740991", 0, null, "{'ok':true,'minor':9007199254740991}")]
    [InlineData("9007199254740992", 0, null, "{'ok':false,'reason':'out of range'}")]
    [InlineData("99999999999999999999", 0, null, "{'ok':false,'reason':'out of range'}")]
    public void ParseHumanAmountExact(string text, int exp, string? locale, string expected) =>
        Assert.Equal(Q(expected), J(GoalOntology.ParseHumanAmount(text, exp, locale)));

    // ---------------- ParseMoney ----------------

    [Theory]
    [InlineData("$20.50", 2, null, "{'minor':2050}")]
    [InlineData("€ 20", 2, null, "{'minor':2000}")]
    [InlineData("£5", 0, null, "{'minor':5}")]
    [InlineData(" $ 7", 0, null, "{'minor':7}")]
    [InlineData("$$5", 2, null, "{'error':'BAD_NUMBER'}")]
    [InlineData("abc", 2, null, "{'error':'BAD_NUMBER'}")]
    [InlineData("20 dollars", 0, null, "{'error':'BAD_NUMBER'}")]
    [InlineData("", 0, null, "{'error':'BAD_NUMBER'}")]
    [InlineData("-5", 0, null, "{'error':'BAD_NUMBER'}")]
    [InlineData("1,000.50", 2, "en", "{'minor':100050}")]
    [InlineData("1,000.50", 2, "de", "{'error':'BAD_NUMBER'}")]
    [InlineData("1.000,50", 2, "de", "{'minor':100050}")]
    [InlineData("1.000,50", 2, "en", "{'error':'BAD_NUMBER'}")]
    [InlineData("1,000.50", 2, "xx", "{'error':'BAD_NUMBER'}")]
    [InlineData("1.000,50", 2, "xx", "{'minor':100050}")]
    [InlineData("1,000.50", 2, null, "{'minor':100050}")]
    [InlineData("1.000.000", 2, null, "{'hole':'AMBIGUOUS_NUMBER'}")]
    [InlineData("1,000,000", 2, null, "{'hole':'AMBIGUOUS_NUMBER'}")]
    [InlineData("1,000", 2, null, "{'hole':'AMBIGUOUS_NUMBER'}")]
    [InlineData("1.000.000", 0, "en", "{'minor':1000000}")]
    [InlineData("1,5", 2, null, "{'minor':150}")]
    [InlineData("1.5", 0, null, "{'error':'BAD_NUMBER'}")]
    [InlineData("1,5.000,5", 2, null, "{'error':'BAD_NUMBER'}")]
    public void ParseMoneyExact(string text, int exp, string? locale, string expected) =>
        Assert.Equal(Q(expected), J(GoalOntology.ParseMoney(text, exp, locale)));

    // ---------------- SlotLits ----------------

    const string TYPES = "{'id':'i','version':1,'domain':'i','types':[{'id':'customer','id_prefix':'cus_'},{'id':'charge','id_prefix':'ch_'},{'id':'blank','id_prefix':''}],"
        + "'units':{'USD':{'kind':'money','exponent':2},'EUR':{'kind':'money','exponent':2},'JPY':{'kind':'money','exponent':0},'count':{'kind':'count'}},"
        + "'relations':[{'id':'charges_of','from':'customer','to':'charge'}],"
        + "'verbs':[{'id':'read_charge','effect':'read','resource_type':'charge','params':{}},"
        + "{'id':'refund','effect':'irreversible','resource_type':'charge','params':{'amount':{'kind':'money','ccys':['USD','EUR']},'reason':{'kind':'enum','values':['dup','fraud']},'tag':{'kind':'text'}}},"
        + "{'id':'tally','effect':'reversible','resource_type':'charge','params':{'amount':{'kind':'count'}}}],'aliases':{},'templates':[";

    static D Ont(params string[] templates) => Obj(TYPES + string.Join(",", templates) + "]}");

    static string Lits(string slot, string valueJson)
    {
        object? r = GoalOntology.SlotLits(Ont(), Obj(slot), Val(valueJson));
        return r is string s ? s : J(r);
    }

    static string Money(string ccy, long n) => "[{'k':'q','q':{'u':{'k':'money','ccy':'" + ccy + "'},'n':" + n + "}}]";
    static string Plain(string kind, long n) => "[{'k':'q','q':{'u':{'k':'" + kind + "'},'n':" + n + "}}]";
    const string MONEY = "{'name':'m','kind':'money','ccy':'USD','max':1000}";

    [Fact]
    public void SlotLitsMissing() => Assert.Equal("missing", GoalOntology.SlotLits(Ont(), Obj(MONEY), null));

    [Fact]
    public void SlotLitsMoney()
    {
        Assert.Equal(Q(Money("USD", 500)), Lits(MONEY, "{'ccy':'USD','minor':500}"));
        Assert.Equal(Q(Money("USD", 1000)), Lits(MONEY, "{'ccy':'USD','minor':1000}"));
        Assert.Equal(Q(Money("USD", 0)), Lits(MONEY, "{'ccy':'USD','minor':0}"));
        Assert.Equal("above the template maximum", Lits(MONEY, "{'ccy':'USD','minor':1001}"));
        Assert.Equal("ill-typed", Lits(MONEY, "{'ccy':'USD','minor':-1}"));
        Assert.Equal("ill-typed", Lits(MONEY, "{'ccy':'EUR','minor':5}"));
        Assert.Equal("ill-typed", Lits(MONEY, "{'ccy':'USD','minor':'500'}"));
        Assert.Equal("ill-typed", Lits(MONEY, "{'ccy':'USD','n':5}"));
        Assert.Equal("ill-typed", Lits(MONEY, "'x'"));
        Assert.Equal("ill-typed", Lits(MONEY, "[]"));
        Assert.Equal(Q(Money("USD", 999999)), Lits("{'name':'m','kind':'money','ccy':'USD'}", "{'ccy':'USD','minor':999999}"));
        var e = Assert.Throws<IrError>(() => GoalOntology.SlotLits(Ont(), Obj(MONEY), Val("5")));
        Assert.Equal("pca-goal: slot value is not an object", e.Message);
    }

    [Fact]
    public void SlotLitsCount()
    {
        const string s = "{'name':'c','kind':'count','max':10}";
        Assert.Equal(Q(Plain("count", 3)), Lits(s, "{'n':3}"));
        Assert.Equal(Q(Plain("count", 0)), Lits(s, "{'n':0}"));
        Assert.Equal(Q(Plain("count", 10)), Lits(s, "{'n':10}"));
        Assert.Equal("above the template maximum", Lits(s, "{'n':11}"));
        Assert.Equal("ill-typed", Lits(s, "{'n':-1}"));
        Assert.Equal("ill-typed", Lits(s, "{'minor':5,'ccy':'USD'}"));
        Assert.Equal("ill-typed", Lits(s, "{'ms':5}"));
    }

    [Fact]
    public void SlotLitsDuration()
    {
        const string s = "{'name':'d','kind':'duration','max':3}";
        Assert.Equal(Q(Plain("duration", 3)), Lits(s, "{'ms':3}"));
        Assert.Equal(Q(Plain("duration", 0)), Lits(s, "{'ms':0}"));
        Assert.Equal("above the template maximum", Lits(s, "{'ms':5}"));
        Assert.Equal("ill-typed", Lits(s, "{'ms':-1}"));
        Assert.Equal("ill-typed", Lits(s, "{'n':1}"));
        Assert.Equal(Q(Plain("duration", 12345)), Lits("{'name':'d','kind':'duration'}", "{'ms':12345}"));
    }

    [Fact]
    public void SlotLitsInstant()
    {
        const string s = "{'name':'t','kind':'instant','max':10}";
        Assert.Equal(Q(Plain("instant", 99999)), Lits(s, "{'epoch_ms':99999}"));
        Assert.Equal(Q(Plain("instant", -5)), Lits(s, "{'epoch_ms':-5}"));
        Assert.Equal("ill-typed", Lits(s, "{'epoch_ms':'x'}"));
        Assert.Equal("ill-typed", Lits(s, "{'ms':5}"));
    }

    [Fact]
    public void SlotLitsId()
    {
        const string s = "{'name':'x','kind':'id','of':'charge'}";
        Assert.Equal("[{'k':'s','s':'ch_1'}]".Replace('\'', '"'), Lits(s, "'ch_1'"));
        Assert.Equal("[{'k':'s','s':'ch_a-b_9'}]".Replace('\'', '"'), Lits(s, "'ch_a-b_9'"));
        Assert.Equal("ill-typed", Lits(s, "'ch_'"));
        Assert.Equal("ill-typed", Lits(s, "'x_1'"));
        Assert.Equal("ill-typed", Lits(s, "'ch_1 '"));
        Assert.Equal("ill-typed", Lits(s, "'ch_1.2'"));
        Assert.Equal("ill-typed", Lits(s, "5"));
        Assert.Equal("ill-typed", Lits(s, "['ch_1']"));
        Assert.Equal("ill-typed", Lits("{'name':'x','kind':'id','of':'ghost'}", "'ch_1'"));
        Assert.Equal("ill-typed", Lits("{'name':'x','kind':'id','of':'blank'}", "'abc'"));
    }

    [Fact]
    public void SlotLitsIdList()
    {
        const string s = "{'name':'x','kind':'id_list','of':'charge'}";
        Assert.Equal(Q("[{'k':'s','s':'ch_1'},{'k':'s','s':'ch_2'}]"), Lits(s, "['ch_1','ch_2']"));
        Assert.Equal("ill-typed", Lits(s, "[]"));
        Assert.Equal("ill-typed", Lits(s, "'ch_1'"));
        Assert.Equal("ill-typed", Lits(s, "['ch_1','bad']"));
        Assert.Equal("ill-typed", Lits(s, "['ch_1','ch_2 ']"));
        Assert.Equal("ill-typed", Lits("{'name':'x','kind':'id_list','of':'ghost'}", "['ch_1']"));
        Assert.Equal("ill-typed", Lits("{'name':'x','kind':'id_list','of':'blank'}", "['abc']"));
        var e = Assert.Throws<IrError>(() => GoalOntology.SlotLits(Ont(), Obj(s), Val("['ch_1',5]")));
        Assert.Equal("pca-goal: string expected", e.Message);
    }

    [Fact]
    public void SlotLitsEnum()
    {
        const string s = "{'name':'x','kind':'enum','values':['a','b']}";
        Assert.Equal(Q("[{'k':'s','s':'a'}]"), Lits(s, "'a'"));
        Assert.Equal("ill-typed", Lits(s, "'c'"));
        Assert.Equal("ill-typed", Lits(s, "5"));
        Assert.Equal("ill-typed", Lits("{'name':'x','kind':'enum'}", "'a'"));
    }

    [Fact]
    public void SlotLitsEnumList()
    {
        const string s = "{'name':'x','kind':'enum_list','values':['a','b']}";
        Assert.Equal(Q("[{'k':'s','s':'a'},{'k':'s','s':'b'}]"), Lits(s, "['a','b']"));
        Assert.Equal(Q("[{'k':'s','s':'b'}]"), Lits(s, "['b']"));
        Assert.Equal("ill-typed", Lits(s, "['a','c']"));
        Assert.Equal("ill-typed", Lits(s, "[]"));
        Assert.Equal("ill-typed", Lits(s, "'a'"));
    }

    [Fact]
    public void SlotLitsTextList()
    {
        const string s = "{'name':'x','kind':'text_list'}";
        Assert.Equal(Q("[{'k':'s','s':'x.com'},{'k':'s','s':'y.org'}]"), Lits(s, "['x.com','y.org']"));
        Assert.Equal("ill-typed", Lits(s, "[]"));
        Assert.Equal("ill-typed", Lits(s, "'x.com'"));
        Assert.Equal("ill-typed", Lits(s, "['']"));
        Assert.Equal("ill-typed", Lits(s, "['a​b']"));
        Assert.Equal("ill-typed", Lits(s, "['ｅ']"));
        Assert.Equal("ill-typed", Lits(s, "[5]"));
        Assert.Equal("ill-typed", Lits(s, "['ok',7]"));
    }

    [Fact]
    public void SlotLitsOtherKindsHaveNoLiterals()
    {
        Assert.Null(GoalOntology.SlotLits(Ont(), Obj("{'name':'x','kind':'text'}"), Val("'x'")));
        Assert.Null(GoalOntology.SlotLits(Ont(), Obj("{'name':'x','kind':'weird'}"), Val("'x'")));
    }

    // ---------------- InstantiateTemplate ----------------

    const string T1 = "{'id':'t1','title':'t','phrases':[],"
        + "'slots':[{'name':'cust','kind':'id','of':'customer','mandatory':true},{'name':'ch','kind':'id','of':'charge','mandatory':true},"
        + "{'name':'max_cap','kind':'money','ccy':'USD','mandatory':true,'max':1000},{'name':'n','kind':'count','mandatory':false,'default':{'n':2}},"
        + "{'name':'kinds','kind':'enum_list','values':['dup','fraud'],'mandatory':false,'default':['dup']}],"
        + "'grants':["
        + "{'gid':'g1','verb':'refund','res':{'k':'all_of','parts':[{'k':'exact','id':'$ch'},{'k':'related','rel':'charges_of','anchor':'$cust'}]},"
        + "'cond':{'k':'and','a':{'k':'cmp','op':'lte','l':{'k':'param','path':'amount'},'r':{'k':'slot','slot':'max_cap'}},"
        + "'b':{'k':'not','c':{'k':'or','a':{'k':'cmp','op':'in','l':{'k':'param','path':'reason'},'r':{'k':'slot','slot':'kinds'}},"
        + "'b':{'k':'cmp','op':'eq','l':{'k':'param','path':'reason'},'r':{'k':'lit','v':{'k':'s','s':'fraud'}}}}}}},"
        + "{'gid':'g2','verb':'tally','res':{'k':'oneof','ids':['$ch','ch_static']},"
        + "'cond':{'k':'cmp','op':'lte','l':{'k':'param','path':'amount'},'r':{'k':'slot','slot':'n'}}},"
        + "{'gid':'g3','verb':'read_charge','res':{'k':'any','reason':'x'},'cond':{'k':'true'}}],"
        + "'prohibits':["
        + "{'pid':'a','target':{'k':'verb','verb':'tally'},'res':{'k':'related','rel':'charges_of','anchor':'$cust'},'cond':{'k':'true'}},"
        + "{'pid':'b','target':{'k':'effect','cls':'reversible'},'res':{'k':'exact','id':'$ch'},'cond':{'k':'cmp','op':'lte','l':{'k':'param','path':'amount'},'r':{'k':'slot','slot':'max_cap'}}},"
        + "{'pid':'c','target':{'k':'effect','cls':'external_send'},'res':{'k':'any','reason':'z'},'cond':{'k':'cmp','op':'lte','l':{'k':'param','path':'amount'},'r':{'k':'slot','slot':'max_cap'}}}],"
        + "'bounds':["
        + "{'bid':'sum','agg':'sum','over':'all','param':'amount','cap':{'u':{'k':'money','ccy':'USD'},'n':0},'onExceed':'deny','cap_slot':'max_cap'},"
        + "{'bid':'cnt','agg':'count','over':['g2'],'cap':{'u':{'k':'count'},'n':0},'onExceed':'deny','cap_slot':'n'},"
        + "{'bid':'lit','agg':'count','over':['g3'],'cap':{'u':{'k':'count'},'n':7},'onExceed':'deny'},"
        + "{'bid':'lit2','agg':'count','over':['g3'],'cap':{'u':{'k':'count'},'n':9},'onExceed':'deny','cap_slot':'cust'}],"
        + "'example':{}}";

    const string FULL = "{'cust':'cus_1','ch':'ch_1','max_cap':{'ccy':'USD','minor':500}}";
    const string MONEY_TY = "{'k':'q','u':{'k':'money','ccy':'USD'}}";
    const string COUNT_TY = "{'k':'q','u':{'k':'count'}}";
    const string CAP500 = "{'u':{'k':'money','ccy':'USD'},'n':500}";

    static D Run(D o, string id, string? vals, List<string>? src = null) =>
        GoalOntology.InstantiateTemplate(o, id, vals == null ? null! : Obj(vals), "pr", "nl text", src);

    static string BoundJson(string bid, string gids, string agg, string value, string cap) =>
        "{'bid':'" + bid + "','sel':{'k':'gids','gids':" + gids + "},'agg':'" + agg + "','value':" + value + ",'key':'','window':{'k':'lifetime'},'scope':{'k':'session'},'cap':" + cap + ",'onExceed':'deny'}";

    const string COUNT_ONE = "{'k':'lit','v':{'k':'q','q':{'u':{'k':'count'},'n':1}}}";

    [Fact]
    public void InstantiateFullGrants()
    {
        D g = Run(Ont(T1), "t1", FULL);
        string g1 = "{'gid':'g1','verb':'refund','res':{'k':'all_of','parts':[{'k':'exact','id':'ch_1'},{'k':'related','rel':'charges_of','anchor':'cus_1'}]},"
            + "'cond':{'k':'and','a':{'k':'cmp','op':'lte','l':{'k':'param','path':'amount','ty':" + MONEY_TY + "},'r':{'k':'lit','v':{'k':'q','q':" + CAP500 + "}}},"
            + "'b':{'k':'not','c':{'k':'or','a':{'k':'cmp','op':'in','l':{'k':'param','path':'reason','ty':{'k':'s'}},'r':{'k':'lit','v':{'k':'set','items':[{'k':'s','s':'dup'}]}}},"
            + "'b':{'k':'cmp','op':'eq','l':{'k':'param','path':'reason','ty':{'k':'s'}},'r':{'k':'lit','v':{'k':'s','s':'fraud'}}}}}}}";
        string g2 = "{'gid':'g2','verb':'tally','res':{'k':'oneof','ids':['ch_1','ch_static']},"
            + "'cond':{'k':'cmp','op':'lte','l':{'k':'param','path':'amount','ty':" + COUNT_TY + "},'r':{'k':'lit','v':{'k':'q','q':{'u':{'k':'count'},'n':2}}}}}";
        string g3 = "{'gid':'g3','verb':'read_charge','res':{'k':'any','reason':'x'},'cond':{'k':'true'}}";
        Assert.Equal(Q("[" + g1 + "," + g2 + "," + g3 + "]"), J(g["grants"]));
    }

    [Fact]
    public void InstantiateFullProhibits()
    {
        D g = Run(Ont(T1), "t1", FULL);
        string a = "{'pid':'a','target':{'k':'verb','verb':'tally'},'res':{'k':'related','rel':'charges_of','anchor':'cus_1'},'cond':{'k':'true'}}";
        string b = "{'pid':'b','target':{'k':'effect','cls':'reversible'},'res':{'k':'exact','id':'ch_1'},"
            + "'cond':{'k':'cmp','op':'lte','l':{'k':'param','path':'amount','ty':" + COUNT_TY + "},'r':{'k':'lit','v':{'k':'q','q':" + CAP500 + "}}}}";
        string c = "{'pid':'c','target':{'k':'effect','cls':'external_send'},'res':{'k':'any','reason':'z'},"
            + "'cond':{'k':'cmp','op':'lte','l':{'k':'param','path':'amount','ty':" + MONEY_TY + "},'r':{'k':'lit','v':{'k':'q','q':" + CAP500 + "}}}}";
        Assert.Equal(Q("[" + a + "," + b + "," + c + "]"), J(g["prohibits"]));
    }

    [Fact]
    public void InstantiateFullBounds()
    {
        D g = Run(Ont(T1), "t1", FULL);
        string cnt = BoundJson("cnt", "['g2']", "count", COUNT_ONE, "{'u':{'k':'count'},'n':2}");
        string lit = BoundJson("lit", "['g3']", "count", COUNT_ONE, "{'u':{'k':'count'},'n':7}");
        string lit2 = BoundJson("lit2", "['g3']", "count", COUNT_ONE, "{'u':{'k':'count'},'n':9}");
        string sum = BoundJson("sum", "['g1','g2','g3']", "sum", "{'k':'param','path':'amount','ty':" + MONEY_TY + "}", CAP500);
        Assert.Equal(Q("[" + cnt + "," + lit + "," + lit2 + "," + sum + "]"), J(g["bounds"]));
        Assert.Equal("[]", J(g["holes"]));
    }

    [Fact]
    public void InstantiateEnvelope()
    {
        D o = Ont(T1);
        D g = Run(o, "t1", FULL, new List<string> { "s1", "s2" });
        Assert.Equal("v,principal,ontDigest,nlDigest,sources,grants,prohibits,bounds,validity,deleg,escalateOn,wildcardAck,holes", string.Join(",", g.Keys));
        Assert.Equal("1", J(g["v"]));
        Assert.Equal("pr", g["principal"]);
        Assert.Equal(GoalOntology.OntologyDigest(o), g["ontDigest"]);
        Assert.Equal(GoalDigests.NlDigest("nl text"), g["nlDigest"]);
        Assert.Equal(Q("['s1','s2']"), J(g["sources"]));
        Assert.Equal(Q("{'notBefore':0,'notAfter':9007199254740991,'maxIdle':0}"), J(g["validity"]));
        Assert.Equal(Q("{'maxDepth':0,'narrowOnly':true,'mayTouch':[]}"), J(g["deleg"]));
        Assert.Equal("[]", J(g["escalateOn"]));
        Assert.Equal("[]", J(g["wildcardAck"]));
        Assert.Equal("[]", J(Run(o, "t1", FULL)["sources"]));
    }

    [Fact]
    public void InstantiateMissingMandatorySlotsBecomeHolesDroppingTheirClauses()
    {
        D g = Run(Ont(T1), "t1", "{'cust':'cus_1','ch':'ch_1'}");
        Assert.Equal(Q("[{'hid':'max_cap','q':'What is the max cap (money USD)? (missing)','domain':[],'affects':[],'global':false}]"), J(g["holes"]));
        Assert.Equal("[]", J(g["grants"]));
        Assert.Equal("[]", J(g["bounds"]));
        string a = "{'pid':'a','target':{'k':'verb','verb':'tally'},'res':{'k':'related','rel':'charges_of','anchor':'cus_1'},'cond':{'k':'true'}}";
        string b = "{'pid':'b','target':{'k':'effect','cls':'reversible'},'res':{'k':'any','reason':'hole'},'cond':{'k':'true'}}";
        string c = "{'pid':'c','target':{'k':'effect','cls':'external_send'},'res':{'k':'any','reason':'hole'},'cond':{'k':'true'}}";
        Assert.Equal(Q("[" + a + "," + b + "," + c + "]"), J(g["prohibits"]));
    }

    [Fact]
    public void InstantiateNullValuesUsesDefaultsAndHolesTheRest()
    {
        D g = Run(Ont(T1), "t1", null);
        L holes = Ll(g["holes"]);
        Assert.Equal(Q("['ch','cust','max_cap']"), J(holes.Select(h => Dd(h)["hid"]).ToList()));
        Assert.Equal("What is the ch (id)? (missing)", Dd(holes[0])["q"]);
        Assert.Equal("What is the cust (id)? (missing)", Dd(holes[1])["q"]);
        Assert.Equal("What is the max cap (money USD)? (missing)", Dd(holes[2])["q"]);
    }

    [Fact]
    public void InstantiateIllTypedAndOversizedValuesBecomeHoles()
    {
        D g = Run(Ont(T1), "t1", "{'cust':'bad','ch':'ch_1','max_cap':{'ccy':'USD','minor':5000}}");
        L holes = Ll(g["holes"]);
        Assert.Equal(2, holes.Count);
        Assert.Equal("What is the cust (id)? (ill-typed)", Dd(holes[0])["q"]);
        Assert.Equal("What is the max cap (money USD)? (above the template maximum)", Dd(holes[1])["q"]);
    }

    [Fact]
    public void InstantiateDropsOnlyTheGrantsAUnmetBoundSelects()
    {
        D o = Ont(T1);
        Dd(Ll(Dd(Ll(o["templates"])[0])["bounds"])[0])["over"] = Val("['g1']");
        D g = Run(o, "t1", "{'cust':'cus_1','ch':'ch_1'}");
        Assert.Equal(Q("['g2','g3']"), J(Ll(g["grants"]).Select(x => Dd(x)["gid"]).ToList()));
        Assert.Equal(Q("['cnt','lit','lit2']"), J(Ll(g["bounds"]).Select(x => Dd(x)["bid"]).ToList()));
    }

    [Fact]
    public void InstantiateUnknownTemplateThrows()
    {
        var e = Assert.Throws<IrError>(() => Run(Ont(T1), "zz", "{}"));
        Assert.Equal("pca-goal: unknown template zz", e.Message);
    }

    const string T2 = "{'id':'t2','slots':[{'name':'cust','kind':'id','of':'customer','mandatory':true}],"
        + "'grants':[{'gid':'x','verb':'refund','res':{'k':'exact','id':'ch_1'},'cond':{'k':'cmp','op':'lte','l':{'k':'param','path':'zz'},'r':{'k':'lit','v':{'k':'q','q':{'u':{'k':'money','ccy':'USD'},'n':1}}}}}],"
        + "'prohibits':[],'bounds':[],'example':{}}";

    const string T3 = "{'id':'t3','slots':[{'name':'max_cap','kind':'money','ccy':'USD','mandatory':true}],"
        + "'grants':[{'gid':'x','verb':'refund','res':{'k':'exact','id':'ch_1'},'cond':{'k':'true'}}],"
        + "'prohibits':[],'bounds':[{'bid':'s','agg':'sum','over':'all','cap':{'u':{'k':'money','ccy':'USD'},'n':0},'onExceed':'deny','cap_slot':'max_cap'}],'example':{}}";

    const string T4 = "{'id':'t4','slots':[],'grants':[{'gid':'x','res':{'k':'exact','id':'ch_1'},'cond':{'k':'true'}}],"
        + "'prohibits':[],'bounds':[{'bid':'c','agg':'count','over':'all','cap':{'u':{'k':'count'},'n':1},'onExceed':'deny'}],'example':{}}";

    [Fact]
    public void InstantiateUndeclaredParameterThrows()
    {
        var e = Assert.Throws<IrError>(() => Run(Ont(T2), "t2", "{'cust':'cus_1'}"));
        Assert.Equal("pca-goal: parameter zz is not declared by any verb", e.Message);
    }

    [Fact]
    public void InstantiateSumBoundWithoutParameterThrows()
    {
        var e = Assert.Throws<IrError>(() => Run(Ont(T3), "t3", "{'max_cap':{'ccy':'USD','minor':5}}"));
        Assert.Equal("pca-goal: parameter undefined is not declared by any verb", e.Message);
    }

    [Fact]
    public void InstantiateBoundWithoutAVerbOnItsGrantThrows()
    {
        var e = Assert.Throws<IrError>(() => Run(Ont(T4), "t4", "{}"));
        Assert.Equal("pca-goal: bound without a surviving grant", e.Message);
    }

    static string Cmp(string l, string r) => "{'k':'cmp','op':'lte','l':" + l + ",'r':" + r + "}";
    static string LitQ(string unit, int n) => "{'k':'lit','v':{'k':'q','q':{'u':" + unit + ",'n':" + n + "}}}";
    const string AMOUNT = "{'k':'param','path':'amount'}";

    static string T5() => "{'id':'t5','slots':[],'grants':["
        + "{'gid':'ga','verb':'refund','res':{'k':'any','reason':'a'},'cond':" + Cmp(LitQ("{'k':'money','ccy':'EUR'}", 5), AMOUNT) + "},"
        + "{'gid':'gb','verb':'refund','res':{'k':'any','reason':'a'},'cond':" + Cmp(LitQ("{'k':'money','ccy':'JPY'}", 5), AMOUNT) + "},"
        + "{'gid':'gc','verb':'refund','res':{'k':'any','reason':'a'},'cond':" + Cmp(AMOUNT, LitQ("{'k':'count'}", 3)) + "},"
        + "{'gid':'gd','verb':'refund','res':{'k':'any','reason':'a'},'cond':" + Cmp(AMOUNT, LitQ("{'k':'money','ccy':'EUR'}", 5)) + "}],"
        + "'prohibits':[],'bounds':[],'example':{}}";

    static string Amt(string ccy) => "{'k':'param','path':'amount','ty':{'k':'q','u':{'k':'money','ccy':'" + ccy + "'}}}";

    [Fact]
    public void InstantiateTakesTheCurrencyHintFromEitherSide()
    {
        D g = Run(Ont(T5()), "t5", "{}");
        L grants = Ll(g["grants"]);
        string eur = "{'k':'money','ccy':'EUR'}";
        Assert.Equal(Q(Cmp(LitQ(eur, 5), Amt("EUR"))), J(Dd(grants[0])["cond"]));
        Assert.Equal(Q(Cmp(LitQ("{'k':'money','ccy':'JPY'}", 5), Amt("USD"))), J(Dd(grants[1])["cond"]));
        Assert.Equal(Q(Cmp(Amt("USD"), LitQ("{'k':'count'}", 3))), J(Dd(grants[2])["cond"]));
        Assert.Equal(Q(Cmp(Amt("EUR"), LitQ(eur, 5))), J(Dd(grants[3])["cond"]));
    }
}
