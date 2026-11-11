using AtlasPca;
using Xunit;

namespace AtlasPca.Corpus.Tests;

/// <summary>The RIM XML reader and canonicaliser against the reference: packages/pca/src/attest-nvidia-rim.ts over @xmldom/xmldom 0.8.15 and
/// xml-crypto 6.1.2. Where the reference is looser (a bare ampersand, an unclosed element, an unquoted value, an unbound prefix, a character
/// reference outside the Char production) this reader stays strict, and these tests pin the refusal.</summary>
public class AttestXmlKillTests
{
    const string PiNote = "XML processing instructions are not permitted", DtdNote = "DTD / DOCTYPE is not permitted", CommentNote = "XML comments are not permitted";
    const string BadCdata = "misplaced or unterminated CDATA section", BadEnd = "unexpected end tag";

    static XmlDoc P(string xml) => AttestXml.Parse(xml);
    static XmlNode R(string xml) => AttestXml.Parse(xml).Root!;
    static string Err(string xml) => Assert.Throws<AttestError>(() => AttestXml.Parse(xml)).Message;
    static string T(string inner) => R($"<r>{inner}</r>").TextContent();
    static string Canon(string xml) => AttestXml.Canonicalize(R(xml), new Dictionary<string, string>(StringComparer.Ordinal), null);

    // ---- node defaults, names, namespaces

    [Fact]
    public void NewNodesStartEmpty()
    {
        var a = new XmlAttr();
        Assert.Equal(new[] { "", "", "", "", "" }, new[] { a.Name, a.Prefix, a.Local, a.Ns, a.Value });
        var n = new XmlNode();
        Assert.Equal(new[] { "", "", "", "", "" }, new[] { n.Name, n.Prefix, n.Local, n.Ns, n.Text });
    }

    [Fact]
    public void TheFirstColonSplitsAQNameAndALeadingColonIsNoPrefix()
    {
        Assert.Equal(("a", "b:c"), AttestXml.SplitQName("a:b:c"));
        Assert.Equal(("", ":a"), AttestXml.SplitQName(":a"));
        Assert.Equal(("a", ""), AttestXml.SplitQName("a:"));
        Assert.Equal(("", "a"), AttestXml.SplitQName("a"));
    }

    [Fact]
    public void ElementNamesFollowTheReferencePattern()
    {
        foreach (var name in new[] { "1a", ":a", "a:", "a:b:c", "!x", "a<b", "-a", ".a", "×a" })
            Assert.Equal($"invalid tagName:{name}", Err($"<{name}/>"));
        Assert.Equal("invalid tagName:!x", Err("<r><!x y=\"1\"/></r>"));
        foreach (var name in new[] { "_a", "a-b.c1", "é", "a·b" })
            Assert.Equal(name, R($"<{name}/>").Name);
    }

    [Fact]
    public void AttributeNamesFollowTheReferencePattern()
    {
        foreach (var name in new[] { "1a", ":a", "a:", "a:b:c", "xmlns:", "xmlns:a:b" })
            Assert.Equal($"invalid attribute:{name}", Err($"<r {name}=\"1\"/>"));
        Assert.Equal("1", R("<r _a-b.c=\"1\"/>").Attr("_a-b.c"));
    }

    [Fact]
    public void AnUnprefixedNameWithoutADefaultNamespaceHasNoNamespace()
    {
        var r = R("<a/>");
        Assert.Equal("", r.Ns);
        Assert.Equal("a", r.Local);
    }

    [Fact]
    public void PrefixesResolveThroughTheScope()
    {
        var r = R("<p:a xmlns:p=\"u\" p:b=\"1\"/>");
        Assert.Equal(("p", "a", "u"), (r.Prefix, r.Local, r.Ns));
        Assert.Equal(("p", "b", "u"), (r.Attrs[0].Prefix, r.Attrs[0].Local, r.Attrs[0].Ns));
    }

    [Fact]
    public void AnUnboundPrefixIsRefused()
    {
        Assert.Equal("namespace prefix p is not bound", Err("<p:a/>"));
        Assert.Equal("namespace prefix q is not bound", Err("<a q:b=\"1\"/>"));
    }

    [Fact]
    public void TheXmlPrefixIsBoundWithoutADeclaration()
    {
        Assert.Equal("http://www.w3.org/XML/1998/namespace", R("<xml:a/>").Ns);
        Assert.Equal("urn:o", R("<xml:a xmlns:xml=\"urn:o\"/>").Ns);
    }

    [Fact]
    public void AnXmlAttributeIsAProfileViolationWithTheReferenceWording()
    {
        Assert.Equal("xml:* attribute 'xml:space' is not permitted (C14N 1.1 profile)", P("<a xml:space=\"preserve\"/>").Violation);
        Assert.Equal("xml:* attribute 'XML:id' is not permitted (C14N 1.1 profile)", P("<a xmlns:XML=\"u\" XML:id=\"1\"/>").Violation);
        Assert.Equal("", P("<a xmlns:xmlx=\"u\" xmlx:id=\"1\"/>").Violation);
        Assert.Equal("RIM: xml:* attribute 'xml:space' is not permitted (C14N 1.1 profile)", NvidiaHook.VerifyRim("<a xml:space=\"preserve\"/>", new[] { "pin" }, 0).Why);
    }

    [Fact]
    public void AnAbsentAttributeReadsEmpty()
    {
        var r = R("<a b=\"1\"/>");
        Assert.Equal("1", r.Attr("b"));
        Assert.Equal("", r.Attr("z"));
    }

    // ---- text and CDATA

    [Fact]
    public void AdjacentTextMergesIntoOneNode()
    {
        var r = R("<a>x<![CDATA[y]]>z<b/>w<![CDATA[v]]></a>");
        Assert.Equal(3, r.Children.Count);
        Assert.Equal("xyz", r.Children[0].Text);
        Assert.True(r.Children[1].Elem);
        Assert.Equal("wv", r.Children[2].Text);
    }

    [Fact]
    public void CdataIsRawAndMisplacedCdataIsRefused()
    {
        Assert.Equal("a<b&lt;cd", T("<![CDATA[a<b&lt;c]]>d"));
        Assert.Equal("", T("<![CDATA[]]>"));
        Assert.Equal(BadCdata, Err("<a><![CDATA[x</a>"));
        Assert.Equal(BadCdata, Err("<![CDATA[x]]><a/>"));
        Assert.Equal(BadCdata, Err("<![CDATA[x"));
    }

    [Fact]
    public void TextAtTheEndOfAnOpenElementReportsTheOpenElement() =>
        Assert.Equal("element <a> is not closed", Err("<a>text"));

    [Fact]
    public void LineEndingsAreNormalisedLikeTheReferenceParser()
    {
        Assert.Equal("x\ny\nz\nw\nv\nu", R("<a>x\r\ny\rz\u0085w\u2028v\r\u0085u</a>").TextContent());
        Assert.Equal("a\u2029b", T("a\u2029b"));
        Assert.Equal("<a>x\ny</a>", Canon("<a>x\r\ny</a>"));
        Assert.Equal("\r", T("&#xD;"));
    }

    // ---- references

    [Fact]
    public void ThePredefinedEntitiesDecode()
    {
        Assert.Equal("<", T("&lt;"));
        Assert.Equal(">", T("&gt;"));
        Assert.Equal("&", T("&amp;"));
        Assert.Equal("\"", T("&quot;"));
        Assert.Equal("'", T("&apos;"));
        Assert.Equal("ab<cd>e&f\"g'hi", T("ab&lt;cd&gt;e&amp;f&quot;g&apos;hi"));
        Assert.Equal("a;&", T("a;&amp;"));
        Assert.Equal("plain", T("plain"));
        Assert.Equal("&lt;", T("&amp;lt;"));
    }

    [Fact]
    public void ABadEntityIsRefused()
    {
        Assert.Equal("unterminated entity reference", Err("<r>&amp</r>"));
        Assert.Equal("unterminated entity reference", Err("<r>&lt;&</r>"));
        Assert.Equal("undefined entity &foo;", Err("<r>&foo;</r>"));
        Assert.Equal("undefined entity &;", Err("<r>&;</r>"));
    }

    [Fact]
    public void CharacterReferencesDecodeOnEveryEdgeOfTheCharProduction()
    {
        foreach (var n in new[] { 0x9, 0xa, 0xd, 0x20, 0x21, 0xd7fe, 0xd7ff, 0xe000, 0xe001, 0xfffc, 0xfffd, 0x10000, 0x10001, 0x10fffe, 0x10ffff })
        {
            Assert.Equal(char.ConvertFromUtf32(n), T($"&#x{n:x};"));
            Assert.Equal(char.ConvertFromUtf32(n), T($"&#{n};"));
        }
    }

    [Fact]
    public void CharacterReferencesOutsideTheCharProductionAreRefused()
    {
        foreach (var n in new[] { 0x0, 0x1, 0x8, 0xb, 0xc, 0xe, 0x1f, 0xd800, 0xdfff, 0xfffe, 0xffff, 0x110000, 0x7fffffff })
        {
            Assert.Equal($"invalid character reference &#x{n:x};", Err($"<r>&#x{n:x};</r>"));
            Assert.Equal($"invalid character reference &#{n};", Err($"<r>&#{n};</r>"));
        }
    }

    [Fact]
    public void HexAndDecimalAreToldApart()
    {
        Assert.Equal("A", T("&#65;"));
        Assert.Equal("A", T("&#x41;"));
        Assert.Equal("e", T("&#x65;"));
        Assert.Equal("j", T("&#x6A;"));
        Assert.Equal("a#b", T("a&#35;b"));
    }

    [Fact]
    public void ANumericReferenceIsDigitsOnly()
    {
        foreach (var r in new[] { "#+65", "#-65", "#x+41", "#x-41", "# 65", "#x 41", "#65 ", "#", "#x", "#X41", "#6_5", "#99999999999" })
            Assert.Equal($"invalid character reference &{r};", Err($"<r>&{r};</r>"));
    }

    [Fact]
    public void AHexReferenceHasAtMostEightDigitsAndADecimalOneAnyNumber()
    {
        Assert.Equal("A", T("&#x00000041;"));
        Assert.Equal("invalid character reference &#x000000041;", Err("<r>&#x000000041;</r>"));
        Assert.Equal("invalid character reference &#xFFFFFFFFFFFFFFFF;", Err("<r>&#xFFFFFFFFFFFFFFFF;</r>"));
        Assert.Equal("A", T("&#000000065;"));
        Assert.Equal("A", T("&#00000065;"));
        Assert.Equal("invalid character reference &#99999999999999999999;", Err("<r>&#99999999999999999999;</r>"));
    }

    [Fact]
    public void AMalformedCharacterReferenceIsRefused()
    {
        foreach (var ent in new[] { "#+65", "#x+41", "#", "#x", "#xZZ", "#6a", "#X41", "#-65", "# 65" })
            Assert.Equal($"invalid character reference &{ent};", Err($"<r>&{ent};</r>"));
    }

    [Fact]
    public void AttributeValuesDecodeAndNormaliseWhitespaceLikeTheReferenceParser()
    {
        Assert.Equal("<&", R("<a b=\"&lt;&amp;\"/>").Attr("b"));
        Assert.Equal("x y z w", R("<a b=\"x\ty\nz\r\nw\"/>").Attr("b"));
        Assert.Equal("x\ty\nz\r", R("<a b=\"x&#x9;y&#xA;z&#xD;\"/>").Attr("b"));
    }

    // ---- comments, processing instructions, DOCTYPE

    [Fact]
    public void CommentsAreNotedAndUnterminatedOnesRefused()
    {
        Assert.Equal(CommentNote, P("<a/><!---->").Violation);
        Assert.Equal("unterminated comment", Err("<a/><!-- x"));
    }

    [Fact]
    public void ProcessingInstructionsAreNotedSkippedAndUnterminatedOnesRefused()
    {
        var d = P("<?pi?><a/>");
        Assert.Equal(PiNote, d.Violation);
        Assert.Equal("a", d.Root!.Name);
        Assert.Equal("t", T("<?p q?>t"));
        Assert.Equal("unterminated processing instruction", Err("<?pi"));
        Assert.Equal("unterminated processing instruction", Err("<a/><?pi"));
    }

    [Fact]
    public void ADoctypeIsNotedAndSkipped()
    {
        foreach (var xml in new[]
        {
            "<!DOCTYPE r><r/>",
            "<!doctype r><r/>",
            "<!DocType r><r/>",
            "<!DOCTYPE r [ <!ENTITY b \"c\"> ]><r/>",
            "<!DOCTYPE r [[ > ] > ]><r/>",
            "<!DOCTYPE r ]><r/>",
        })
        {
            var d = P(xml);
            Assert.Equal(DtdNote, d.Violation);
            Assert.Equal("r", d.Root!.Name);
        }
    }

    [Fact]
    public void AnUnterminatedDoctypeIsRefused()
    {
        Assert.Equal("unterminated DOCTYPE", Err("<!DOCTYPE r"));
        Assert.Equal("unterminated DOCTYPE", Err("<!DOCTYPE r [ >"));
    }

    // ---- structure

    [Fact]
    public void EndTagsAreChecked()
    {
        Assert.Equal(BadEnd, Err("</a>"));
        Assert.Equal(BadEnd, Err("<a></a"));
        Assert.Equal("end tag </b> does not match <a>", Err("<a></b>"));
    }

    [Fact]
    public void TheDocumentHasOneClosedElement()
    {
        Assert.Equal("more than one document element", Err("<a/><b/>"));
        Assert.Equal("element <a> is not closed", Err("<a>"));
    }

    [Fact]
    public void AnEndTagLowersTheDepth()
    {
        // a sibling that raised the depth instead of lowering it would reach the cap inside this chain
        var chain = "<r><b></b>" + string.Concat(Enumerable.Repeat("<a>", 254)) + string.Concat(Enumerable.Repeat("</a>", 254)) + "</r>";
        Assert.Equal("r", R(chain).Name);
    }

    // ---- start tags

    [Fact]
    public void MalformedStartTagsAreRefusedWithTheirOwnReason()
    {
        foreach (var (xml, why) in new[]
        {
            ("<a", "unterminated start tag"),
            ("<a ", "unterminated start tag"),
            ("<>", "malformed start tag"),
            ("< a/>", "malformed start tag"),
            ("<a/", "malformed start tag"),
            ("<a/x>", "malformed start tag"),
            ("<a b", "malformed attribute"),
            ("<a b ", "malformed attribute"),
            ("<a b>", "malformed attribute"),
            ("<a =\"1\"/>", "malformed attribute"),
            ("<a b c=\"1\"/>", "malformed attribute"),
            ("<a b=", "unquoted attribute value"),
            ("<a b= ", "unquoted attribute value"),
            ("<a b=x/>", "unquoted attribute value"),
            ("<a b=\"1", "unterminated attribute value"),
            ("<a b='1\"/>", "unterminated attribute value"),
            ("<a b=\"<\"/>", "'<' in an attribute value"),
            ("<a b=\"1\" b=\"2\"/>", "attribute b is repeated"),
        })
            Assert.Equal(why, Err(xml));
    }

    [Fact]
    public void WellFormedStartTagsReadEveryForm()
    {
        var a = R("<a b = \"1\" c\n=\n'2'\td=\"3\"\n/>");
        Assert.Equal("a", a.Name);
        Assert.Equal(("1", "2", "3"), (a.Attr("b"), a.Attr("c"), a.Attr("d")));
        Assert.Equal("1", R("<a\nb=\"1\"/>").Attr("b"));
        Assert.Equal("1", R("<a\tb=\"1\"></a\n>").Attr("b"));
        Assert.Equal("x\"y", R("<a b='x\"y'/>").Attr("b"));
        var r = R("<r><a/><b/></r>");
        Assert.Equal(new[] { "a", "b" }, r.ElementChildren().Select(c => c.Name));
    }

    // ---- canonical form

    [Fact]
    public void CanonicalFormOfElementsAttributesAndText()
    {
        Assert.Equal("<r a=\"1\" b=\"2\"><x>t</x>u<y></y></r>", Canon("<r b=\"2\" a=\"1\"><x>t</x>u<y/></r>"));
        Assert.Equal("<p:r xmlns:p=\"u\"></p:r>", Canon("<p:r xmlns:p=\"u\"/>"));
    }

    [Fact]
    public void TextEscapes() =>
        Assert.Equal("<r>&amp;&lt;&gt;&#xD;\"'\t\n</r>", Canon("<r>&amp;&lt;&gt;&#xD;\"'\t\n</r>"));

    [Fact]
    public void AttributeEscapes() =>
        Assert.Equal("<r v=\"&amp;&lt;&quot;&#x9;&#xA;&#xD;'>\"></r>", Canon("<r v=\"&amp;&lt;&quot;&#x9;&#xA;&#xD;'>\"/>"));

    [Fact]
    public void NamespaceDeclarationsComeFirstInPrefixOrder() =>
        Assert.Equal("<r xmlns=\"d\" xmlns:a=\"u1\" xmlns:b=\"u2\" z=\"1\"></r>", Canon("<r z=\"1\" xmlns:b=\"u2\" xmlns=\"d\" xmlns:a=\"u1\"/>"));

    [Fact]
    public void AttributesSortUnqualifiedFirstThenByNamespaceAndLocalName()
    {
        // namespace y sorts before z although its prefix sorts after
        Assert.Equal("<r xmlns:a=\"z\" xmlns:b=\"y\" c=\"4\" q=\"1\" b:x=\"3\" a:x=\"2\"></r>", Canon("<r xmlns:a=\"z\" xmlns:b=\"y\" q=\"1\" a:x=\"2\" b:x=\"3\" c=\"4\"/>"));
        Assert.Equal("<r xmlns:a=\"z\" a:x=\"1\" a:y=\"2\"></r>", Canon("<r xmlns:a=\"z\" a:y=\"2\" a:x=\"1\"/>"));
        // one namespace, two prefixes: the local name decides, not the qualified name
        Assert.Equal("<r xmlns:a=\"u\" xmlns:p=\"u\" p:a=\"1\" a:b=\"2\"></r>", Canon("<r xmlns:p=\"u\" xmlns:a=\"u\" a:b=\"2\" p:a=\"1\"/>"));
    }

    [Fact]
    public void ABindingIsRenderedOnceAndAnEmptyDefaultOnlyToUndeclare()
    {
        Assert.Equal("<r xmlns:p=\"u\"><b></b></r>", Canon("<r xmlns:p=\"u\"><b/></r>"));
        Assert.Equal("<r xmlns:p=\"u\"><b></b></r>", Canon("<r xmlns:p=\"u\"><b xmlns:p=\"u\"/></r>"));
        Assert.Equal("<r xmlns=\"u\"><b></b></r>", Canon("<r xmlns=\"u\"><b/></r>"));
        Assert.Equal("<r></r>", Canon("<r xmlns=\"\"/>"));
        Assert.Equal("<r xmlns=\"u\"><b xmlns=\"\"></b></r>", Canon("<r xmlns=\"u\"><b xmlns=\"\"/></r>"));
        Assert.Throws<AttestError>(() => Canon("<r xmlns:q=\"u\"><b xmlns:q=\"\"/></r>")); // a prefix redeclared to another URI is refused
        Assert.Equal("<r xmlns:q=\"\"></r>", Canon("<r xmlns:q=\"\"/>")); // as the reference renders it
    }

    [Fact]
    public void AnExplicitXmlDeclarationIsRenderedLikeTheReference() =>
        Assert.Equal("<r xmlns:xml=\"http://www.w3.org/XML/1998/namespace\"></r>", Canon("<r xmlns:xml=\"http://www.w3.org/XML/1998/namespace\"/>"));

    [Fact]
    public void AnApexElementRendersTheBindingsOfItsAncestorsAndSkipIsOmitted()
    {
        var r = R("<r xmlns:p=\"u\"><c/><d/></r>");
        var c = r.ElementChildren()[0];
        Assert.Equal("<c xmlns:p=\"u\"></c>", AttestXml.Canonicalize(c, c.Parent!.Scope(), null));
        Assert.Equal("<r xmlns:p=\"u\"><d></d></r>", AttestXml.Canonicalize(r, new Dictionary<string, string>(StringComparer.Ordinal), c));
    }
}
