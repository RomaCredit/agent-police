"""Discoverability surface: crawler files, metadata, and structured data.

The FAQPage assertions are the point of this file. Structured data that
describes content the page does not actually show is a search-guideline
violation and, more to the point, a lie about the page - so the questions in
the JSON-LD are checked against the questions rendered in the HTML.
"""

import json
import re
import tempfile
from pathlib import Path
from typing import ClassVar

import pytest
from fastapi.testclient import TestClient

from agentpolice.server import app as app_module

STATIC = Path(app_module.__file__).parent / "static"


@pytest.fixture
def client():
    return TestClient(app_module.create_app(
        canary_db=str(Path(tempfile.mkdtemp()) / "c.db"),
        canary_base="https://security.example.com", canary_dns=None))


@pytest.fixture(scope="module")
def html():
    return (STATIC / "index.html").read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def gate_html():
    return (STATIC / "gate.html").read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def gate_ld(gate_html):
    block = re.search(
        r'<script type="application/ld\+json">(.*?)</script>', gate_html, re.DOTALL)
    assert block, "no JSON-LD block on the gate page"
    return json.loads(block.group(1))


@pytest.fixture(scope="module")
def ld(html):
    block = re.search(
        r'<script type="application/ld\+json">(.*?)</script>', html, re.DOTALL)
    assert block, "no JSON-LD block in the page"
    return json.loads(block.group(1))


class TestCrawlerFiles:
    def test_robots_points_at_the_sitemap(self, client):
        body = client.get("/robots.txt").text
        assert "Sitemap: https://security.example.com/sitemap.xml" in body

    def test_robots_keeps_crawlers_out_of_the_canary_path(self, client):
        # A crawler fetching a canary URL would record a hit that means
        # nothing: the evidence has to come from whoever harvested the token.
        body = client.get("/robots.txt").text
        assert "Disallow: /c/" in body
        assert "Disallow: /api/" in body

    def test_sitemap_is_well_formed_xml(self, client):
        import xml.etree.ElementTree as ET
        res = client.get("/sitemap.xml")
        assert res.status_code == 200
        assert "xml" in res.headers["content-type"]
        root = ET.fromstring(res.text)
        locs = [e.text for e in root.iter("{http://www.sitemaps.org/schemas/sitemap/0.9}loc")]
        assert locs == ["https://security.example.com/",
                        "https://security.example.com/en",
                        "https://security.example.com/gate",
                        "https://security.example.com/gate/en"]

    def test_crawler_files_follow_the_configured_host(self):
        """A deployment on another host must not advertise this one."""
        other = TestClient(app_module.create_app(
            canary_db=str(Path(tempfile.mkdtemp()) / "c.db"),
            canary_base="https://elsewhere.test", canary_dns=None))
        assert "elsewhere.test/sitemap.xml" in other.get("/robots.txt").text
        assert "https://elsewhere.test/" in other.get("/sitemap.xml").text


class TestPageMetadata:
    def test_has_canonical_and_description(self, html):
        assert '<link rel="canonical"' in html
        desc = re.search(r'<meta name="description" content="([^"]+)"', html)
        assert desc and 60 < len(desc.group(1)) < 320

    def test_has_open_graph(self, html):
        for prop in ("og:type", "og:url", "og:title", "og:description"):
            assert f'property="{prop}"' in html, prop

    def test_declares_language(self, html):
        assert '<html lang="zh-CN">' in html


class TestStructuredData:
    def test_software_application_points_at_real_places(self, ld):
        app = next(n for n in ld["@graph"] if n["@type"] == "SoftwareApplication")
        assert app["name"] == "agent-police"
        assert app["downloadUrl"] == "https://pypi.org/project/agent-police/"
        assert app["codeRepository"] == "https://github.com/RomaCredit/agent-police"
        assert app["citation"]["identifier"] == "arXiv:2604.08407"

    def test_faq_questions_are_actually_on_the_page(self, ld, html):
        """Structured data must describe content a visitor can see."""
        faq = next(n for n in ld["@graph"] if n["@type"] == "FAQPage")
        assert len(faq["mainEntity"]) >= 5
        for item in faq["mainEntity"]:
            question = item["name"]
            assert question in html, f"FAQ question not rendered on the page: {question}"

    def test_faq_answers_are_substantive(self, ld):
        """Guard against one-line answers, which are not worth marking up.

        The floor is in characters and the page is Chinese, where a character
        carries far more than a Latin one: 60 here is a paragraph, not a
        sentence fragment. Raising it further would only invite padding an
        answer that is already complete.
        """
        faq = next(n for n in ld["@graph"] if n["@type"] == "FAQPage")
        for item in faq["mainEntity"]:
            answer = item["acceptedAnswer"]["text"]
            assert len(answer) > 60, item["name"]

    def test_the_caveat_survives_in_structured_data(self, ld):
        """The "a clean scan is not proof" answer is the one most worth losing
        to an optimisation pass, so it is pinned here."""
        faq = next(n for n in ld["@graph"] if n["@type"] == "FAQPage")
        answers = " ".join(i["acceptedAnswer"]["text"] for i in faq["mainEntity"])
        assert "无法证明" in answers
        assert "绝不会" in answers  # nothing returned by the endpoint is executed


class TestGatePage:
    """The /gate page describes a second tool, so its claims are pinned too."""

    def test_gate_page_is_served(self, client):
        res = client.get("/gate")
        assert res.status_code == 200
        assert "agent-police-gate" in res.text

    def test_robots_allows_the_gate_page(self, client):
        assert "Allow: /gate" in client.get("/robots.txt").text

    def test_has_its_own_canonical(self, gate_html):
        assert '<link rel="canonical" href="https://security.romaapi.com/gate">' in gate_html

    def test_points_at_the_right_package_and_repo(self, gate_ld):
        app = next(n for n in gate_ld["@graph"] if n["@type"] == "SoftwareApplication")
        assert app["name"] == "agent-police-gate"
        assert app["downloadUrl"] == "https://pypi.org/project/agent-police-gate/"
        assert app["codeRepository"] == "https://github.com/RomaCredit/agent-police-gate"

    def test_faq_questions_are_actually_on_the_page(self, gate_ld, gate_html):
        faq = next(n for n in gate_ld["@graph"] if n["@type"] == "FAQPage")
        assert len(faq["mainEntity"]) >= 5
        for item in faq["mainEntity"]:
            assert item["name"] in gate_html, f"FAQ question not rendered: {item['name']}"

    def test_the_limits_survive_in_structured_data(self, gate_ld):
        """The two claims most worth losing to an optimisation pass.

        A page selling a security tool has every incentive to drop "it cannot
        see what the model actually said" and "an adaptive attacker bypasses
        this 100% of the time". Both are pinned here.
        """
        faq = next(n for n in gate_ld["@graph"] if n["@type"] == "FAQPage")
        answers = " ".join(i["acceptedAnswer"]["text"] for i in faq["mainEntity"])
        assert "从来没见过模型真正产出的那一条" in answers
        assert "100% 失效" in answers
        assert "社区规则永不拦截" in answers

    def test_page_states_code_does_not_auto_update(self, gate_html):
        """The split between auto-updating rules and manually-updated code.

        Asserted on both pages because it is the security claim a redesign is
        most likely to smooth away: it is the one promise that makes an
        auto-updating channel defensible at all.
        """
        # Fullwidth punctuation is correct here; the question is asserted
        # exactly as the page renders it.
        assert "客户端代码会自动升级吗？" in gate_html  # noqa: RUF001
        assert "只有规则自动更新" in gate_html

        en = (STATIC / "en" / "gate.html").read_text(encoding="utf-8")
        assert "Does the client code auto-update?" in en
        assert "Only rules update automatically" in en


class TestBilingual:
    """Two languages, two crawlable URLs, and the links between them.

    The switch in the header is a plain link rather than a JS toggle so each
    language has its own canonical and can be indexed on its own. That only
    pays off if the hreflang annotations actually agree with each other, which
    is what most of this class checks.
    """

    PAGES: ClassVar[dict] = {
        "/": ("zh-CN", STATIC / "index.html"),
        "/en": ("en", STATIC / "en" / "index.html"),
        "/gate": ("zh-CN", STATIC / "gate.html"),
        "/gate/en": ("en", STATIC / "en" / "gate.html"),
    }

    @pytest.mark.parametrize("path", list(PAGES))
    def test_every_page_is_served(self, client, path):
        res = client.get(path)
        assert res.status_code == 200, path
        assert "agent-police" in res.text

    @pytest.mark.parametrize("path", list(PAGES))
    def test_declares_its_own_language(self, path):
        lang, source = self.PAGES[path]
        assert f'<html lang="{lang}">' in source.read_text(encoding="utf-8")

    @pytest.mark.parametrize("path", list(PAGES))
    def test_canonical_is_self_referential(self, path):
        _, source = self.PAGES[path]
        html = source.read_text(encoding="utf-8")
        expected = f'<link rel="canonical" href="https://security.romaapi.com{path}">'
        assert expected in html, f"{path} canonical does not point at itself"

    def test_hreflang_pairs_are_reciprocal(self):
        """zh must point at en and en must point back at the same zh.

        A one-way annotation is the classic way a bilingual site ends up with
        the two versions competing with each other instead of consolidating.
        """
        for zh, en in (("/", "/en"), ("/gate", "/gate/en")):
            zh_html = self.PAGES[zh][1].read_text(encoding="utf-8")
            en_html = self.PAGES[en][1].read_text(encoding="utf-8")
            zh_url = f"https://security.romaapi.com{zh}"
            en_url = f"https://security.romaapi.com{en}"
            for html, where in ((zh_html, zh), (en_html, en)):
                assert f'hreflang="zh-CN" href="{zh_url}"' in html, where
                assert f'hreflang="en" href="{en_url}"' in html, where
                assert f'hreflang="x-default" href="{zh_url}"' in html, where

    @pytest.mark.parametrize("path", list(PAGES))
    def test_language_switch_links_to_the_counterpart(self, path):
        _, source = self.PAGES[path]
        html = source.read_text(encoding="utf-8")
        counterpart = {"/": "/en", "/en": "/", "/gate": "/gate/en", "/gate/en": "/gate"}[path]
        assert 'class="langswitch"' in html, path
        assert f'href="{counterpart}"' in html, f"{path} does not link to {counterpart}"
        assert 'aria-current="true"' in html, path

    def test_sitemap_declares_the_alternates(self, client):
        body = client.get("/sitemap.xml").text
        assert 'xmlns:xhtml="http://www.w3.org/1999/xhtml"' in body
        assert body.count('hreflang="en"') == 4
        assert body.count('hreflang="x-default"') == 4

    def test_robots_allows_both_languages(self, client):
        body = client.get("/robots.txt").text
        for path in ("Allow: /en", "Allow: /gate", "Allow: /gate/en"):
            assert path in body


class TestRuntimeStrings:
    """Findings are rendered in JS, so the string table is part of the page."""

    def test_both_languages_define_the_same_keys(self):
        """A key present in one table and missing in the other renders the raw
        key id to a user. Cheaper to catch here than in a screenshot."""
        js = (STATIC / "i18n.js").read_text(encoding="utf-8")
        zh_block = js.split("'zh-CN': {", 1)[1].split("\n  },", 1)[0]
        en_block = js.split("en: {", 1)[1].split("\n  },", 1)[0]
        def keys(block):
            return set(re.findall(r"'([a-z][a-z.]+)':", block))

        zh_keys, en_keys = keys(zh_block), keys(en_block)
        assert zh_keys, "no keys parsed from the zh table"
        assert zh_keys == en_keys, (
            f"only in zh: {sorted(zh_keys - en_keys)}; "
            f"only in en: {sorted(en_keys - zh_keys)}")

    def test_app_js_holds_no_hardcoded_chinese(self):
        """Every user-facing string must come from the table, or the English
        page renders Chinese verdicts."""
        js = (STATIC / "app.js").read_text(encoding="utf-8")
        assert not re.search(r"[一-鿿]", js), \
            "app.js still contains Chinese literals; move them into i18n.js"

    def test_english_page_loads_the_string_table_before_the_app(self):
        html = (STATIC / "en" / "index.html").read_text(encoding="utf-8")
        assert html.index("i18n.js") < html.index("app.js")
