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
        assert locs == ["https://security.example.com/"]

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
