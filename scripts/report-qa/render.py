"""Render one HTML report without browser execution or external asset access."""
import hashlib
import json
from pathlib import Path
import re
import sys

import tinycss2
from weasyprint import CSS, HTML

source = Path(sys.argv[1]).read_text()
source_hash = hashlib.sha256(source.encode()).hexdigest()
out = Path(sys.argv[2])
width, height = int(sys.argv[3]), int(sys.argv[4])


def media(css):
    # Resolve only the known viewport-width query; reject unexpected additions.
    result = []
    for rule in tinycss2.parse_stylesheet(css, skip_comments=True, skip_whitespace=True):
        if rule.type == "at-rule" and rule.lower_at_keyword == "media":
            condition = tinycss2.serialize(rule.prelude).strip()
            if condition in ["(max-width:760px)", "(max-width: 760px)"]:
                if width <= 760:
                    result.append(tinycss2.serialize(rule.content))
            elif condition != "print":
                raise ValueError("Unknown media query: " + condition)
        else:
            result.append(tinycss2.serialize([rule]))
    return "\n".join(result)


source = re.sub(r"<style>(.*?)</style>", lambda m: "<style>" + media(m[1]) + "</style>",
                source, flags=re.S)
attempts = []


def no_assets(url, *args, **kwargs):
    attempts.append(url)
    raise ValueError("Asset loading disabled")


doc = HTML(string=source, url_fetcher=no_assets, media_type="screen").render(
    stylesheets=[CSS(string=f"@page {{size:{width}px {height}px;margin:0}}")])
assert not attempts, attempts
assert len(doc.pages) == 1, "Increase QA canvas height"
doc.write_pdf(out)
boxes, blocks = [], []
seen_elements = set()
for box in doc.pages[0]._page_box.descendants():
    if box.__class__.__name__ == "TextBox":
        boxes.append({"text": box.text, "x": round(box.position_x, 2),
                      "y": round(box.position_y, 2), "width": round(box.width, 2),
                      "height": round(box.height, 2)})
    if (box.__class__.__name__ == "BlockBox" and box.element_tag in ["article", "h2"]
            and box.element not in seen_elements):
        seen_elements.add(box.element)
        blocks.append({"tag": box.element_tag, "id": box.element.get("id"),
                       "x": box.border_box_x(), "y": box.border_box_y(),
                       "width": box.border_width(), "height": box.border_height()})
Path(str(out) + ".json").write_text(json.dumps({
    "renderer": "WeasyPrint 66.0", "input_sha256": source_hash,
    "width": width, "height": height, "network_attempts": attempts,
    "text_boxes": boxes, "blocks": blocks}, indent=2) + "\n")
