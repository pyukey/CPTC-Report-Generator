#!/usr/bin/env python3

from __future__ import annotations

import sys
from html.parser import HTMLParser


TEXT_ESCAPE_MAP = {
    "&": r"\&",
    "%": r"\%",
    "$": r"\$",
    "#": r"\#",
    "_": r"\_",
    "{": r"\{",
    "}": r"\}",
    "~": r"\textasciitilde{}",
    "^": r"\textasciicircum{}",
}

URL_ESCAPE_MAP = {
    "%": r"\%",
    "#": r"\#",
    "&": r"\&",
    "{": r"\{",
    "}": r"\}",
}


def escape_latex_text(text: str) -> str:
    pieces: list[str] = []
    i = 0

    while i < len(text):
        ch = text[i]

        # Preserve existing LaTeX commands and already-escaped characters.
        if ch == "\\":
            if i + 1 < len(text):
                nxt = text[i + 1]
                if nxt.isalpha():
                    j = i + 2
                    while j < len(text) and text[j].isalpha():
                        j += 1
                    pieces.append(text[i:j])
                    i = j
                    continue
                if nxt in TEXT_ESCAPE_MAP or nxt in ["\\", " ", "[", "]"]:
                    pieces.append(text[i:i + 2])
                    i += 2
                    continue

            pieces.append(r"\textbackslash{}")
            i += 1
            continue

        pieces.append(TEXT_ESCAPE_MAP.get(ch, ch))
        i += 1

    return "".join(pieces)


def escape_latex_url(url: str) -> str:
    pieces: list[str] = []
    i = 0
    while i < len(url):
        ch = url[i]
        if ch == "\\" and i + 1 < len(url) and url[i + 1] in {"%", "#", "&", "{", "}", "_"}:
            pieces.append(url[i : i + 2])
            i += 2
            continue
        if ch == "\\":
            pieces.append(r"\textbackslash{}")
        else:
            pieces.append(URL_ESCAPE_MAP.get(ch, ch))
        i += 1
    return "".join(pieces)


class HtmlToLatexParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self.pre_parts: list[str] = []
        self.in_pre = False
        self.in_inline_code = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr_map = dict(attrs)

        if tag == "div":
            return
        if tag == "br":
            self.parts.append("\\bigskip\n")
            return
        if tag in {"b", "strong"}:
            self.parts.append(r"\textbf{")
            return
        if tag in {"i", "em"}:
            self.parts.append(r"\textit{")
            return
        if tag == "ul":
            self.parts.append("\\begin{itemize}\n")
            return
        if tag == "ol":
            self.parts.append("\\begin{enumerate}\n")
            return
        if tag == "li":
            self.parts.append("\\item ")
            return
        if tag == "pre":
            self.in_pre = True
            self.pre_parts = []
            return
        if tag == "code":
            if self.in_pre:
                return
            self.in_inline_code = True
            self.parts.append(r"\texttt{\detokenize{")
            return
        if tag == "a":
            href = escape_latex_url(attr_map.get("href") or "")
            self.parts.append(f"\\href{{{href}}}{{")
            return

    def handle_endtag(self, tag: str) -> None:
        if tag == "div":
            self.parts.append("\n\n")
            return
        if tag in {"b", "strong", "i", "em", "a"}:
            self.parts.append("}")
            return
        if tag == "ul":
            self.parts.append("\n\\end{itemize}")
            return
        if tag == "ol":
            self.parts.append("\n\\end{enumerate}")
            return
        if tag == "pre":
            content = "".join(self.pre_parts).strip("\n")
            self.parts.append("\\begin{verbatim}\n")
            self.parts.append(content)
            self.parts.append("\n\\end{verbatim}\n")
            self.in_pre = False
            self.pre_parts = []
            return
        if tag == "code" and not self.in_pre:
            self.in_inline_code = False
            self.parts.append("}}")

    def handle_data(self, data: str) -> None:
        data = data.replace("\xa0", " ")
        if self.in_pre:
            self.pre_parts.append(data)
            return
        if self.in_inline_code:
            self.parts.append(data)
            return
        self.parts.append(escape_latex_text(data))

    def get_output(self) -> str:
        rendered = "".join(self.parts)
        lines = [line.rstrip() for line in rendered.splitlines()]
        return "\n".join(lines).strip() + ("\n" if rendered else "")


def main() -> int:
    parser = HtmlToLatexParser()
    parser.feed(sys.stdin.read())
    parser.close()
    sys.stdout.write(parser.get_output())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
