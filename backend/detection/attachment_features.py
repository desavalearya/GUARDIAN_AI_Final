"""Feature extraction for Office and PDF attachments.

The trained models expect features with specific semantics:

* The Office model (Zenodo MSOffice VBA macro dataset) expects binary flags for
  VBA keywords found in *macro source code*. Scanning the whole file is wrong for
  OOXML formats, which are ZIP archives: deflate-compressed bytes match short
  tokens like ``run(`` or ``windows`` by chance and fabricate macro hits.
* The PDF model (CIC-Evasive-PDFMal2022) expects PDFiD-style structural counts,
  with ``PdfSize`` in kilobytes and ``MetadataSize`` in bytes.
"""

from __future__ import annotations

import io
import logging
import re
import zipfile
from typing import Any

log = logging.getLogger(__name__)

__all__ = [
    "OfficeExtraction",
    "PdfExtraction",
    "extract_office_features",
    "extract_pdf_features",
]


# ---------------------------------------------------------------------------
# Office
# ---------------------------------------------------------------------------

# Maps a feature name from office_feature_order.json to the regexes that mark it
# as present in VBA source. Feature names carry a leading space in the dataset,
# so callers must match them exactly.
_VBA_PATTERNS: dict[str, tuple[str, ...]] = {
    " autoopen": (r"\bauto_?open\b",),
    " auto_open": (r"\bauto_open\b",),
    " document_open": (r"\bdocument_open\b",),
    " workbook_open": (r"\bworkbook_open\b",),
    " document_close": (r"\bdocument_close\b",),
    " shell": (r"\bshell\s*\(", r"\bshell\s+\""),
    " shellexecute": (r"\bshellexecute\b",),
    " shell.application": (r"shell\.application",),
    " wscript.shell": (r"wscript\.shell",),
    " createobject": (r"\bcreateobject\s*\(",),
    " call": (r"\bcall\s+\w",),
    " callbyname": (r"\bcallbyname\s*\(",),
    " showwindow": (r"\bshowwindow\b",),
    " vbhide": (r"\bvbhide\b",),
    " chr": (r"\bchr\s*\(",),
    " chrb": (r"\bchrb\s*\(",),
    " chrw": (r"\bchrw\s*\(",),
    " strreverse": (r"\bstrreverse\s*\(",),
    " xor": (r"\bxor\b",),
    " run": (r"\.run\b", r"\brun\s*\(",),
    " environ": (r"\benviron\s*\(",),
    " createtextfile": (r"\bcreatetextfile\b",),
    " savetofile": (r"\bsavetofile\b",),
    " executeexcel4macro": (r"\bexecuteexcel4macro\b",),
    " activeworkbook.saveas": (r"activeworkbook\.saveas",),
    " filecopy": (r"\bfilecopy\b",),
    " kill": (r"\bkill\s+\w",),
    " output": (r"\bfor\s+output\b", r"\boutput\b\s*$"),
    " print": (r"\bprint\s*#",),
    " system": (r"\bsystem\b",),
    " windows": (r"\bwindows\b",),
    " write": (r"\bfor\s+write\b", r"\bwrite\s*#"),
    " open": (r"\bopen\s+\"", r"\.open\b"),
    " lib": (r"\blib\s+\"",),
    " virtual": (r"\bvirtual(alloc|protect|free)\b", r"\bvirtual\b"),
    " binary": (r"\bfor\s+binary\b", r"\bbinary\b"),
    "dde": (r"\bdde(auto)?\b",),
    " vba stomping": (r"\bvba\s*stomp",),
    "base64 strings": (r"\bbase64\b", r"frombase64string"),
    " hex strings": (r"\bhex\s*\(", r"\bchr\$\s*\(", r"&h[0-9a-f]{2,}"),
}

# ZIP members that carry a VBA project in OOXML documents.
_OOXML_VBA_MEMBERS = ("vbaproject.bin", "vbadata.xml")

# OLE storage/stream names that indicate a VBA project in legacy formats.
_OLE_VBA_MARKERS = (b"VBA", b"Macros", b"_VBA_PROJECT", b"dir")


class OfficeExtraction:
    """Result of Office feature extraction."""

    def __init__(
        self,
        features: dict[str, float],
        *,
        container: str,
        has_macros: bool,
        macro_source_bytes: int,
        extraction_method: str,
        notes: list[str],
    ) -> None:
        self.features = features
        self.container = container
        self.has_macros = has_macros
        self.macro_source_bytes = macro_source_bytes
        self.extraction_method = extraction_method
        self.notes = notes

    def as_meta(self) -> dict[str, Any]:
        return {
            "container": self.container,
            "has_macros": self.has_macros,
            "macro_source_bytes": self.macro_source_bytes,
            "extraction_method": self.extraction_method,
            "notes": self.notes,
        }


def _macro_source_via_olevba(content: bytes, filename: str) -> tuple[str, str] | None:
    """Return (source, method) using oletools.olevba, or None if unavailable."""
    try:
        from oletools.olevba import VBA_Parser
    except ImportError:
        return None

    parser = None
    try:
        parser = VBA_Parser(filename or "attachment", data=content)
        if not parser.detect_vba_macros():
            return "", "olevba (no macros)"
        chunks = [
            code for _, _, _, code in parser.extract_macros() if code
        ]
        return "\n".join(chunks), "olevba"
    except Exception as exc:  # noqa: BLE001 - malformed documents are expected
        log.warning("olevba extraction failed for %s: %s", filename, exc)
        return None
    finally:
        if parser is not None:
            try:
                parser.close()
            except Exception:  # noqa: BLE001
                pass


def _ooxml_macro_bytes(content: bytes) -> tuple[bytes, list[str], bool]:
    """Pull VBA project bytes out of an OOXML (ZIP) document."""
    notes: list[str] = []
    try:
        with zipfile.ZipFile(io.BytesIO(content)) as zf:
            members = zf.namelist()
            vba_members = [
                n for n in members if n.lower().rsplit("/", 1)[-1] in _OOXML_VBA_MEMBERS
            ]
            if not vba_members:
                notes.append(
                    f"OOXML archive with {len(members)} parts and no vbaProject.bin"
                )
                return b"", notes, False
            notes.append(f"VBA project parts: {', '.join(vba_members)}")
            blob = b"".join(zf.read(n) for n in vba_members)
            return blob, notes, True
    except zipfile.BadZipFile:
        notes.append("not a valid OOXML archive")
        return b"", notes, False


def _ole_macro_bytes(content: bytes) -> tuple[bytes, list[str], bool]:
    """Detect a VBA project inside a legacy OLE document."""
    notes: list[str] = []
    try:
        import olefile

        if not olefile.isOleFile(io.BytesIO(content)):
            notes.append("not an OLE container")
            return b"", notes, False

        ole = olefile.OleFileIO(io.BytesIO(content))
        try:
            streams = ["/".join(p) for p in ole.listdir()]
            vba_streams = [s for s in streams if "vba" in s.lower() or "macro" in s.lower()]
            if not vba_streams:
                notes.append(f"OLE container with {len(streams)} streams and no VBA storage")
                return b"", notes, False
            notes.append(f"VBA streams: {', '.join(vba_streams[:8])}")
            blob = b""
            for s in vba_streams:
                try:
                    blob += ole.openstream(s).read()
                except Exception:  # noqa: BLE001
                    continue
            return blob, notes, True
        finally:
            ole.close()
    except ImportError:
        notes.append("olefile unavailable")
        return b"", notes, False
    except Exception as exc:  # noqa: BLE001
        notes.append(f"OLE parse error: {exc}")
        return b"", notes, False


def extract_office_features(
    content: bytes, filename: str, feature_names: list[str]
) -> OfficeExtraction:
    """Extract VBA-macro features from an Office document.

    Only genuine macro source is scanned. A document with no VBA project yields an
    all-zero vector, which is the correct input for a macro-trained model.
    """
    features = {name: 0.0 for name in feature_names}
    notes: list[str] = []

    is_zip = content[:2] == b"PK"
    is_ole = content[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
    container = "OOXML (ZIP)" if is_zip else "OLE (legacy)" if is_ole else "unknown"

    # Preferred path: oletools decompresses VBA source properly.
    olevba = _macro_source_via_olevba(content, filename)
    if olevba is not None:
        source, method = olevba
        has_macros = bool(source.strip())
        if not has_macros:
            notes.append("olevba found no VBA macros")
    else:
        method = "raw VBA project scan (oletools unavailable)"
        if is_zip:
            blob, zip_notes, has_macros = _ooxml_macro_bytes(content)
        elif is_ole:
            blob, zip_notes, has_macros = _ole_macro_bytes(content)
        else:
            blob, zip_notes, has_macros = content, ["unrecognised container"], True
        notes.extend(zip_notes)
        # VBA project streams are MS-OVBA compressed; literal keywords still survive
        # often enough to be a usable fallback signal.
        source = blob.decode("latin-1", errors="ignore")

    source_lower = source.lower()
    if has_macros and source_lower:
        for feature, patterns in _VBA_PATTERNS.items():
            if feature not in features:
                continue
            for pattern in patterns:
                if re.search(pattern, source_lower, flags=re.MULTILINE):
                    features[feature] = 1.0
                    break

    return OfficeExtraction(
        features,
        container=container,
        has_macros=has_macros,
        macro_source_bytes=len(source.encode("latin-1", errors="ignore")),
        extraction_method=method,
        notes=notes,
    )


# ---------------------------------------------------------------------------
# PDF
# ---------------------------------------------------------------------------


class PdfExtraction:
    """Result of PDF feature extraction."""

    def __init__(self, features: dict[str, float], notes: list[str]) -> None:
        self.features = features
        self.notes = notes

    def as_meta(self) -> dict[str, Any]:
        return {"notes": self.notes}


def _pdf_string_length(raw: str) -> int:
    """Length in characters of a PDF string literal or hex string."""
    raw = raw.strip()
    if raw.startswith("<") and raw.endswith(">"):
        hex_digits = re.sub(r"[^0-9a-fA-F]", "", raw[1:-1])
        data = bytes.fromhex(hex_digits[: len(hex_digits) // 2 * 2])
        if data[:2] in (b"\xfe\xff", b"\xff\xfe"):
            return max(0, (len(data) - 2) // 2)
        return len(data)
    if raw.startswith("(") and raw.endswith(")"):
        inner = raw[1:-1]
        inner = re.sub(r"\\([nrtbf()\\])", "x", inner)
        return len(inner)
    return len(raw)


def _metadata_size(text: str) -> tuple[float, str]:
    """Size in bytes of the document metadata, PDFiD-style."""
    packet = re.search(r"<\?xpacket begin=.*?<\?xpacket end=.*?\?>", text, flags=re.DOTALL)
    if packet:
        return float(len(packet.group(0))), "XMP packet measured"

    ref = re.search(r"/Metadata\s+(\d+)\s+(\d+)\s+R", text)
    if ref:
        obj_num = ref.group(1)
        obj = re.search(
            rf"(?<!\d){obj_num}\s+0\s+obj(.*?)endobj", text, flags=re.DOTALL
        )
        if obj:
            length = re.search(r"/Length\s+(\d+)", obj.group(1))
            if length:
                return float(length.group(1)), "/Metadata stream /Length"
            return float(len(obj.group(1))), "/Metadata object body length"
        return 0.0, "/Metadata reference present but object not found"

    if "/Metadata" in text:
        return 0.0, "/Metadata key present but unparseable"
    return 0.0, "no /Metadata or XMP packet in document"


def _xref_length(text: str) -> tuple[float, str]:
    """Byte length of the cross-reference section."""
    table = re.search(r"\bxref\b(.*?)\btrailer\b", text, flags=re.DOTALL)
    if table:
        return float(len(table.group(1))), "classic xref table measured"

    xref_stream = re.search(
        r"/Type\s*/XRef(.*?)stream", text, flags=re.DOTALL
    )
    if xref_stream:
        length = re.search(r"/Length\s+(\d+)", xref_stream.group(1))
        if length:
            return float(length.group(1)), "xref stream /Length (PDF 1.5+)"
        size = re.search(r"/Size\s+(\d+)", xref_stream.group(1))
        if size:
            return float(size.group(1)), "xref stream /Size (PDF 1.5+)"
    return 0.0, "no cross-reference section found"


def _page_count(content: bytes, text: str) -> tuple[float, str]:
    try:
        import PyPDF2

        reader = PyPDF2.PdfReader(io.BytesIO(content), strict=False)
        return float(len(reader.pages)), "PyPDF2 page count"
    except Exception:  # noqa: BLE001 - fall back to token counting
        pass

    counts = re.findall(r"/Type\s*/Page[^s]", text)
    if counts:
        return float(len(counts)), "/Type /Page token count"
    tree = re.search(r"/Type\s*/Pages.*?/Count\s+(\d+)", text, flags=re.DOTALL)
    if tree:
        return float(tree.group(1)), "page tree /Count"
    return 0.0, "page count unavailable"


_V3_PDF_FEATURES = {
    "isencrypted",
    "embeddedfiles",
    "images",
    "text",
    "header",
    "obj",
    "endobj",
    "stream",
    "endstream",
    "xref",
    "trailer",
    "startxref",
    "encrypt",
    "objstm",
    "js",
    "javascript",
    "aa",
    "openaction",
    "launch",
    "acroform",
    "xfa",
    "jbig2decode",
    "richmedia",
    "embeddedfile",
    "colors",
}


def _extract_pdf_features_v3(content: bytes, feature_names: list[str]) -> PdfExtraction:
    """PDFiD-style counts used by models/PDF_v3 (no PdfSize/MetadataSize)."""
    features = {name: 0.0 for name in feature_names}
    notes: list[str] = ["extractor=pdfid-v3"]
    text = content.decode("latin-1", errors="ignore")
    low = text.lower()

    def count(token: str) -> float:
        return float(low.count(token.lower()))

    features["header"] = 1.0 if "%pdf" in low[:1024] else 0.0
    features["obj"] = count("obj")
    features["endobj"] = count("endobj")
    features["stream"] = count("stream")
    features["endstream"] = count("endstream")
    features["xref"] = count("xref")
    features["trailer"] = count("trailer")
    features["startxref"] = count("startxref")
    features["encrypt"] = count("/encrypt")
    features["isencrypted"] = 1.0 if features.get("encrypt", 0) > 0 else 0.0
    features["objstm"] = count("/objstm")
    features["js"] = count("/js")
    features["javascript"] = count("/javascript")
    features["aa"] = float(max(0.0, count("/aa") - count("/aaa")))
    features["openaction"] = count("/openaction")
    features["launch"] = count("/launch")
    features["acroform"] = count("/acroform")
    features["xfa"] = count("/xfa")
    features["jbig2decode"] = count("/jbig2decode")
    features["richmedia"] = count("/richmedia")
    features["embeddedfile"] = count("/embeddedfile")
    features["embeddedfiles"] = count("/embeddedfiles") + features.get("embeddedfile", 0.0)
    features["images"] = count("/image") + count("/xobject")
    features["text"] = count("/font")
    features["colors"] = count("/colors") + count("/colorspace")

    fired = [k for k in ("js", "javascript", "openaction", "launch", "embeddedfile") if features.get(k, 0)]
    if fired:
        notes.append("attack-ish tokens: " + ", ".join(fired))
    return PdfExtraction({k: features.get(k, 0.0) for k in feature_names}, notes)


def extract_pdf_features(content: bytes, feature_names: list[str]) -> PdfExtraction:
    """Extract PDF features in the schema the loaded model was trained on."""
    if feature_names and set(feature_names) <= _V3_PDF_FEATURES or (
        feature_names and "javascript" in feature_names and "PdfSize" not in feature_names
    ):
        return _extract_pdf_features_v3(content, feature_names)

    features = {name: 0.0 for name in feature_names}
    notes: list[str] = []
    text = content.decode("latin-1", errors="ignore")

    def count(token: str) -> float:
        return float(text.count(token))

    # PdfSize is in kilobytes in the training data, not bytes.
    features["PdfSize"] = len(content) / 1024.0

    metadata_size, metadata_note = _metadata_size(text)
    features["MetadataSize"] = metadata_size
    notes.append(f"MetadataSize: {metadata_note}")

    pages, page_note = _page_count(content, text)
    features["Pages"] = pages
    notes.append(f"Pages: {page_note}")

    xref_len, xref_note = _xref_length(text)
    features["XrefLength"] = xref_len
    notes.append(f"XrefLength: {xref_note}")

    title = re.search(r"/Title\s*(\([^)]*\)|<[0-9a-fA-F\s]*>)", text)
    if title:
        features["TitleCharacters"] = float(_pdf_string_length(title.group(1)))
        notes.append("TitleCharacters: /Title parsed from document info")
    else:
        notes.append("TitleCharacters: no /Title entry")

    encrypted = "/Encrypt" in text
    features["isEncrypted"] = 1.0 if encrypted else 0.0
    features["Encrypt"] = count("/Encrypt")

    features["EmbeddedFiles"] = count("/EmbeddedFile")

    # PDFiD counts `stream` and `endstream` separately, so subtract the overlap.
    features["Stream"] = max(0.0, count("stream") - count("endstream"))
    features["Trailer"] = count("trailer")
    if features["Trailer"] == 0.0:
        notes.append(
            "Trailer: 0 - document uses cross-reference streams (PDF 1.5+), "
            "which have no literal 'trailer' keyword"
        )

    features["ObjStm"] = count("/ObjStm")
    features["Colors"] = count("/Colors")

    return PdfExtraction(features, notes)
