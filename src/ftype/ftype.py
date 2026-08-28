#!/usr/bin/env python3
"""
Analyze what programming lanugages a project uses
"""

# TODO Refactor using major packages, e.g. mimetypes, filetype, or python-magic
# TODO Remove Java
# TODO Add other file types, e.g. Excel, Word, database

import argparse
import os
import re
import sys
import typing
from pathlib import Path


class FileType:
    def __init__(self, path: Path):
        self.path = path
        self.unknown = None
        self.unclassifiable = None

    FILE_TYPES: typing.ClassVar = {
        ".bash": "Shell",
        ".c": "C",
        ".cc": "C++",
        ".code-workspace": "VSCode Workspace",
        ".cpp": "C++",
        ".erb": "Template",
        ".h": "C/C++",
        ".hpp": "C/C++",
        ".info": "Info",
        ".java": "Java",
        ".js": "JavaScript",
        ".md": "Markdown",
        ".plist": "Property List",
        ".py": "Python",
        ".rb": "Ruby",
        ".rs": "Rust",
        ".sh": "Shell",
        ".template": "Template",
        ".toml": "TOML",
        ".ts": "TypeScript",
        ".tsx": "TypeScript",
        ".txt": "Text",
        ".yaml": "YAML",
        ".yml": "YAML",
        ".zsh": "Shell",
    }

    FILE_CHARACTERISTICS: typing.ClassVar = {
        "C": {
            "code": True,
            "executable": False,
        },
        "C++": {
            "code": True,
            "executable": False,
        },
        "Directory": {
            "code": False,
            "executable": False,
        },
        "Info": {
            "code": False,
            "executable": False,
        },
        "Java": {
            "code": True,
            "executable": False,
        },
        "JavaScript": {
            "code": True,
            "executable": True,
        },
        "Markdown": {
            "code": False,
            "executable": False,
        },
        "Non-existent": {
            "code": False,
            "executable": False,
        },
        "Other": {
            "code": False,
            "executable": False,
        },
        "Property List": {
            "code": False,
            "executable": False,
        },
        "Python": {
            "code": True,
            "executable": True,
        },
        "Ruby": {
            "code": True,
            "executable": True,
        },
        "Rust": {
            "code": True,
            "executable": True,
        },
        "Shell": {
            "code": True,
            "executable": True,
        },
        "Symlink": {
            "code": False,
            "executable": False,
        },
        "Template": {
            "code": False,
            "executable": False,
        },
        "Text": {
            "code": False,
            "executable": False,
        },
        "TOML": {
            "code": False,
            "executable": False,
        },
        "TypeScript": {
            "code": True,
            "executable": False,
        },
        "VSCode Workspace": {
            "code": False,
            "executable": False,
        },
        "YAML": {
            "code": False,
            "executable": False,
        },
    }

    @classmethod
    def all_types(cls) -> set[str]:
        return sorted(set(cls.FILE_CHARACTERISTICS.keys()))

    @classmethod
    def file_characteristics(cls) -> dict[str, dict[str, bool]]:
        return cls.FILE_CHARACTERISTICS.copy()

    @classmethod
    def check_type_characteristic(cls, type: str, characteristic: str) -> bool:
        type_definition = cls.FILE_CHARACTERISTICS.get(type, None)
        if type_definition is None:
            return False
        return type_definition.get(characteristic, False)

    @classmethod
    def type_is_code(cls, type: str) -> bool:
        return cls.check_type_characteristic(type, "code")

    @classmethod
    def type_is_executable(cls, type: str) -> bool:
        return cls.check_type_characteristic(type, "executable")

    def summary(self, long: bool = False) -> str:
        definition = self.define()
        definitions = []
        if definition["code"]:
            definitions.append("code")
            if definition["executable"]:
                definitions.append("executable")
                if definition["permitted"]:
                    definitions.append("permitted")
        if len(definitions) == 0:
            definitions.append("not code")

        return f"{definition['type']}: {', '.join(definitions)}"

    def define(self) -> dict[str]:
        type = self.type()
        code = self.is_code()
        executable = self.is_executable()
        permitted = self.is_permitted_executable()
        return {
            "type": type,
            "code": code,
            "executable": executable,
            "permitted": permitted,
        }

    def type(self) -> str:
        ext = self.path.suffix.lower()
        self.unknown = False
        self.unclassifiable = False

        if not self.path.exists():
            return "Non-existent"

        if self.path.is_dir():
            return "Directory"

        if os.path.islink(str(self.path)):
            return "Symlink"  # Skip symlinks

        # TODO Identify macOS aliases

        if self.is_linux_executable():
            return "Linux Executable"

        if self.is_macos_executable():
            return "macOS Executable"

        if self.is_binary():
            return "Binary"

        # Check by extension
        if ext in self.FILE_TYPES:
            return self.FILE_TYPES[ext]

        if ext != "":
            self.unknown = True
            return "Unknown"

        if typ := self.type_from_shebang():
            return typ

        if typ := self.type_from_code():
            return typ

        self.unclassifiable = True
        return "Unknown"

    def is_binary(self):
        """Check if a file is binary by looking for a null byte."""
        try:
            with self.path.open("rb") as f:
                # Read the first 1024 bytes (sufficient to catch binary signatures)
                chunk = f.read(1024)
                return b"\0" in chunk
        except OSError:
            # Treat unreadable files as binary/skip them
            return True

    def is_linux_executable(self):
        # 1. Check if the user has execute permissions
        if not os.access(self.path, os.X_OK):
            return False

        # 2. Read the first 4 bytes to check for the ELF magic number
        try:
            with self.path.open("rb") as f:
                magic_number = f.read(4)
            return magic_number == b"\x7fELF"
        except OSError:
            return False

    def is_macos_executable(self):
        # Standard macOS Mach-O magic numbers
        MACOS_MAGIC = {
            b"\xcf\xfa\xed\xfe",  # 64-bit Mach-O (mh_magic_64)
            b"\xfe\xed\xfa\xcf",  # 64-bit Mach-O Reverse Byte Order
            b"\xce\xfa\xed\xfe",  # 32-bit Mach-O (mh_magic)
            b"\xfe\xed\xfa\xce",  # 32-bit Mach-O Reverse Byte Order
            b"\xca\xfe\xba\xbe",  # Universal/Fat Binary (mach_header)
            b"\xbe\xba\xfe\xca",  # Universal/Fat Binary Reverse Byte Order
        }

        try:
            with self.path.open("rb") as f:
                header = f.read(4)
                return header in MACOS_MAGIC
        except OSError:
            return False

    def is_code(self):
        return self.type_is_code(self.type())

    def is_executable(self):
        return self.type_is_executable(self.type())

    def is_permitted_executable(self):
        return self.is_executable() and os.access(str(self.path), os.X_OK)

    def type_from_file_contents(self) -> str | None:
        # Inspect Shebang or content to determine type (as far as possible)
        if ftype := self.type_from_shebang():
            return ftype
        return self.type_from_code()

    LANGUAGE_PATTERNS: dict[str, dict[str, float]] = {  # noqa
        "c": {
            r"#include\s+<[a-z_]+\.h>": 3.0,
            r"\bprintf\s*\(": 2.5,
            r"\bscanf\s*\(": 2.5,
            r"\bmalloc\s*\(": 2.5,
            r"\bfree\s*\(": 1.5,
            r"\bstruct\s+[a-zA-Z_]\w*\s*\{": 1.5,
            r"\bint\s+main\s*\(": 1.5,
            r"[{};]\s*$": 0.5,
        },
        "c++": {
            r"#include\s+<(iostream|vector|string|map|memory|algorithm|utility)>": 4.0,
            r"\bstd::": 3.5,
            r"\bcout\s*<<": 3.5,
            r"\bcin\s*>>": 3.5,
            r"\bnamespace\s+[a-zA-Z_]\w*": 3.0,
            r"\bclass\s+[a-zA-Z_]\w*": 2.5,
            r"\btemplate\s*<": 3.0,
            r"\bauto\s+[a-zA-Z_]\w*\s*=": 2.0,
            r"\bnew\s+[a-zA-Z_]\w*": 1.5,
        },
        "python": {
            r"^\s*def\s+[a-zA-Z_]\w*\s*\(": 3.0,
            r"^\s*elif\s+": 2.5,
            r"^\s*import\s+[\w\.]+(\s+as\s+[\w]+)?": 2.0,
            r"^\s*from\s+[\w\.]+\s+import": 2.0,
            r"\bNone\b": 1.5,
            r"\bTrue\b|\bFalse\b": 1.0,
            r"\"\"\"|\'\'\'": 2.0,
            r":\s*$": 0.5,
        },
        "javascript": {
            r"\bconst\s+|\blet\s+|\bvar\s+": 2.0,
            r"\bfunction\s*\(": 2.0,
            r"=>": 2.0,
            r"\bconsole\.log\(": 2.5,
            r"===|!== ": 2.0,
            r"\bexport\s+default\b|\bmodule\.exports\b": 2.5,
            r"^\s*import\s+.*\s+from\s+['\"]": 2.0,
            r"[{};]\s*$": 0.5,
        },
        "typescript": {
            r"\binterface\s+[A-Z]\w*\s*\{": 4.0,
            r"\btype\s+[A-Z]\w*\s*=": 4.0,
            r":\s*(string|number|boolean|any|void|unknown|never)\b": 3.5,
            r"<[A-Z]\w*(\s*extends\s+.*)?>": 3.0,
            r"\bas\s+[A-Z]\w*\b": 3.0,
            r"\breadonly\s+": 2.5,
            r"\benum\s+[A-Z]\w*\s*\{": 3.5,
            r"\bimport\s+type\s+": 4.0,
        },
        "ruby": {
            r"^\s*def\s+[a-zA-Z_]\w*[!?]?": 2.5,
            r"^\s*end\s*$": 3.0,
            r"^\s*elsif\s+": 2.5,
            r"\bputs\b|\bp\b": 1.5,
            r"\battr_accessor\b|\battr_reader\b": 3.0,
            r"\bnil\b": 2.0,
            r"^\s*require\s+['\"]": 2.0,
            r"#\{.*\}": 2.5,
        },
        "rust": {
            r"\bfn\s+[a-zA-Z_]\w*\s*\(": 3.0,
            r"\blet\s+mut\s+": 3.0,
            r"\bpub\s+fn\b": 3.0,
            r"\bimpl\b|\btrait\b": 2.5,
            r"\bprintln!\(|\beprintln!\(": 3.0,
            r"\bmatch\s+.*\{": 2.0,
            r"->\s*[\w:<>]+\s*\{": 2.0,
            r"\bOk\([^)]*\)|\bErr\([^)]*\)": 2.0,
            r"\bSome\([^)]*\)|\bNone\b": 1.0,
        },
        "shell": {
            r"^#!\s*/bin/(bash|sh|zsh)": 4.0,
            r"^#!\s*/usr/bin/env\s+(bash|sh|zsh)": 4.0,
            r"^\s*if\s+\[\[?.*\]\]?;\s*then": 3.0,
            r"^\s*fi\s*$": 3.0,
            r"^\s*elif\s+\[\[?.*\]\]?;\s*then": 2.5,
            r"\bexport\s+[a-zA-Z_]\w*=": 2.5,
            r"\blocal\s+[a-zA-Z_]\w*=": 2.5,
            r"\$\{?[a-zA-Z_]\w*\}?": 1.5,
            r"^\s*echo\s+": 1.5,
            r">\s*/dev/null\s+2>&1": 2.0,
        },
    }

    SNIPPET_LENGTH = 2000
    MINIMUM_THRESHOLD = 1.5

    def type_from_code(self) -> str | None:
        try:
            with self.path.open("r", encoding="utf-8") as f:
                code_snippet = f.read(self.SNIPPET_LENGTH)

        except Exception:  # noqa
            return None

        if not code_snippet or not code_snippet.strip():
            return None

        scores: dict[str, float] = {lang: 0.0 for lang in self.LANGUAGE_PATTERNS}
        lines = code_snippet.splitlines()

        for line in lines:
            stripped = line.strip()
            if not stripped:
                continue

            for lang, patterns in self.LANGUAGE_PATTERNS.items():
                for pattern, weight in patterns.items():
                    if re.search(pattern, stripped):
                        scores[lang] += weight

        best_language, highest_score = max(scores.items(), key=lambda item: item[1])

        # Minimum threshold to avoid false positives on ambiguous single lines
        if highest_score < self.MINIMUM_THRESHOLD:
            return None

        # Resolve TypeScript vs JavaScript: TS signatures supersede JS base syntax
        if scores["typescript"] > 0 and (
            best_language == "javascript"
            or scores["typescript"] >= scores["javascript"]
        ):
            return "typescript"

        # Resolve ambiguity between C and C++: default to 'c' if scores are tied or C++ signature absent
        if best_language in ("c", "c++"):
            if scores["c++"] > scores["c"]:
                return "c++"
            return "c"

        return best_language

    def type_from_shebang(self) -> str | None:
        """Inspect shebang to determine file type (if possible)"""
        try:
            with self.path.open("r", encoding="utf-8") as f:
                first_line = f.readline().strip()
        except Exception:  # noqa
            return None

        if first_line.startswith("#!"):
            if re.search(r"\bpython\b", first_line):
                return "Python"
            if re.search(r"\bruby\b", first_line):
                return "Ruby"
            if re.search(r"\b(bash|zsh)\b", first_line):
                return "Shell"
            if re.search(r"\b(node|js)\b", first_line):
                return "JavaScript"
            if re.search(r"\brust\b", first_line):
                return "Rust"
        return None


def main():
    parser = argparse.ArgumentParser(description="Analyze a file and display its type.")
    parser.add_argument(
        "-a",
        "--all",
        action="store_true",
        help="Display the list of all file types",
    )
    parser.add_argument(
        "-l",
        "--long",
        action="store_true",
        help="Display details",
    )
    parser.add_argument("file", nargs="?", help="File to check")
    args = parser.parse_args()
    if not args.all and not args.file:
        parser.error("You must specify either --all or provide a file name")
    if args.all:
        for type in FileType.all_types():
            print(type)
        sys.exit(0)

    type_analyzer = FileType(Path(args.file))
    if args.long:
        print(type_analyzer.summary())
    else:
        print(type_analyzer.type())


if __name__ == "__main__":
    main()
