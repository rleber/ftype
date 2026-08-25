#!/usr/bin/env python3
"""
Analyze what programming lanugages a project uses
"""

# TODO Refactor using major packages, e.g. mimetypes, filetype, or python-magic
# TODO Add other file types, e.g. Excel, Word, database

import argparse
import os
import sys
import typing
from pathlib import Path


class FileType:
    def __init__(self, path: Path):
        self.path = path
        self.unknown = None
        self.unclassifiable = None

    FILE_TYPES: typing.ClassVar = {
        ".bash": "Shell Script",
        ".c": "C/C++",
        ".cc": "C/C++",
        ".code-workspace": "VSCode Workspace",
        ".cpp": "C/C++",
        ".erb": "Template",
        ".h": "C/C++",
        ".hpp": "C/C++",
        ".info": "Info",
        ".java": "Java",
        ".js": "JavaScript/TypeScript",
        ".md": "Markdown",
        ".plist": "Property List",
        ".py": "Python",
        ".rb": "Ruby",
        ".rs": "Rust",
        ".sh": "Shell Script",
        ".template": "Template",
        ".toml": "TOML",
        ".ts": "JavaScript/TypeScript",
        ".txt": "Text",
        ".yaml": "YAML",
        ".yml": "YAML",
        ".zsh": "Shell Script",
    }

    FILE_CHARACTERISTICS: typing.ClassVar = {
        "C/C++": {
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
        "JavaScript/TypeScript": {
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
        "Shell Script": {
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

        # Inspect Shebang or content for edge cases (e.g., files without extensions)
        try:
            with self.path.open("r", encoding="utf-8") as f:
                first_line = f.readline().strip()
                if first_line.startswith("#!"):
                    if "python" in first_line:
                        return "Python"
                    if "ruby" in first_line:
                        return "Ruby"
                    if "sh" in first_line:
                        return "Shell Script"

                # Search for specific file_type keywords
                content = f.read(2000)  # Read first 2000 chars
                if "def " in content and "import " in content:
                    return "Python"
                if "def " in content and "end" in content:
                    return "Ruby"
        except Exception:  # noqa
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
