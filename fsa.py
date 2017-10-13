#!/usr/bin/env python2
# -*- coding: utf-8 -*-

"""File system audit tool

A command line tool for collecting filesystem meta-data. Iterates through
input files, and outputs file hash and meta-data using the specified algorithm
and format (to stdout).

Usage:
    $ python fsa.py ROOT_PATH                   - File(s) or path to audit.
                    [--recursive]               - Recursively walk directory tree.
                    [--json]                    - Output in JSON format.
                    [--csv]                     - Output in CSV format.
                    [--algorithm ALGORITHM]     - File hash algorithm (see below).
                    [--string FORMAT_STRING]    - Output str.format template (see below).
                    [--ignore FILE_NAME_FILTER] - Ignore fnmatch pattern (can specify multiple).

    FORMAT_STRING defines template for output using the following keywords:
        {name}  - File name (no path)
        {path}  - File name with path
        {mode}  - Protection bits (as octal permissions)
        {uid}   - User ID of owner
        {gid}   - Group ID of owener
        {size}  - Size of file in bytes
        {atime} - Time of most recent access
        {mtime} - Time of most recent content modification
        {ctime} - Platform dependent; time of most recent meta data change in
                  unix, or time of creation in windows.
        {hash}  - File hash value

    ALGORITHM defines file hashing algorithm:
        md5
        sha1
        sha224
        sha256
        sha384
        sha512

    Example:
        $ python fsa.py ~/ --recursive --string "{path}, {hash}" \
                           --algorithm sha256 --ignore ".*" --ignore "*.log"

Note:
    * Large files are read in 128MB chunks to prevent excessive memory
      utilization.
    * Two CSV output files can be effectively compared using Beyond Compare,
      (https://www.scootersoftware.com) or other diff tools.
    * Ignores empty folders.
"""

__author__ = "Jesse Waas"
__description__ = "File system audit tool"
__copyright__ = "Copyright 2017, Jesse Waas"
__license__ = "MIT"
__version__ = "0.1.0"
__maintainer__ = "Jesse Waas"
__email__ = "Jesse Waas"
__status__ = "Development"

import os
import hashlib
import json
import argparse
from fnmatch import fnmatch
from collections import OrderedDict

BLOCK_SIZE = 128*1024*1024 # 128MiB block size
HASH_FN = hashlib.sha256()

class FileMeta(object):
    """File meta-data object

    Encapsulates hash and meta-data attributes related to a single file.
    Enables formatted output as json, csv, or template based string.

    Example:
        file_meta_data = FileMeta("/tmp/test.txt")

        file_meta_data.to_json()

        file_meta_data.to_csv()

        file_meta_data.to_string("{path}, {hash}")

    Attributes:
        name:  File name (no path)
        path:  File name with path
        mode:  Protection bits (as octal permissions)
        uid:   User ID of owner
        gid:   Group ID of owener
        size:  Size of file in bytes
        atime: Time of most recent access
        mtime: Time of most recent content modification
        ctime: Platform dependent; time of most recent meta data change in
               unix, or time of creation in windows.

        hash_value: File hash value
    """

    def __init__(self, file_path, hash_algorithm=HASH_FN):
        """Create file meta-data object

        Initialize file meta-data object. File stat information is read,
        and a hash is generated.

        Default file hashing algorithm is sha256. This can be overwritten by
        setting the hash_algorithm agument to a different hashlib algorithm
        such as hashlib.md5().

        Examples:
            file_meta = FileMeta("/tmp/test.txt")

            file_meta = FileMeta("/tmp/test.txt", hash_algorithm=hashlib.md5())

        Args:
            file_path: Path to file of interest
            hash_algorithm: hashlib Hash algorithm (default hashlib.sha256())
        """
        file_stat = os.stat(file_path)

        self.name = os.path.split(file_path)[1]
        self.path = file_path
        self.mode = "{:o}".format(file_stat.st_mode & 0o777)
        self.uid = file_stat.st_uid
        self.gid = file_stat.st_gid
        self.size = file_stat.st_size
        self.atime = file_stat.st_atime
        self.mtime = file_stat.st_mtime
        self.ctime = file_stat.st_ctime
        self.hash_value = hash_file(file_path, hash_algorithm)

    def to_list(self):
        return [self.name,
                self.path,
                self.mode,
                self.uid,
                self.gid,
                self.size,
                self.atime,
                self.mtime,
                self.ctime,
                self.hash_value]

    def to_dict(self):
        return OrderedDict([("name", self.name),
                            ("path", self.path),
                            ("mode", self.mode),
                            ("uid", self.uid),
                            ("gid", self.gid),
                            ("size", self.size),
                            ("atime", self.atime),
                            ("mtime", self.mtime),
                            ("ctime", self.ctime),
                            ("hash", self.hash_value)])

    def to_string(self, fmt="{path}, {mode}, {uid}, {gid}, {size}, "\
                            "{hash_value}"):
        """Return formatted file meta-data string

        Enables keyword based string formatting using str.format().

        Keys:
            {name}  - File name (no path)
            {path}  - File name with path
            {mode}  - Protection bits (as octal permissions)
            {uid}   - User ID of owner
            {gid}   - Group ID of owener
            {size}  - Size of file in bytes
            {atime} - Time of most recent access
            {mtime} - Time of most recent content modification
            {ctime} - Platform dependent; time of most recent meta data change in
                      unix, or time of creation in windows.
            {hash}  - File hash value

        Examples:
            FileMeta.to_string(fmt="{path}, {size}, {hash}")

            Output would be similar to: "/tmp/text.txt, 1024, deadbeefdeadbeef..."

        Args:
            fmt: str.format() string using above keywords.
        """
        return fmt.format(name=self.name,
                          path=self.path,
                          mode=self.mode,
                          uid=self.uid,
                          gid=self.gid,
                          size=self.size,
                          time=self.atime,
                          mtime=self.mtime,
                          ctime=self.ctime,
                          hash_value=self.hash_value)

    def to_json(self):
        return json.dumps(self.to_dict())

    def __str__(self):
        return json.dumps(self.to_dict(), indent=2)


def hash_file(path, hash_algorithm=HASH_FN):
    """Return hash of specified file.

    Uses hashlib to calculate file hashes. Large files will be read in
    BLOCK_SIZE chunks.

    Args:
        path: Path to file for which hash is to be generated
        hash_algorithm: hashlib Algorithm such as hashlib.sha256()
    """
    with open(path, "rb") as file_to_hash:

        def block_read():
            return file_to_hash.read(BLOCK_SIZE)

        for block in iter(block_read, ""):
            hash_algorithm.update(block)

        return hash_algorithm.hexdigest()


def ignore_file(ignore_path, ignore_files):
    """Check if specified file path matches ignore patterns

    Determine if file, or any parent folder name matches list of ignore file
    patterns. Uses fnmatch to perform name pattern comparisons.

    Args:
        ignore_path: File path to be tested
        ignore_files: List of ignore patterns (see fnmatch)
    """
    if ignore_files:
        while ignore_path:
            ignore_path, ignore_file = os.path.split(ignore_path)
            if True in (fnmatch(ignore_file, f) for f in ignore_files):
               return True

    return False


def walk_path(path, recursive=False, hash_algorithm=HASH_FN, ignore_files=None):
    """FileMeta generator using os.walk to identify input files

    Yields single FileMeta object based on (optionally recursive) traversal of
    directory tree starting at specified root path. Traverses top-down.

    Args:
        path: Root path for meta-data calculation
        recursive: True if full directory tree should be traversed
        hash_algorithm: hashlib Algorithm such as hashlib.sha1()
        ignore_files: List of file patterns to ignore (tested with fnmatch)
    """

    if not os.path.isdir(path):
        if not ignore_file(path, ignore_files):
            yield FileMeta(path, hash_algorithm.copy())
    else:
        for root, dirs, files in os.walk(path):
            for file_name in files:
                file_path = os.path.join(root, file_name)

                if ignore_file(file_path, ignore_files):
                    continue

                yield FileMeta(file_path, hash_algorithm.copy())

            if not recursive:
                break


def main():
    """Command line interface for generating filesystem meta-data"""
    parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter,
                                     description=
"""File system audit tool. A command line tool for collecting filesystem
meta-data. Iterates through input files, and outputs file hash and meta-data
using the specified algorithm and format (to stdout).

Example:
    $ python fsa.py ~/ --recursive --string "{path}, {hash}" \\
                       --algorithm sha256 --ignore .* --ignore *.log

Note:
    * Large files are read in 128MB chunks to prevent excessive memory
      utilization.
    * Two CSV output files can be effectively compared using Beyond Compare,
      (https://www.scootersoftware.com) or other diff tools.
    * Ignores empty folders.

[1] Output --string format options:
    {name}  - File name (no path)
    {path}  - File name with path
    {mode}  - Protection bits (as octal permissions)
    {uid}   - User ID of owner
    {gid}   - Group ID of owener
    {size}  - Size of file in bytes
    {atime} - Time of most recent access
    {mtime} - Time of most recent content modification
    {ctime} - Platform dependent; time of most recent meta data change in
              unix, or time of creation in windows.
    {hash}  - File hash value

    Example: --string "{path}, {mode}, {size}, {hash}" """)

    parser.add_argument("path", metavar="PATH", nargs="+",
                        help="File(s) or path to audit.")
    parser.add_argument("-s", "--string", metavar="FORMAT",
                        help="""Output str.format template. See [1] above.""")
    parser.add_argument("-i", "--ignore", metavar="PATTERN", action="append",
                        help="Ignore fnmatch pattern (can specify multiple).")
    parser.add_argument("-a", "--algorithm", default=HASH_FN,
                        help="File hash algorithm (md5, sha1, "
                             "sha224, sha256, sha384, sha512).")
    parser.add_argument("-r", "--recursive", action="store_true",
                        help="Recursively walk directory tree.")
    parser.add_argument("--json", action="store_true",
                        help="Output in JSON format.")
    parser.add_argument("--csv", action="store_true",
                        help="Output in CSV format.")

    args = parser.parse_args()

    hash_algorithm_map = {"md5": hashlib.md5(),
                          "sha1": hashlib.sha1(),
                          "sha224": hashlib.sha224(),
                          "sha256": hashlib.sha256(),
                          "sha384": hashlib.sha384(),
                          "sha512": hashlib.sha512()}

    hash_algorithm = HASH_FN

    if args.algorithm in hash_algorithm_map:
        hash_algorithm = hash_algorithm_map[args.algorithm]

    multi_path = len(args.path) > 1

    for file_path in args.path:
        if os.path.isdir(file_path) and multi_path and not args.recursive:
            continue

        for file_meta in walk_path(file_path, recursive=args.recursive,
                                   hash_algorithm=hash_algorithm,
                                   ignore_files=args.ignore):
            if args.string:
                print(file_meta.to_string(fmt=args.string))
            elif args.csv:
                print(file_meta.to_string())
            elif args.json:
                print(file_meta.to_json())
            else:
                print(file_meta)


if __name__ == "__main__":
    main()
