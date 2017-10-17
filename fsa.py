#!/usr/bin/env python
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

from __future__ import print_function

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
import csv
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

    KEYS = ["name", "path", "mode", "uid", "gid", "size", "atime", "mtime",
            "ctime", "hash"]

    def __init__(self, file_path=None, hash_algorithm=HASH_FN, from_dict=None):
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
            import_dict: Dict representation of existing FileMeta object to
                         clone. "file_path" And "hash_algorithm" arguments
                         ignored.
        """

        if from_dict:
            self.from_dict(from_dict)
        else:
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

    def from_dict(self, import_dict):
        self.name = import_dict["name"]
        self.path = import_dict["path"]
        self.mode = import_dict["mode"]
        self.uid = import_dict["uid"]
        self.gid = import_dict["gid"]
        self.size = import_dict["size"]
        self.atime = import_dict["atime"]
        self.mtime = import_dict["mtime"]
        self.ctime = import_dict["ctime"]
        self.hash_value = import_dict["hash"]

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

    def __getitem__(self, attr):
        # "hash_value" known externally as "hash" TODO: Clean up.
        if attr == "hash": attr = "hash_value"
        return self.__dict__[attr]


class FileMetaCollection(object):
    """File meta-data collection object

    Encapsulates a collection of FileMeta objects loaded from a previous audit.
    Each FileMeta instance represents an audit of a single file (on a given
    host at a specific point of time).

    MetaFile attributes can be "indexed" (made into dict keys) by passing the
    attribute name to this classes constructor. This allows for fast lookups.

    Attributes:
        index_keys: MetaFile values to index (list)
        name: File name (informational only)
        meta_list: Flat list of MetaFile objects
        meta_indexed: MetaFile objects indexed by key/value
    """

    def __init__(self, index_keys, name=None, from_iterable=None,
                 from_json_file=None):

        if isinstance(index_keys, str):
            index_keys = [index_keys]

        self.name = name
        self.index_keys = index_keys
        self.meta_list = []

        # meta_indexed = {key = INDEX_KEY,
        #                 val = { key = META_FILE_KEY_VALUE,
        #                         val = META_FILE}}
        #
        # Example: {key = "path",
        #           val = { key = "foo.bar",
        #                   val = MetaFile(path="foo.bar")}}
        #
        self.meta_indexed = OrderedDict(
            ((k, OrderedDict()) for k in self.index_keys))

        if from_iterable:
            self.from_iterable(from_iterable)

        if from_json_file:
            self.from_json_file(from_json_file)

    def add(self, meta):
        """Add a single MetaFile to this collection.

        Args:
            meta: MetaFile
        """
        self.meta_list.append(meta)

        for key in self.index_keys:
            # Note that only one FileMeta object is stored per unique index
            # key value. Non-unique keys will be overwritten.
            self.meta_indexed[key][meta[key]] = meta

    def to_csv(self, path):
        """Save FileMeta collection to CSV file.

        Args:
            path: Output CSV file path
        """
        with open(path, "wb") as csv_file:
            csv_writer = csv.writer(csv_file)
            csv_writer.writerow(FileMeta.KEYS)
            csv_writer.writerows((x.to_dict() for x in self.meta_list))

    def to_json(self, path):
        """Save FileMeta collection to JSON file.

        Args:
            path: Output JSON file path
        """
        with open(path, "w") as json_file:
            json.dump([x.to_dict() for x in self.meta_list], json_file)

    def from_iterable(self, iterable):
        """Load MetaFiles from MetaFile iterable.

        Args:
            iterable: Iterable collection of MetaFile's such as list()
        """
        for meta in iterable:
            self.add(meta)

    def from_json_file(self, path):
        """Load MetaFiles from Json file.

        Args:
            path: JSON File path
        """
        with open(path, "r") as meta_file:
            raw_meta_data = json.load(meta_file)

            for raw_meta in raw_meta_data:
                meta = FileMeta(from_dict=raw_meta)
                self.add(meta)

    def get_meta_list(self):
        """Get list of all FileMeta objects in this FileMetaCollection."""
        return self.meta_list

    def get_meta_index(self, key):
        """Get dictionary of {value:MetaFile}'s for the specified key.

        Args:
            key: MetaFile attribute key (name|path|mode|uid|gid|size|atime|
                                         mtime|ctime|hash)
        """
        return self.meta_indexed[key]

    def get_meta(self, key, value):
        """Get single FileMeta object by key and value.

        Example:
            FileMetaCollection.get_meta("path", "foo.bar")
                ==> FileMeta(path="foo.bar")

        Args:
            key: MetaFile attribute key (name|path|mode|uid|gid|size|atime|
                                         mtime|ctime|hash)
            value: Value of MetaFile attribute.
        """
        return self.meta_indexed[key].get(value, None)


def get_key_value_superset(file_meta_collections, primary_key):
    """Get key value superset from a list of FileMetaCollection's.

    Iterates throug N input FileMetaCollection's and accumulates a superset of
    key values related to the specified primary key.

    Note that FileMetaCollection's are themselves lists of meta data
    for different files.

    Example:

    file_meta_col_1 = [{"path":1..}, {"path":2..}, {"path":3..}]
    file_meta_col_2 = [{"path":2..}, {"path":3..}, {"path":4..}]

    get_key_value_superset([file_meta_col_1, file_meta_col_2], "path")

    Result: [1, 2, 3, 4]

    Input order maintained where possible.

    Args:
        file_meta_collections: List of FileMetaCollectionis
        primary_key: Primary key with which to resolve value superset
    """
    # Using OrderedDict as 'ordered set' to collect ordered, unique list
    # of primary key values.
    primary_key_value_dict = OrderedDict()

    # Fetch all primary key values from input collections. Each collection
    # may contain different primary key value sets - we want a unique super
    # -set of these.
    for file_meta_collection in file_meta_collections:
        key_values = file_meta_collection.get_meta_index(primary_key)
        primary_key_value_dict.update(key_values)

    # Collapse to simple list of keys. Values are now assigned to
    # arbitrary FileMeta instances which are not useful.
    primary_key_values = list(primary_key_value_dict.keys())

    return primary_key_values


def group_diff(interesting_keys, meta_files):
    """Compare meta data file interesting key values.

    Performs n-way diff on specified collection of MetaFiles. The specified
    key values are compared and "diff group" integers are defined to group
    meta_files with common key values.

    Diff groups are provided both for individual keys and for the combination
    of all keys.

    Args:
        interesting_keys: List of key strings to compare (name|path|mode|uid|
                                                          gid|size|atime|mtime|
                                                          ctime|hash)
        meta_files: List of MetaFile file meta data objects for comparison.
    """
    result = []

    # Cache key values that are found in input meta files so we can track
    # the number of unique values found (gives us group #)
    #
    # single_key_value_cache = {key = INTERESTING_KEY,
    #                           val = { key=INTERESTING_VALUE,
    #                                   val=DIFF_GROUP_INTEGER}}
    #
    single_key_value_cache = dict(((k, dict()) for k in interesting_keys))

    # tuple_key_value_cache = {key = TUPLE_OF_INTERESTING_GROUP_INTEGERS
    #                          val = DIFF_SUMMARY_GROUP_INTEGER}
    tuple_key_value_cache = dict()

    for meta in meta_files:

        # Use an OrderedDict() here so that groups.items() is produced in
        # order consistant with interesting_keys. Note that this
        #
        # groups = {key=INTERESTING_KEY, val=DIFF_GROUP_INTEGER}
        groups = OrderedDict()

        for key in interesting_keys:
            cache = single_key_value_cache[key]
            meta_key_value = meta[key]

            # New DIFF_GROUP_INTEGER is equal to length of cache (number of
            # unique values found).
            if not meta_key_value in cache:
                cache[meta_key_value] = len(cache)

            groups[key] = cache[meta_key_value]

        # Convert to immutable nested tuple to be accepted as a cache dict key
        groups_tuple = tuple(groups.items())

        # New DIFF_SUMMARY_GROUP_INTEGER is equal to length of cache (number of
        # unique values found). Unique values comprise of tuples of
        # DIFF_GROUP_INTEGER's related to all interesting keys.
        if groups_tuple not in tuple_key_value_cache:
            tuple_key_value_cache[groups_tuple] = len(tuple_key_value_cache)

        result.append((meta, groups, tuple_key_value_cache[groups_tuple]))

    return result


def hash_file(path, hash_algorithm=HASH_FN):
    """Return hash of specified file.

    Uses hashlib to calculate file hashes. Large files will be read in
    BLOCK_SIZE chunks.

    Args:
        path: Path to file for which hash is to be generated
        hash_algorithm: hashlib Algorithm such as hashlib.sha256()
    """
    hash_algorithm = hash_algorithm.copy()

    with open(path, "rb") as file_to_hash:

        while True:
            block = file_to_hash.read(BLOCK_SIZE)
            if block:
                hash_algorithm.update(block)
            else:
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
            yield FileMeta(path, hash_algorithm)
    else:
        for root, dirs, files in os.walk(path):
            for file_name in files:
                file_path = os.path.join(root, file_name)

                if ignore_file(file_path, ignore_files):
                    continue

                yield FileMeta(file_path, hash_algorithm)

            if not recursive:
                break


def cmd_walk(args):
    """Analyse files on file system."""
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

    meta_file_collection = None
    if bool(args.csv) | bool(args.json):
        meta_file_collection = FileMetaCollection(["path"])

    for file_path in args.path:
        if os.path.isdir(file_path) and multi_path and not args.recursive:
            continue

        for file_meta in walk_path(file_path, recursive=args.recursive,
                                   hash_algorithm=hash_algorithm,
                                   ignore_files=args.ignore):

            if args.string:
                print(file_meta.to_string(fmt=args.string))
            else:
                print(file_meta.path)

            if meta_file_collection:
                meta_file_collection.add(file_meta)

    if meta_file_collection:
        if args.csv:
            meta_file_collection.to_csv(args.csv)

        elif args.json:
            meta_file_collection.to_json(args.json)


def cmd_diff(args):
    """Diff file system based on previously captured meta-data."""
    file_meta_collections = []

    PATH_KEY = "path"
    INTERESTING_KEYS = ["hash", "size"]

    # Input analysis archives
    for path in args.diff:
        file_meta_collection = FileMetaCollection(PATH_KEY, name=path, from_json_file=path)
        file_meta_collections.append(file_meta_collection)

    primary_key_values = get_key_value_superset(file_meta_collections, PATH_KEY)

    print()

    interesting_keys_txt = "".join(("{:^10}".format(k) for k in INTERESTING_KEYS))
    column_header_txt = "{:40}{}{:^10}".format("File @ Archive", interesting_keys_txt, "sum")

    print(column_header_txt)

    # For each file for which we have meta-data
    for file_key in primary_key_values:

        # Obtain meta data for different version of the file
        meta_list = [m.get_meta(PATH_KEY, file_key) for m in file_meta_collections]

        diff = group_diff(INTERESTING_KEYS, meta_list)

        # For each comparison key that we are interested in
        for archive_path, (meta, key_groups, group) in zip(args.diff, diff):
            row_name = "{} @ {}".format(file_key, archive_path)
            key_group_txt = "".join(("{:^10}".format(g) for g in key_groups.values()))

            print("{:40}{}{:^10}".format(row_name, key_group_txt, group))

        print()


def main():
    """Command line interface for generating filesystem meta-data"""
    parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter,
                                     description=
# pylint: disable=bad-continuation
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
# pylint: enable=bad-continuation
    parser.add_argument("path", metavar="PATH", nargs="*",
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
    parser.add_argument("--json",
                        help="Output to JSON file.")
    parser.add_argument("--csv",
                        help="Output to CSV file.")
    parser.add_argument("--diff", nargs="*",
                        help="Diff the specified archive files.")

    args = parser.parse_args()

    if args.diff:
        cmd_diff(args)
    else:
        cmd_walk(args)


if __name__ == "__main__":
    main()
