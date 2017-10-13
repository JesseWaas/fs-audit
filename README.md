# fs-audit
Command line tool for collecting filesystem meta-data. Iterates through input
files, and outputs file hash and meta-data using the specified algorithm and
format (to stdout).

## Status
Initial version. Pending test case development.

## Requirements
Python 2.7+ (tested on 2.7.5)

## Usage:
```
$ python fsa.py ROOT_PATH                   - File(s) or path to audit.
                [--recursive]               - Recursively walk directory tree.
                [--json]                    - Output in JSON format.
                [--csv]                     - Output in CSV format.
                [--algorithm ALGORITHM]     - File hash algorithm (see below).
                [--string FORMAT_STRING]    - Output str.format template (see below).
                [--ignore FILE_NAME_FILTER] - Ignore fnmatch pattern (can specify multiple).
                [--help]                    - Display usage information.

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
```

## Note:
 * Large files are read in 128MB chunks to prevent excessive memory utilization.
 * Two CSV output files can be effectively compared using Beyond Compare, (https://www.scootersoftware.com) or other diff tools.
 * Ignores empty folders.
