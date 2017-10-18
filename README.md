# fs-audit
Command line tool for collecting and analysing filesystem meta-data. Supports 
capture of meta-data for a user defined set of files, and post processing of
that meta-data to highlight differences.

Captured meta-data includes various os.stat attributes as well as a file hash.
See FORMAT_STRING below for a full list.

This tool is intended to assist with auditing of software deployments accross
multiple remote servers.

## Status
Unstable.

## Requirements
Python 2.7+ (tested on 2.7.5 and 3.5.2)

## Usage:
```
$ python fsa.py ROOT_PATH                   - File(s) or path to audit.
                [--recursive]               - Recursively walk directory tree.
                [--json]                    - Output in JSON format.
                [--csv]                     - Output in CSV format.
                [--algorithm ALGORITHM]     - File hash algorithm (see below).
                [--string FORMAT_STRING]    - Output str.format template (see below).
                [--ignore FILE_NAME_FILTER] - Ignore fnmatch pattern (can specify multiple).
                
                [--diff DIFF ...            - Diff the specified archive file records.
                [--diffkeys KEYS ...        - Meta data key values to compare (see below).
                
                [--help]                    - Display usage information.

KEYS file meta data key values:
    name    - File name (no path)
    path    - File name with path
    mode    - Protection bits (as octal permissions)
    uid     - User ID of owner
    gid     - Group ID of owener
    size    - Size of file in bytes
    atime   - Time of most recent access
    mtime   - Time of most recent content modification
    ctime   - Platform dependent; time of most recent meta data change in
              unix, or time of creation in windows.
    hash    - File hash value

FORMAT_STRING defines template for output using the above KEY inside curley braces:
    {name}  - File name (no path)
    {path}  - File name with path
    {mode}  - Protection bits (as octal permissions)
    ...

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
