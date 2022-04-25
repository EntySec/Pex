# Pex

Python Exploitation is a collection of special utilities for providing high quality penetration testing using pure python programming language.

## Installation

```
pip3 install git+https://github.com/EntySec/Pex
```

## Utilities

### Post

Collection of methods for pushing files to or pulling files from compromised platform.

* `pex.post` - `Post` sends data to target system and executes it.
   * `pex.post.pull` - `Pull` pulls data from target system using specified method.
      * `pex.post.pull.dd` - Pull file using `dd`.
      * `pex.post.pull.cat` - Pull file using `cat`.
   * `pex.post.push` - `Push` pushes data to target system using specified method.
      * `pex.post.push.echo` - Push file using `echo -e`.
      * `pex.post.push.bash_echo` - Push file using `echo -en`.
      * `pex.post.push.printf` - Push file using `printf`.
      * `pex.post.push.certutil` - Push file using `certutil`.
