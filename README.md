# Pex

Python Exploitation is a collection of special utilities for providing high quality penetration testing using pure python programming language.

## Installation

```
pip3 install git+https://github.com/EntySec/Pex
```

## Utilities

### Client

Collection of client implementations for several protocols.

* `pex.client.adb` - ADB client.
* `pex.client.channel` - TCP interactive wrapper.
* `pex.client.http` - HTTP client.
* `pex.client.ssh` - SSH client.
* `pex.client.tcp` - TCP client.
* `pex.client.udp` - UDP client.
* `pex.client.wp` - WordPress client.
* `pex.client.stream` - Stream client.

### Tools

Collection of tools for special reasons.

* `pex.tools.tcp` - TCP tools.
* `pex.tools.http` - HTTP tools.
* `pex.tools.db` - Database tools.
* `pex.tools.payload` - Payload tools.
* `pex.tools.ssl` - SSL tools.
* `pex.tools.string` - String tools.
* `pex.tools.type` - Type tools.

### Post

Collection of methods for pushing files to or pulling files from compromised platform.

* `pex.post.pull`
    * `pex.post.pull.cat` - Pull file using `cat`.

* `pex.post.push`
    * `pex.post.push.echo` - Push file using `echo -e`.
    * `pex.post.push.bash_echo` - Push file using `echo -en`.
    * `pex.post.push.printf` - Push file using `printf`.
    * `pex.post.push.certutil` - Push file using `certutil`.