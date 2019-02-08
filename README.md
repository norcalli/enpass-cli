# `enpass-cli`

[![crates.io](https://img.shields.io/crates/v/enpass-cli.svg?style=flat)](https://crates.io/crates/enpass-cli) [![docs.rs](https://docs.rs/enpass-cli/badge.svg)](https://docs.rs/enpass-cli)

Developed on Linux, and therefore only tested on Linux.

Requires `libsqlcipher` to be available as a shared library. This can be installed from AUR as `pacman -S sqlcipher`.

I am looking into removing this dependency by statically compiling it. crates.io release also pending.

```
❯ enpass-cli
error: The following required arguments were not provided:
    -d <database>
    -p <password>

USAGE:
    enpass-cli -d <database> -p <password>

For more information try --help
```
