# NftTools

Help interacting with nftables

NftTools provides helpers to work with nftables from Python. It builds on python-nftables which itself uses libnftables. Note that the API is not yet stable and can change from one version to the next.

---

## Features

- Convert an nftables rule into its JSON representation.
- Validate an nftables rule by temporary applying it in a helper chain.
- Convert simple rules into a dictionary representation.
- Convert that dictionary representation into an nftables rule.
- Supports IPv4 and IPv6.
- Provides limited support for sets.

---

## Installation

Install using PyPi:

```shell
pip3 install nfttools
```

Note: The tool uses `python3-nftables` as dependency. If you don't use Debian's operating system package (or Alpine's `py3-nftables`) but attempt to install `pip-nftables` instead, the latter might complain on missing "schema.json". Workaround: Use the operating system package or copy it's "schema.json" to the place `pip-nftables` is looking for that file.

---

## Reporting bugs

In case you encounter any bugs, please report the expected behavior and the actual behavior so that the issue can be reproduced and fixed.

---
## Developers

### Clone repository

Clone this repo to your local machine using `https://github.com/towalink/nfttools.git`

Install the module temporarily to make it available in your Python installation:
```shell
pip3 install -e <path to root of "src" directory>
```

---

## License

[![License](http://img.shields.io/:license-mit-blue.svg?style=flat-square)](https://opensource.org/licenses/MIT)

- **[MIT license](https://opensource.org/licenses/MIT)**
- Copyright 2024-2024 © <a href="https://github.com/towalink/nfttools" target="_blank">Dirk Henrici</a>.
- [WireGuard](https://www.wireguard.com/) is a registered trademark of Jason A. Donenfeld.
