# halo2-regex

**Regex verification circuit in halo2.**

## Disclaimer
DO NOT USE THIS LIBRARY IN PRODUCTION. At this point, this is under development not audited. It has known and unknown bugs and security flaws.

## Features
`halo2-regex` provides a library for a regex verification chip compatible with the [halo2 library developed by privacy-scaling-explorations team](https://github.com/privacy-scaling-explorations/halo2).

## Requirement
- rustc 1.68.0-nightly (0468a00ae 2022-12-17)
- cargo 1.68.0-nightly (cc0a32087 2022-12-14)

## Installation and Build
You can install and build our library with the following commands.
```bash
git clone https://github.com/zkemail/halo2-regex.git
cd halo2-regex
cargo build --release
```

## Usage
You can open the API specification by executing `cargo doc --open`.

## Test
You can run the tests by executing `cargo test --release`.

## Acknowledgments
Big thank-yous to [vivek b](https://github.com/vb7401) and [ying tong](https://github.com/therealyingtong) for helping debug these circuits!
