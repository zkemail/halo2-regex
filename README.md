# halo2-regex

You have to run `python3 gen.py` from within `regex_to_circom/` in https://github.com/zk-email-verify/zk-email-verify/ . Then, copy the generated halo2_regex_lookup.txt file into this repo. Then, run `cargo test`.

Big thank-yous to [vivek b](https://github.com/vb7401) and [ying tong](https://github.com/therealyingtong) for helping debug these circuits, and [sora](https://github.com/SoraSuegami/) for helping ink out an initial plan for the circuits!

## Format of input file

space-seperated list of accept states (right now only one state is supported)
space-seperated list of public/constrained states
space-seperated list of all states that are not public/constrained
