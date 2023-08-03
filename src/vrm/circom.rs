use super::VrmError;
use crate::vrm::js_caller::*;
use crate::vrm::DecomposedRegexConfig;
use crate::{AllstrRegexDef, SubstrRegexDef};
use fancy_regex::Regex;
use itertools::Itertools;
use petgraph::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::io::BufWriter;
use std::io::Write;
use std::path::PathBuf;
use std::{collections::HashMap, fs::File};
use thiserror::Error;

impl DecomposedRegexConfig {
    pub fn gen_circom(&self, circom_path: &PathBuf, template_name: &str) -> Result<(), VrmError> {
        let mut all_regex = String::new();
        let part_configs = &self.parts;
        for config in part_configs.iter() {
            all_regex += &config.regex_def;
        }
        let dfa_val = get_dfa_json_value(&all_regex)?;
        let mut circom = gen_circom_allstr(&dfa_val, template_name)?;
        circom += "\n";
        let (substr_defs_array, _, _) = self.extract_substr_ids(&dfa_val)?;
        for (idx, defs) in substr_defs_array.into_iter().enumerate() {
            // let mut valid_next_states = HashSet::new();
            circom += &format!("\tsignal output reveal{}[msg_bytes];\n", idx);
            circom += "\tfor (var i = 0; i < msg_bytes; i++) {\n";
            circom += &format!("\t\treveal{} <== in[i+1] * (", idx);
            for (j, (cur, next)) in defs.iter().enumerate() {
                circom += &format!("states[i+1][{}] * states[i+2][{}]", cur, next);
                if j != defs.len() - 1 {
                    circom += " + ";
                }
            }
            circom += ");\n\t}\n";
        }
        circom += "}";
        let mut circom_file = File::create(circom_path)?;
        write!(circom_file, "{}", circom)?;
        circom_file.flush()?;
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn circom1_test() {
        let regex_decomposed: DecomposedRegexConfig = serde_json::from_str(
            r#"
        {
            "max_byte_size": 128,
            "parts":[
                {
                    "is_public": false,
                    "regex_def": "email was meant for @",
                    "max_size": 21
                },
                {
                    "is_public": true,
                    "regex_def": "(a|b|c|d|e|f|g|h|i|j|k|l|m|n|o|p|q|r|s|t|u|v|w|x|y|z)+",
                    "max_size": 7,
                    "solidity": {
                        "type": "String"
                    }
                },
                {
                    "is_public": false,
                    "regex_def": ".",
                    "max_size": 1
                }
            ]
        }"#,
        )
        .unwrap();
        let circom_path = PathBuf::from("./test_regexes/test1_regex.circom");
        regex_decomposed
            .gen_circom(&circom_path, "Test1Regex")
            .unwrap();
    }
}
