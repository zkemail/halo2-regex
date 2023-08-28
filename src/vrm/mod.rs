use std::{collections::HashMap, fs::File};
mod circom;
mod js_caller;
use crate::vrm::js_caller::*;
use crate::{AllstrRegexDef, SubstrRegexDef};
use fancy_regex::Regex;
use itertools::Itertools;
use petgraph::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashSet;
use std::io::BufWriter;
use std::io::Write;
use std::path::PathBuf;
use thiserror::Error;

/// Error definitions related to VRM.
#[derive(Error, Debug)]
pub enum VrmError {
    #[error("No edge from {:?} to {:?} in the graph",.0,.1)]
    NoEdge(NodeIndex<usize>, NodeIndex<usize>),
    #[error(transparent)]
    JsCallerError(#[from] JsCallerError),
    #[error(transparent)]
    IoError(#[from] std::io::Error),
    #[error(transparent)]
    RegexError(#[from] fancy_regex::Error),
}

/// A configuration of decomposed regexes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecomposedRegexConfig {
    /// Maximum byte size of the input string.
    pub max_byte_size: usize,
    /// A vector of decomposed regexes.
    pub parts: Vec<RegexPartConfig>,
}

/// Decomposed regex part.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegexPartConfig {
    /// A flag indicating whether the substring matching with `regex_def` should be exposed.
    pub is_public: bool,
    /// A regex string.
    pub regex_def: String,
    /// Maximum byte size of the substring in this part.
    pub max_size: usize,
    /// (Optional) A solidity type of the substring in this part, e.g., "String", "Int", "Decimal".
    pub solidity: Option<SoldityType>,
}

/// Solidity type of the substring.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum SoldityType {
    String,
    Uint,
    Decimal,
}

impl DecomposedRegexConfig {
    /// Generate text files for [`AllstrRegexDef`] and [`SubstrRegexDef`].
    ///
    /// # Arguments
    /// * `allstr_file_path` - a file path of the text file for [`AllstrRegexDef`].
    /// * `substr_file_pathes` - a vector of the text files for [`SubstrRegexDef`].
    pub fn gen_regex_files(
        &self,
        allstr_file_path: &PathBuf,
        substr_file_pathes: &[PathBuf],
    ) -> Result<(), VrmError> {
        // let catch_all = catch_all_regex_str()?;
        // let first_part = RegexPartConfig {
        //     is_public: false,
        //     regex_def: "(".to_string() + catch_all.as_str() + "+)?",
        //     max_size: self.max_byte_size,
        //     solidity: None,
        // };
        // let last_part = RegexPartConfig {
        //     is_public: false,
        //     regex_def: "(".to_string() + catch_all.as_str() + "+)?",
        //     max_size: self.max_byte_size,
        //     solidity: None,
        // };
        let mut all_regex = String::new();
        let part_configs = &self.parts;
        for config in part_configs.iter() {
            all_regex += &config.regex_def;
        }
        let dfa_val = get_dfa_json_value(&all_regex)?;
        let regex_text = dfa_to_regex_def_text(&dfa_val)?;
        let mut regex_file = File::create(allstr_file_path)?;
        write!(regex_file, "{}", regex_text)?;
        regex_file.flush()?;

        // let mut graph = Graph::<bool, String, Directed, usize>::with_capacity(0, 0);
        // let max_state = get_max_state(&dfa_val)?;
        // add_graph_nodes(&dfa_val, &mut graph, None, max_state)?;
        // let accepted_state = get_accepted_state(&dfa_val).ok_or(JsCallerError::NoAcceptedState)?;

        // // let mut remove_edges = HashSet::new();
        // // graph.visit_all_cycles(|g, cycle_nodes| {
        // //     if cycle_nodes.len() == 1 {
        // //         return;
        // //     }
        // //     // println!("cycles {:?}", cycle_nodes);
        // //     let n = cycle_nodes.len();
        // //     let e = g.find_edge(cycle_nodes[n - 1], cycle_nodes[0]).unwrap();
        // //     remove_edges.insert(e);
        // // });
        // let accepted_state_index = NodeIndex::from(accepted_state);
        // let mut pathes = Vec::<Vec<NodeIndex<usize>>>::new();
        // let mut stack = Vec::<(NodeIndex<usize>, Vec<NodeIndex<usize>>)>::new();
        // stack.push((accepted_state_index, vec![accepted_state_index]));
        // let mut self_nodes = HashSet::new();
        // let mut self_nodes_char = HashMap::new();
        // for state in 0..=max_state {
        //     let node = NodeIndex::from(state);
        //     if let Some(edge) = graph.find_edge(node, node) {
        //         let str = graph.edge_weight(edge).unwrap().as_str();
        //         let bytes = str.as_bytes();
        //         self_nodes_char.insert(node.index(), bytes[0] as char);
        //     }
        // }

        // while stack.len() != 0 {
        //     let (node, path) = stack.pop().unwrap();
        //     let mut parents = graph.neighbors(node).detach();
        //     while let Some((edge, parent)) = parents.next(&graph) {
        //         if parent.index() == node.index() {
        //             self_nodes.insert(node.index());
        //             graph.remove_edge(edge).unwrap();
        //             continue;
        //         }
        //         if !path.contains(&parent) {
        //             if parent.index() == 0 {
        //                 pathes.push(path.to_vec());
        //                 continue;
        //             }
        //             stack.push((parent, vec![path.clone(), vec![parent]].concat()));
        //         }
        //     }
        // }

        // let mut public_config_indexes: Vec<usize> = vec![];
        // let mut part_regexes = vec![];
        // for (idx, config) in part_configs.iter().enumerate() {
        //     if config.is_public {
        //         public_config_indexes.push(idx);
        //     }
        //     if idx == 0 {
        //         part_regexes.push(Regex::new(&format_regex_str(&config.regex_def)?)?);
        //     } else {
        //         let pre_regex = part_regexes[idx - 1].to_string();
        //         part_regexes.push(Regex::new(
        //             &(pre_regex + &format_regex_str(&config.regex_def)?),
        //         )?);
        //     }
        // }
        // let num_public_parts = public_config_indexes.len();
        // debug_assert_eq!(num_public_parts, substr_file_pathes.len());
        // let mut substr_defs_array = (0..num_public_parts)
        //     .map(|_| HashSet::<(usize, usize)>::new())
        //     .collect_vec();
        // let mut substr_endpoints_array = (0..num_public_parts)
        //     .map(|_| (HashSet::<usize>::new(), HashSet::<usize>::new()))
        //     .collect_vec();
        // for path in pathes.iter_mut() {
        //     let n = path.len();
        //     path.append(&mut vec![NodeIndex::from(0)]);
        //     let edges = (0..n)
        //         .map(|idx| {
        //             graph
        //                 .find_edge(path[idx], path[idx + 1])
        //                 .ok_or(VrmError::NoEdge(path[idx], path[idx + 1]))
        //         })
        //         .collect::<Result<Vec<EdgeIndex<usize>>, VrmError>>()?;
        //     let string_vec = edges
        //         .iter()
        //         .map(|edge| graph.edge_weight(*edge).unwrap().as_str())
        //         .collect::<Vec<&str>>();
        //     let path_states = path
        //         .into_iter()
        //         .rev()
        //         .map(|node| node.index())
        //         .collect::<Vec<usize>>();
        //     let path_strs = string_vec
        //         .iter()
        //         .rev()
        //         .map(|s| s.to_string())
        //         .collect::<Vec<String>>();
        //     // for (idx, state) in path_states.iter().enumerate() {
        //     //     println!("idx {} state {}", idx, state,);
        //     // }
        //     // for (idx, str) in path_strs.iter().enumerate() {
        //     //     println!(
        //     //         "idx {} byte {} str {}",
        //     //         idx,
        //     //         str.as_bytes()[0],
        //     //         (str.as_bytes()[0] as char)
        //     //     );
        //     // }

        //     let substr_states = self.get_substr_defs_from_path(
        //         &path_states,
        //         &path_strs,
        //         &part_regexes,
        //         &public_config_indexes,
        //     )?;
        //     for (substr_idx, (path_states, substr)) in substr_states.into_iter().enumerate() {
        //         // println!(
        //         //     "substr_idx {}, path_states {:?}, substr {}",
        //         //     substr_idx, path_states, substr
        //         // );
        //         let defs = &mut substr_defs_array[substr_idx];
        //         substr_endpoints_array[substr_idx].0.insert(path_states[0]);
        //         substr_endpoints_array[substr_idx]
        //             .1
        //             .insert(path_states[path_states.len() - 1]);
        //         for path_idx in 0..(path_states.len() - 1) {
        //             defs.insert((path_states[path_idx], path_states[path_idx + 1]));
        //             if self_nodes.contains(&path_states[path_idx]) {
        //                 defs.insert((path_states[path_idx], path_states[path_idx]));
        //             }
        //             for pre_path_idx in 0..=path_idx {
        //                 if graph
        //                     .find_edge(
        //                         NodeIndex::from(path_states[path_idx + 1]),
        //                         NodeIndex::from(path_states[pre_path_idx]),
        //                     )
        //                     .is_some()
        //                 {
        //                     defs.insert((path_states[path_idx + 1], path_states[pre_path_idx]));
        //                 }
        //             }

        //             // println!("{} {}", substr_def_array[idx], substr_def_array[idx + 1],);
        //         }
        //         if self_nodes.contains(&path_states[path_states.len() - 1]) {
        //             let part_index = public_config_indexes[substr_idx];
        //             let part_regex = &part_regexes[part_index];
        //             let substr =
        //                 substr + &self_nodes_char[&path_states[path_states.len() - 1]].to_string();
        //             if part_regex.is_match(&substr).unwrap() {
        //                 defs.insert((
        //                     path_states[path_states.len() - 1],
        //                     path_states[path_states.len() - 1],
        //                 ));
        //             }
        //         }
        //     }
        // }
        // for index in self_nodes.iter() {
        //     // println!("self index {}", index);
        //     for defs in substr_defs_array.iter_mut() {
        //         if defs
        //             .iter()
        //             .find(|def| (def.0 == *index || def.1 == *index) && !def.2)
        //             .is_some()
        //         {
        //             defs.insert((*index, *index, false));
        //         }
        //     }
        // }
        // println!("{:?}", substr_defs_array);
        let (substr_defs_array, substr_endpoints_array, public_config_indexes) =
            self.extract_substr_ids(&dfa_val)?;
        for (idx, defs) in substr_defs_array.into_iter().enumerate() {
            let mut writer = BufWriter::new(File::create(&substr_file_pathes[idx])?);
            let max_size = &part_configs[public_config_indexes[idx]].max_size;
            writer.write_fmt(format_args!("{}\n", &max_size))?;
            writer.write_fmt(format_args!("0\n{}\n", self.max_byte_size - 1))?;
            let mut starts_str = "".to_string();
            let starts = substr_endpoints_array[idx]
                .0
                .iter()
                .sorted_by(|a, b| a.cmp(b));
            for start in starts {
                starts_str += &format!("{} ", start);
            }
            writer.write_fmt(format_args!("{}\n", starts_str))?;
            let mut ends_str = "".to_string();
            let ends = substr_endpoints_array[idx]
                .1
                .iter()
                .sorted_by(|a, b| a.cmp(b));
            for end in ends {
                ends_str += &format!("{} ", end);
            }
            writer.write_fmt(format_args!("{}\n", ends_str))?;
            let mut defs = defs.iter().collect::<Vec<&(usize, usize)>>();
            defs.sort_by(|a, b| {
                let start_cmp = a.0.cmp(&b.0);
                let end_cmp = a.1.cmp(&b.1);
                if start_cmp == std::cmp::Ordering::Equal {
                    end_cmp
                } else {
                    start_cmp
                }
            });
            for (cur, next) in defs.iter() {
                writer.write_fmt(format_args!("{} {}\n", cur, next))?;
            }
        }
        // println!("pathes {:?}", pathes);
        Ok(())
    }

    pub fn extract_substr_ids(
        &self,
        dfa_val: &[Value],
    ) -> Result<
        (
            Vec<HashSet<(usize, usize)>>,
            Vec<(HashSet<usize>, HashSet<usize>)>,
            Vec<usize>,
        ),
        VrmError,
    > {
        // let catch_all = catch_all_regex_str()?;
        // let first_part = RegexPartConfig {
        //     is_public: false,
        //     regex_def: "(".to_string() + catch_all.as_str() + "+)?",
        //     max_size: self.max_byte_size,
        //     solidity: None,
        // };
        // let last_part = RegexPartConfig {
        //     is_public: false,
        //     regex_def: "(".to_string() + catch_all.as_str() + "+)?",
        //     max_size: self.max_byte_size,
        //     solidity: None,
        // };
        let part_configs = &self.parts;

        let mut graph = Graph::<bool, String, Directed, usize>::with_capacity(0, 0);
        let max_state = get_max_state(dfa_val)?;
        add_graph_nodes(dfa_val, &mut graph, None, max_state)?;
        let accepted_state = get_accepted_state(dfa_val).ok_or(JsCallerError::NoAcceptedState)?;

        // let mut remove_edges = HashSet::new();
        // graph.visit_all_cycles(|g, cycle_nodes| {
        //     if cycle_nodes.len() == 1 {
        //         return;
        //     }
        //     // println!("cycles {:?}", cycle_nodes);
        //     let n = cycle_nodes.len();
        //     let e = g.find_edge(cycle_nodes[n - 1], cycle_nodes[0]).unwrap();
        //     remove_edges.insert(e);
        // });
        let accepted_state_index = NodeIndex::from(accepted_state);
        let mut pathes = Vec::<Vec<NodeIndex<usize>>>::new();
        let mut stack = Vec::<(NodeIndex<usize>, Vec<NodeIndex<usize>>)>::new();
        stack.push((accepted_state_index, vec![accepted_state_index]));
        let mut self_nodes = HashSet::new();
        let mut self_nodes_char = HashMap::new();
        for state in 0..=max_state {
            let node = NodeIndex::from(state);
            if let Some(edge) = graph.find_edge(node, node) {
                let str = graph.edge_weight(edge).unwrap().as_str();
                let bytes = str.as_bytes();
                // println!("byte {} {}", bytes[0], "^".as_bytes()[0]);
                // let char = if bytes[0] == b"^"[0] || bytes[0] == b"$"[0] {
                //     0 as char
                // } else {
                //     bytes[0] as char
                // };
                // println!("char {}", char);
                self_nodes_char.insert(node.index(), bytes[0]);
            }
        }

        while stack.len() != 0 {
            let (node, path) = stack.pop().unwrap();
            let mut parents = graph.neighbors(node).detach();
            while let Some((edge, parent)) = parents.next(&graph) {
                if parent.index() == node.index() {
                    self_nodes.insert(node.index());
                    graph.remove_edge(edge).unwrap();
                    continue;
                }
                if !path.contains(&parent) {
                    if parent.index() == 0 {
                        pathes.push(path.to_vec());
                        continue;
                    }
                    stack.push((parent, vec![path.clone(), vec![parent]].concat()));
                }
            }
        }

        let mut public_config_indexes: Vec<usize> = vec![];
        let mut part_regexes = vec![];
        for (idx, config) in part_configs.iter().enumerate() {
            if config.is_public {
                public_config_indexes.push(idx);
            }
            if idx == 0 {
                part_regexes.push(Regex::new(&format_regex_str(&config.regex_def)?)?);
            } else {
                let pre_regex = part_regexes[idx - 1].to_string();
                part_regexes.push(Regex::new(
                    &(pre_regex + &format_regex_str(&config.regex_def)?),
                )?);
            }
        }
        let num_public_parts = public_config_indexes.len();
        // debug_assert_eq!(num_public_parts, substr_file_pathes.len());
        let mut substr_defs_array = (0..num_public_parts)
            .map(|_| HashSet::<(usize, usize)>::new())
            .collect_vec();
        let mut substr_endpoints_array = (0..num_public_parts)
            .map(|_| (HashSet::<usize>::new(), HashSet::<usize>::new()))
            .collect_vec();
        for path in pathes.iter_mut() {
            let n = path.len();
            path.append(&mut vec![NodeIndex::from(0)]);
            let edges = (0..n)
                .map(|idx| {
                    graph
                        .find_edge(path[idx], path[idx + 1])
                        .ok_or(VrmError::NoEdge(path[idx], path[idx + 1]))
                })
                .collect::<Result<Vec<EdgeIndex<usize>>, VrmError>>()?;
            let string_vec = edges
                .iter()
                .map(|edge| graph.edge_weight(*edge).unwrap().as_str())
                .collect::<Vec<&str>>();
            let path_states = path
                .into_iter()
                .rev()
                .map(|node| node.index())
                .collect::<Vec<usize>>();
            let path_strs = string_vec
                .iter()
                .rev()
                .map(|s| s.to_string())
                .collect::<Vec<String>>();
            // for (idx, state) in path_states.iter().enumerate() {
            //     println!("idx {} state {}", idx, state,);
            // }
            // for (idx, str) in path_strs.iter().enumerate() {
            //     println!(
            //         "idx {} byte {} str {}",
            //         idx,
            //         str.as_bytes()[0],
            //         (str.as_bytes()[0] as char)
            //     );
            // }

            let substr_states = self.get_substr_defs_from_path(
                &path_states,
                &path_strs,
                &part_regexes,
                &public_config_indexes,
            )?;
            for (substr_idx, (path_states, substr)) in substr_states.into_iter().enumerate() {
                // println!(
                //     "substr_idx {}, path_states {:?}, substr {}",
                //     substr_idx, path_states, substr
                // );
                let defs = &mut substr_defs_array[substr_idx];
                substr_endpoints_array[substr_idx].0.insert(path_states[0]);
                substr_endpoints_array[substr_idx]
                    .1
                    .insert(path_states[path_states.len() - 1]);
                for path_idx in 0..(path_states.len() - 1) {
                    defs.insert((path_states[path_idx], path_states[path_idx + 1]));
                    if self_nodes.contains(&path_states[path_idx]) {
                        defs.insert((path_states[path_idx], path_states[path_idx]));
                    }
                    for pre_path_idx in 0..=path_idx {
                        if graph
                            .find_edge(
                                NodeIndex::from(path_states[pre_path_idx]),
                                NodeIndex::from(path_states[path_idx + 1]),
                            )
                            .is_some()
                        {
                            defs.insert((path_states[path_idx + 1], path_states[pre_path_idx]));
                        }
                    }

                    // println!("{} {}", substr_def_array[idx], substr_def_array[idx + 1],);
                }
                if self_nodes.contains(&path_states[path_states.len() - 1]) {
                    let part_index = public_config_indexes[substr_idx];
                    let part_regex = &part_regexes[part_index];
                    let byte = self_nodes_char[&path_states[path_states.len() - 1]];
                    let substr = substr + &(byte as char).to_string();
                    if part_regex.is_match(&substr).unwrap() {
                        defs.insert((
                            path_states[path_states.len() - 1],
                            path_states[path_states.len() - 1],
                        ));
                    }
                }
            }
        }
        // for index in self_nodes.iter() {
        //     // println!("self index {}", index);
        //     for defs in substr_defs_array.iter_mut() {
        //         if defs
        //             .iter()
        //             .find(|def| (def.0 == *index || def.1 == *index) && !def.2)
        //             .is_some()
        //         {
        //             defs.insert((*index, *index, false));
        //         }
        //     }
        // }
        // println!("{:?}", substr_defs_array);

        // for (idx, defs) in substr_defs_array.into_iter().enumerate() {
        //     let mut writer = BufWriter::new(File::create(&substr_file_pathes[idx])?);
        //     let max_size = &part_configs[public_config_indexes[idx]].max_size;
        //     writer.write_fmt(format_args!("{}\n", &max_size))?;
        //     writer.write_fmt(format_args!("0\n{}\n", self.max_byte_size - 1))?;
        //     let mut starts_str = "".to_string();
        //     for start in substr_endpoints_array[idx].0.iter() {
        //         starts_str += &format!("{} ", start);
        //     }
        //     writer.write_fmt(format_args!("{}\n", starts_str))?;
        //     let mut ends_str = "".to_string();
        //     for end in substr_endpoints_array[idx].1.iter() {
        //         ends_str += &format!("{} ", end);
        //     }
        //     writer.write_fmt(format_args!("{}\n", ends_str))?;
        //     for (cur, next) in defs.iter() {
        //         writer.write_fmt(format_args!("{} {}\n", cur, next))?;
        //     }
        // }
        Ok((
            substr_defs_array,
            substr_endpoints_array,
            public_config_indexes,
        ))
    }

    fn get_substr_defs_from_path(
        &self,
        path_states: &[usize],
        path_strs: &[String],
        part_regexes: &[Regex],
        public_config_indexes: &[usize],
    ) -> Result<Vec<(Vec<usize>, String)>, VrmError> {
        debug_assert_eq!(path_states.len(), path_strs.len() + 1);
        let mut concat_str = String::new();
        for str in path_strs.into_iter() {
            let first_chars = str.as_bytes();
            concat_str += &(first_chars[0] as char).to_string();
            // println!("concat_str {:?}", concat_str.as_bytes());
        }
        let index_ends = part_regexes
            .iter()
            .map(|regex| {
                // println!(
                //     "whitespace {:?}",
                //     Regex::new(r#"a(0|1|2|3|4|5|6|7|8|9|a|b|c|d|e|f|g|h|i|j|k|l|m|n|o|p|q|r|s|t|u|v|w|x|y|z|A|B|C|D|E|F|G|H|I|J|K|L|M|N|O|P|Q|R|S|T|U|V|W|X|Y|Z|!|\"|#|%|&|'|\(|\)|\*|\+|,|-|\.|\/|:|;|<|=|>|\?|@|\[|\\|\]|_|`|{|}|~|\t| )+"#)
                //         .unwrap()
                //         .find("a")
                //         .unwrap()
                //         .unwrap()
                //         .as_str()
                //         .as_bytes()
                // );
                // println!(
                //     "regex {}, found {:?} end {}",
                //     regex.as_str(),
                //     regex
                //         .find(&concat_str)
                //         .unwrap()
                //         .unwrap()
                //         .as_str()
                //         .as_bytes(),
                //     regex.find(&concat_str).unwrap().unwrap().end()
                // );
                let found = regex.find(&concat_str).unwrap().unwrap();
                if found.start() == found.end() {
                    found.end() + 1
                } else {
                    found.end()
                }
            })
            .collect_vec();
        let mut substr_results = vec![];
        for index in public_config_indexes.iter() {
            let start = if *index == 0 {
                0
            } else {
                index_ends[index - 1]
            };
            let end = index_ends[*index];
            // println!("start {} end {}", start, end);
            substr_results.push((
                path_states[(start)..=end].to_vec(),
                concat_str[0..=(end - 1)].to_string(),
            ));
        }
        Ok(substr_results)
    }
}
