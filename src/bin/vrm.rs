use std::{
    fs::File,
    path::{Path, PathBuf},
};

use clap::{Parser, Subcommand};
#[cfg(feature = "vrm")]
use halo2_regex::vrm::*;
use itertools::Itertools;

#[cfg(feature = "vrm")]
#[derive(Parser, Debug, Clone)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[cfg(feature = "vrm")]
#[derive(Debug, Subcommand, Clone)]
enum Commands {
    GenHalo2Texts {
        #[arg(short, long)]
        decomposed_regex_path: String,
        #[arg(short, long)]
        allstr_file_path: String,
        #[arg(short, long)]
        substrs_dir_path: String,
    },
    GenCircom {
        #[arg(short, long)]
        decomposed_regex_path: String,
        #[arg(short, long)]
        circom_file_path: String,
        #[arg(short, long)]
        template_name: String,
    },
}
#[cfg(feature = "vrm")]
fn main() {
    let cli = Cli::parse();
    match cli.command {
        Commands::GenHalo2Texts {
            decomposed_regex_path,
            allstr_file_path,
            substrs_dir_path,
        } => {
            let regex_decomposed: DecomposedRegexConfig =
                serde_json::from_reader(File::open(decomposed_regex_path).unwrap()).unwrap();
            let num_public_part = regex_decomposed
                .parts
                .iter()
                .filter(|part| part.is_public)
                .collect_vec()
                .len();
            let substr_file_pathes = (0..num_public_part)
                .map(|idx| {
                    PathBuf::new()
                        .join(&substrs_dir_path)
                        .join(&format!("substr{}.txt", idx))
                })
                .collect_vec();
            regex_decomposed
                .gen_regex_files(
                    &Path::new(&allstr_file_path).to_path_buf(),
                    &substr_file_pathes,
                )
                .unwrap();
        }
        Commands::GenCircom {
            decomposed_regex_path,
            circom_file_path,
            template_name,
        } => {
            let regex_decomposed: DecomposedRegexConfig =
                serde_json::from_reader(File::open(decomposed_regex_path).unwrap()).unwrap();
            let circom_path = PathBuf::from(circom_file_path);
            regex_decomposed
                .gen_circom(&circom_path, &template_name)
                .unwrap();
        }
    }
}

#[cfg(not(feature = "vrm"))]
fn main() {
    panic!("Please enable vrm feature to commands");
}
