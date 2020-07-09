use algebra_core::{CanonicalDeserialize, CanonicalSerialize};
use groth16::Parameters as Groth16Parameters;


use epoch_snark::{prove, BLSCurve, CPCurve, EpochBlock, EpochTransition, Parameters};
use bls_crypto::Signature;

use ethers_core::{types::U256, utils::rlp};
use ethers_providers::*;

use gumdrop::Options;
use std::{
    convert::TryFrom,
    fs::File,
    io::{BufReader, BufWriter},
    path::PathBuf,
    sync::Arc,
};
use tracing_subscriber::{
    filter::EnvFilter,
    fmt::{time::ChronoUtc, Subscriber},
};

mod types;
use types::HeaderExtra;

#[derive(Debug, Options, Clone)]
pub struct PlumoOpts {
    help: bool,

    #[options(help = "the celo node's endpoint", default = "http://localhost:8545")]
    pub node_url: String,

    #[options(help = "the duration of an epoch (in blocks)", default = "17280")]
    pub epoch_duration: usize,

    #[options(help = "the first block in the range being proven")]
    pub start_block: u64,

    #[options(help = "the last block in the range being proven")]
    pub end_block: u64,

    #[options(help = "path to the proving key for the BLS SNARK")]
    pub epoch_proving_key: PathBuf,

    #[options(help = "path to the proving key for the CRH -> XOF SNARK")]
    pub hash_to_bits_proving_key: Option<PathBuf>,

    #[options(help = "path where the proof will be saved at")]
    pub proof_path: PathBuf,

    #[options(help = "the number of validators")]
    pub num_validators: u32,

    #[options(help = "the max allowed faults")]
    pub maximum_non_signers: u32,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // initialize the logger
    Subscriber::builder()
        .with_timer(ChronoUtc::rfc3339())
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    // parse the cli args
    let opts = PlumoOpts::parse_args_default_or_exit();
    let maximum_non_signers = opts.maximum_non_signers;
    let num_validators = opts.num_validators;

    // initialize the provider
    let provider = Arc::new(Provider::<Http>::try_from(opts.node_url)?);

    // grab all the state transitions
    let futs = (opts.start_block..=opts.end_block)
        .step_by(opts.epoch_duration)
        .enumerate()
        .map(|(i, num)| {
            let provider = provider.clone();
            async move {
                // get the block & decode the epoch data from the header's extra
                let block = provider.get_block(num).await.expect("could not get block");
                let epoch = rlp::decode::<HeaderExtra>(&block.extra_data.0)
                    .expect("could not decode extras");

                // Get the bitmap / signature
                let bitmap = {
                    let bitmap_num = U256::from(&block.epoch_snark_data.bitmap.0[..]);
                    let mut bitmap = Vec::new();
                    for i in 0..256 {
                        bitmap.push(bitmap_num.bit(i));
                    }
                    bitmap
                };

                let signature = block.epoch_snark_data.signature;
                let aggregate_signature = Signature::deserialize(&mut &signature.0[..])
                    .expect("could not deserialize signature - your header snark data is corrupt");

                // construct the epoch block transition
                EpochTransition {
                    block: EpochBlock {
                        index: i as u16,
                        maximum_non_signers,
                        new_public_keys: epoch.added_validators_pubkeys,
                    },
                    aggregate_signature,
                    bitmap,
                }
            }
        })
        .collect::<Vec<_>>();

    let mut transitions = futures_util::future::join_all(futs).await;
    let first_epoch = transitions.remove(0).block;

    // load the proving key(s)
    let mut file = BufReader::new(File::open(opts.epoch_proving_key)?);
    let epoch_proving_key = Groth16Parameters::<CPCurve>::deserialize(&mut file).unwrap();

    let hash_to_bits_proving_key = if let Some(path) = opts.hash_to_bits_proving_key {
        let mut file = BufReader::new(File::open(path)?);
        Some(Groth16Parameters::<BLSCurve>::deserialize(&mut file).unwrap())
    } else {
        None
    };

    let parameters = Parameters {
        epochs: epoch_proving_key,
        hash_to_bits: hash_to_bits_proving_key,
    };

    let proof = prove(&parameters, num_validators, &first_epoch, &transitions)
        .expect("could not generate zkp");

    let mut file = BufWriter::new(File::create(opts.proof_path)?);
    proof.serialize(&mut file)?;

    println!("OK!");
    Ok(())
}
