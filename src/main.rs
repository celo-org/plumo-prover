use algebra_core::{CanonicalDeserialize, CanonicalSerialize};
use groth16::Parameters as Groth16Parameters;
use bls_crypto::{PublicKey as BlsPubkey, Signature, hash_to_curve::try_and_increment::COMPOSITE_HASH_TO_G1};


use epoch_snark::{trusted_setup, prove, BLSCurve, CPCurve, EpochBlock, EpochTransition, Parameters};

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

    let provider = Arc::new(Provider::<Http>::try_from("http://52.188.172.83:8545")?);

        let futs = (25u64..35)
            .step_by(1)
            .enumerate()
            .map(|(i, epoch_index)| {
                let provider = provider.clone();
                async move {
                    let previous_num = (epoch_index-1)*17280;
                    let num = epoch_index*17280;
                    println!("nums: {}, {}", previous_num, num);

                    let block = provider.get_block(num).await.expect("could not get block");
                    //println!("block: {:?}", block);
                    let previous_validators = provider.get_validators_public_keys(format!("0x{:x}", previous_num+1)).await.expect("could not get validators");
                    let previous_validators_keys = previous_validators.into_iter().map(|s| BlsPubkey::deserialize(&mut std::io::Cursor::new(&s))).collect::<Result<Vec<_>, _>>().unwrap();
                    let validators = provider.get_validators_public_keys(format!("0x{:x}", num+1)).await.expect("could not get validators");
                    let validators_keys = validators.into_iter().map(|s| BlsPubkey::deserialize(&mut std::io::Cursor::new(&s))).collect::<Result<Vec<_>, _>>().unwrap();
                    //println!("valiators keys: {}", validators_keys.len());
                    println!("valiators: {}", previous_validators_keys == validators_keys);

                    // Get the bitmap / signature
                    let bitmap = {
                        let bitmap_num = U256::from(&block.epoch_snark_data.bitmap.0[..]);
                        let mut bitmap = Vec::new();
                        for i in 0..256 {
                            bitmap.push(bitmap_num.bit(i));
                        }
                        bitmap
                    };
                    //println!("bitmap: {:?}", bitmap);

                    let signature = block.epoch_snark_data.signature;
                    let aggregate_signature = Signature::deserialize(&mut &signature.0[..])
                        .expect("could not deserialize signature - your header snark data is corrupt");
                    //for i in 0..100 {
                    let i = 33;
                        let epoch_block = EpochBlock {
                            index: epoch_index as u16,
                            maximum_non_signers: i,
                            new_public_keys: validators_keys.clone(),
                        };
                        let bytes = epoch_block.encode_to_bytes().unwrap();
                        let mut participating_keys = vec![];
                        for (j, b) in bitmap.iter().enumerate() {
                            if *b {
                                participating_keys.push(previous_validators_keys[j].clone());
                            }
                        }
                        let aggregated_key = BlsPubkey::aggregate(&participating_keys);
                        let res = aggregated_key.verify(
                            &bytes,
                            &[],
                            &aggregate_signature,
                            &*COMPOSITE_HASH_TO_G1,
                        ).unwrap();
                        println!("epoch {}: num non signers {}, num keys {}", epoch_index, i, validators_keys.len());
                    //}
                    
                    // construct the epoch block transition
                    EpochTransition {
                        block: EpochBlock {
                            index: epoch_index as u16,
                            maximum_non_signers: i,
                            new_public_keys: validators_keys,
                        },
                        aggregate_signature,
                        bitmap,
                    }
                }
            })
            .collect::<Vec<_>>();

    for epoch_index in 25u64..35 {
        println!("epoch {}", epoch_index);



    }

        /*
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
                    let validators = provider.get_validators(num).await.expect("could not get validators");

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
        */
        let mut transitions = futures_util::future::join_all(futs).await;
        let first_epoch = transitions.remove(0).block;
    let num_validators = 100u32;
        let epoch_proving_key = trusted_setup(num_validators as usize, 10, 33, &mut rand::thread_rng(), false).unwrap().epochs;

        let parameters = Parameters {
            epochs: epoch_proving_key,
            hash_to_bits: None,
        };

        let proof = prove(&parameters, num_validators, &first_epoch, &transitions)
            .expect("could not generate zkp");

        let mut file = BufWriter::new(File::create("./proof")?);
        proof.serialize(&mut file)?;

        println!("OK!");
        Ok(())
}
