use bitcoin::Txid;
use lightning::io;
use lightning::rgb_utils::{
	AssetSchema as SharedAssetSchema, ContractId, NativeRgbBackend, RgbBackendError,
	RgbFundingValidation, RgbTransport, RGB_PENDING_FASCIA_NS, RGB_PRIMARY_NS,
};
use lightning::util::persist::KVStoreSync;
use rgb_lib::keys::{generate_keys, WitnessVersion};
use rgb_lib::wallet::{DatabaseType, OnlineOptions, SinglesigKeys, Wallet, WalletData};
use rgb_lib::{AssetSchema, BitcoinNetwork};
use std::collections::HashMap;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Default)]
struct TestStore(Mutex<HashMap<(String, String, String), Vec<u8>>>);

impl KVStoreSync for TestStore {
	fn read(
		&self, primary_namespace: &str, secondary_namespace: &str, key: &str,
	) -> Result<Vec<u8>, io::Error> {
		self.0
			.lock()
			.unwrap()
			.get(&(primary_namespace.to_owned(), secondary_namespace.to_owned(), key.to_owned()))
			.cloned()
			.ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))
	}

	fn write(
		&self, primary_namespace: &str, secondary_namespace: &str, key: &str, buf: Vec<u8>,
	) -> Result<(), io::Error> {
		self.0.lock().unwrap().insert(
			(primary_namespace.to_owned(), secondary_namespace.to_owned(), key.to_owned()),
			buf,
		);
		Ok(())
	}

	fn remove(
		&self, primary_namespace: &str, secondary_namespace: &str, key: &str, _lazy: bool,
	) -> Result<(), io::Error> {
		self.0.lock().unwrap().remove(&(
			primary_namespace.to_owned(),
			secondary_namespace.to_owned(),
			key.to_owned(),
		));
		Ok(())
	}

	fn list(
		&self, primary_namespace: &str, secondary_namespace: &str,
	) -> Result<Vec<String>, io::Error> {
		Ok(self
			.0
			.lock()
			.unwrap()
			.keys()
			.filter(|(primary, secondary, _)| {
				primary == primary_namespace && secondary == secondary_namespace
			})
			.map(|(_, _, key)| key.clone())
			.collect())
	}
}

fn real_native_backend() -> (Arc<NativeRgbBackend>, PathBuf) {
	let unique = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
	let data_dir = std::env::temp_dir()
		.join(format!("rust-lightning-rgb-native-{}-{unique}", std::process::id()));
	let _ = std::fs::remove_dir_all(&data_dir);
	std::fs::create_dir_all(&data_dir).unwrap();
	let keys = generate_keys(BitcoinNetwork::Regtest, WitnessVersion::Taproot);
	let wallet = Wallet::new(
		WalletData {
			data_dir: data_dir.to_string_lossy().into_owned(),
			bitcoin_network: BitcoinNetwork::Regtest,
			database_type: DatabaseType::Sqlite,
			max_allocations_per_utxo: 5,
			supported_schemas: vec![
				AssetSchema::Nia,
				AssetSchema::Cfa,
				AssetSchema::Uda,
				AssetSchema::Ifa,
			],
			reuse_addresses: false,
		},
		SinglesigKeys::from_keys(&keys, None),
	)
	.unwrap();
	let backend = Arc::new(NativeRgbBackend::new(
		wallet,
		OnlineOptions {
			indexer_url: "http://127.0.0.1:1".to_owned(),
			skip_consistency_check: true,
			vanilla_sync_lookback: 20,
		},
	));
	(backend, data_dir)
}

#[tokio::test]
async fn native_backend_is_injected_and_reports_real_network_errors() {
	let (backend, data_dir) = real_native_backend();
	let result = backend
		.accept_funding_transfer(
			"0000000000000000000000000000000000000000000000000000000000000000".to_owned(),
			1,
			RgbTransport::RestHttp { tls: false, host: "127.0.0.1:1".to_owned() },
			None,
		)
		.await;
	assert!(matches!(
		result,
		Err(RgbBackendError::Network(_)) | Err(RgbBackendError::Unexpected(_))
	));

	std::fs::remove_dir_all(data_dir).unwrap();
}

#[tokio::test]
async fn failed_fascia_consumption_remains_pending_and_non_durable() {
	let (backend, data_dir) = real_native_backend();
	let store = Arc::new(TestStore::default());
	let txid =
		Txid::from_str("0000000000000000000000000000000000000000000000000000000000000001").unwrap();
	store
		.write(RGB_PRIMARY_NS, RGB_PENDING_FASCIA_NS, &txid.to_string(), b"invalid".to_vec())
		.unwrap();

	assert!(!backend.is_transaction_durable(&txid, store.as_ref()));
	assert!(backend.has_pending_transactions(store.as_ref()).unwrap());
	assert!(matches!(
		backend.process_pending_transactions(store.clone()).await,
		Err(RgbBackendError::Unexpected(_))
	));
	assert!(!backend.is_transaction_durable(&txid, store.as_ref()));
	assert!(backend.has_pending_transactions(store.as_ref()).unwrap());

	std::fs::remove_dir_all(data_dir).unwrap();
}

#[test]
fn funding_validation_recovery_record_round_trips() {
	let validation = RgbFundingValidation {
		consignment: vec![1, 2, 3, 4],
		contract_id: ContractId::copy_from_slice(&[42; 32]).unwrap(),
		schema: SharedAssetSchema::Nia,
		received_amount: 1_000,
	};
	let encoded = bincode::serialize(&validation).unwrap();
	let decoded: RgbFundingValidation = bincode::deserialize(&encoded).unwrap();
	assert_eq!(decoded, validation);
}

/// A [`KVStoreSync`] whose mutating operations always fail, used to verify that the RGB
/// persistence helpers propagate the error instead of panicking. This matters for the browser
/// `localStorage` backend, where writes can fail (e.g. quota exceeded) mid-commitment — a panic
/// there would abort the whole WASM module.
struct FailingStore;

impl KVStoreSync for FailingStore {
	fn read(&self, _: &str, _: &str, _: &str) -> Result<Vec<u8>, io::Error> {
		Err(io::Error::new(io::ErrorKind::Other, "simulated read failure"))
	}
	fn write(&self, _: &str, _: &str, _: &str, _: Vec<u8>) -> Result<(), io::Error> {
		Err(io::Error::new(io::ErrorKind::Other, "simulated write failure"))
	}
	fn remove(&self, _: &str, _: &str, _: &str, _: bool) -> Result<(), io::Error> {
		Err(io::Error::new(io::ErrorKind::Other, "simulated remove failure"))
	}
	fn list(&self, _: &str, _: &str) -> Result<Vec<String>, io::Error> {
		Ok(Vec::new())
	}
}

#[test]
fn rgb_persistence_helpers_propagate_store_errors_instead_of_panicking() {
	use lightning::rgb_utils::{RgbInfo, RgbKvStoreExt, TransferInfo};

	let store = FailingStore;
	let contract_id = ContractId::copy_from_slice(&[7; 32]).unwrap();

	// These helpers previously `.expect(...)`-panicked on any KVStore failure. They must now
	// surface the error so the coloring path closes the channel instead of aborting the node.
	let transfer_info = TransferInfo { contract_id, rgb_amount: 100 };
	assert!(store.write_rgb_transfer_info("txid", &transfer_info).is_err());
	assert!(store.read_rgb_transfer_info("txid").is_err());

	let rgb_info = RgbInfo {
		contract_id,
		schema: SharedAssetSchema::Nia,
		local_rgb_amount: 10,
		remote_rgb_amount: 20,
		batch_transfer_idx: None,
	};
	assert!(store.write_rgb_channel_info("chan", &rgb_info, true).is_err());
	assert!(store.write_rgb_consignment("chan", vec![1, 2, 3]).is_err());
	assert!(store.remove_rgb_consignment("chan").is_err());
}
