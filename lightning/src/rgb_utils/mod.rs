//! A module to provide RGB functionality

use crate::ln::chan_utils::{
	get_countersigner_payment_script, BuiltCommitmentTransaction, ClosingTransaction,
	CommitmentTransaction, HTLCOutputInCommitment,
};
use crate::ln::channel::{ChannelContext, ChannelError, FundingScope};
use crate::ln::channel_state::ChannelDetails;
use crate::ln::types::ChannelId;
use crate::sign::SignerProvider;
use crate::types::features::ChannelTypeFeatures;
use crate::types::payment::PaymentHash;
use crate::util::persist::KVStoreSync;

use bitcoin::blockdata::transaction::Transaction;
use bitcoin::hex::DisplayHex;
use bitcoin::psbt::{ExtractTxError, Psbt};
use bitcoin::secp256k1::PublicKey;
use bitcoin::{Network, ScriptBuf, TxOut};
#[cfg(all(feature = "rgb-wasm", not(feature = "rgb-native")))]
use std::collections::HashSet;

/// RGB contract identifier shared with BOLT11 invoices and both wallet backends.
pub use lightning_invoice::ContractId;
#[cfg(all(feature = "rgb-native", not(feature = "rgb-wasm")))]
use rgb_lib::{
	bitcoin::psbt::Psbt as RgbLibPsbt,
	utils::recipient_id_from_script_buf as native_recipient_id_from_script_buf,
	wallet::{
		rust_only::{
			AssetColoringInfo as NativeAssetColoringInfo, ColoringInfo as NativeColoringInfo,
		},
		OnlineOptions, Recipient as NativeRecipient, TransportEndpoint as NativeTransportEndpoint,
		Wallet, WitnessData as NativeWitnessData,
	},
	AssetSchema as NativeAssetSchema, Assignment as NativeAssignment,
	BitcoinNetwork as NativeBitcoinNetwork, ConsignmentExt, Error as RgbLibError,
	Fascia as NativeFascia, FileContent, RgbTxid as NativeRgbTxid, WitnessOrd,
};
#[cfg(all(feature = "rgb-wasm", not(feature = "rgb-native")))]
use rgb_lib_wasm::{
	bitcoin::psbt::Psbt as RgbLibPsbt,
	utils::recipient_id_from_script_buf as wasm_recipient_id_from_script_buf,
	wallet::{
		rust_only::{AssetColoringInfo as WasmAssetColoringInfo, ColoringInfo as WasmColoringInfo},
		Online as WasmOnline, Recipient as WasmRecipient, Wallet as WasmWallet,
		WalletData as WasmWalletData, WitnessData as WasmWitnessData,
	},
	AssetSchema as WasmAssetSchema, Assignment as WasmAssignment,
	BitcoinNetwork as WasmBitcoinNetwork, ConsignmentExt, Error as WasmRgbLibError, FileContent,
	WitnessOrd,
};
/// RGB transport endpoint shared by both wallet backends.
pub use rgbinvoice::RgbTransport;

use serde::{Deserialize, Serialize};

use crate::io;
#[cfg(all(feature = "rgb-native", not(feature = "rgb-wasm")))]
use crate::sync::Mutex;
use core::fmt;
use core::ops::Deref;
use std::cell::RefCell;
use std::collections::HashMap;
#[cfg(all(feature = "rgb-wasm", not(feature = "rgb-native")))]
use std::rc::Rc;
use std::str::FromStr;
use std::sync::Arc;

/// RGB schemas represented independently from a wallet backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd, Serialize, Deserialize)]
pub enum AssetSchema {
	/// Non-inflatable assets.
	Nia,
	/// Unique digital assets.
	Uda,
	/// Collectible fungible assets.
	Cfa,
	/// Inflatable fungible assets.
	Ifa,
}

impl fmt::Display for AssetSchema {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "{self:?}")
	}
}

#[cfg(all(feature = "rgb-native", not(feature = "rgb-wasm")))]
impl From<NativeAssetSchema> for AssetSchema {
	fn from(value: NativeAssetSchema) -> Self {
		match value {
			NativeAssetSchema::Nia => Self::Nia,
			NativeAssetSchema::Uda => Self::Uda,
			NativeAssetSchema::Cfa => Self::Cfa,
			NativeAssetSchema::Ifa => Self::Ifa,
		}
	}
}

#[cfg(all(feature = "rgb-native", not(feature = "rgb-wasm")))]
impl From<AssetSchema> for NativeAssetSchema {
	fn from(value: AssetSchema) -> Self {
		match value {
			AssetSchema::Nia => Self::Nia,
			AssetSchema::Uda => Self::Uda,
			AssetSchema::Cfa => Self::Cfa,
			AssetSchema::Ifa => Self::Ifa,
		}
	}
}

/// RGB assignment represented independently from a wallet backend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Assignment {
	/// Fungible value in RGB units.
	Fungible(u64),
	/// Non-fungible value.
	NonFungible,
	/// Inflation right.
	InflationRight(u64),
	/// Any assignment.
	Any,
}

#[cfg(all(feature = "rgb-native", not(feature = "rgb-wasm")))]
impl From<NativeAssignment> for Assignment {
	fn from(value: NativeAssignment) -> Self {
		match value {
			NativeAssignment::Fungible(amount) => Self::Fungible(amount),
			NativeAssignment::NonFungible => Self::NonFungible,
			NativeAssignment::InflationRight(amount) => Self::InflationRight(amount),
			NativeAssignment::Any => Self::Any,
		}
	}
}

#[cfg(all(feature = "rgb-wasm", not(feature = "rgb-native")))]
impl From<WasmAssetSchema> for AssetSchema {
	fn from(value: WasmAssetSchema) -> Self {
		match value {
			WasmAssetSchema::Nia => Self::Nia,
			WasmAssetSchema::Ifa => Self::Ifa,
		}
	}
}

#[cfg(all(feature = "rgb-wasm", not(feature = "rgb-native")))]
impl From<WasmAssignment> for Assignment {
	fn from(value: WasmAssignment) -> Self {
		match value {
			WasmAssignment::Fungible(amount) => Self::Fungible(amount),
			WasmAssignment::NonFungible => Self::NonFungible,
			WasmAssignment::InflationRight(amount) => Self::InflationRight(amount),
			WasmAssignment::Any => Self::Any,
		}
	}
}

/// RGB backend error represented independently from a wallet backend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RgbBackendError {
	/// The funding consignment is invalid.
	InvalidConsignment,
	/// The funding consignment could not be found.
	NoConsignment,
	/// The consignment uses an unknown RGB schema.
	UnknownSchema(String),
	/// The selected backend does not support the consignment schema.
	UnsupportedSchema(AssetSchema),
	/// A required network service failed.
	Network(String),
	/// Durable RGB wallet persistence failed.
	Persistence(String),
	/// An unexpected backend failure occurred.
	Unexpected(String),
}

#[cfg(all(feature = "rgb-native", not(feature = "rgb-wasm")))]
impl From<RgbLibError> for RgbBackendError {
	fn from(value: RgbLibError) -> Self {
		match value {
			RgbLibError::InvalidConsignment => Self::InvalidConsignment,
			RgbLibError::NoConsignment => Self::NoConsignment,
			RgbLibError::UnknownRgbSchema { schema_id } => Self::UnknownSchema(schema_id),
			RgbLibError::UnsupportedSchema { asset_schema } => {
				Self::UnsupportedSchema(asset_schema.into())
			},
			RgbLibError::InvalidColoringInfo { details } => {
				Self::Unexpected(format!("Invalid coloring info: {details}"))
			},
			RgbLibError::Indexer { details }
			| RgbLibError::InvalidIndexer { details }
			| RgbLibError::Network { details } => Self::Network(details),
			error => Self::Unexpected(error.to_string()),
		}
	}
}

#[cfg(all(feature = "rgb-wasm", not(feature = "rgb-native")))]
impl From<WasmRgbLibError> for RgbBackendError {
	fn from(value: WasmRgbLibError) -> Self {
		match value {
			WasmRgbLibError::InvalidConsignment => Self::InvalidConsignment,
			WasmRgbLibError::NoConsignment => Self::NoConsignment,
			WasmRgbLibError::UnknownRgbSchema { schema_id } => Self::UnknownSchema(schema_id),
			WasmRgbLibError::UnsupportedSchema { asset_schema } => {
				Self::UnsupportedSchema(asset_schema.into())
			},
			WasmRgbLibError::InvalidColoringInfo { details } => {
				Self::Unexpected(format!("Invalid coloring info: {details}"))
			},
			WasmRgbLibError::Indexer { details }
			| WasmRgbLibError::InvalidIndexer { details }
			| WasmRgbLibError::Network { details }
			| WasmRgbLibError::Proxy { details } => Self::Network(details),
			WasmRgbLibError::Persistence { details } => Self::Persistence(details),
			error => Self::Unexpected(error.to_string()),
		}
	}
}

/// RGB asset-specific transaction coloring data.
#[derive(Clone, Debug)]
pub struct AssetColoringInfo {
	/// Map of transaction output indexes to RGB amounts.
	pub output_map: HashMap<u32, u64>,
	/// Static blinding used for deterministic transaction construction.
	pub static_blinding: Option<u64>,
}

/// Backend-neutral RGB transaction coloring data.
#[derive(Clone, Debug)]
pub struct ColoringInfo {
	/// Asset-specific transaction coloring data.
	pub asset_info_map: HashMap<ContractId, AssetColoringInfo>,
	/// Static blinding used for deterministic transaction construction.
	pub static_blinding: Option<u64>,
	/// Nonce used to order off-chain transactions.
	pub nonce: Option<u64>,
}

impl ColoringInfo {
	#[cfg(all(feature = "rgb-native", not(feature = "rgb-wasm")))]
	fn into_native(self) -> NativeColoringInfo {
		NativeColoringInfo {
			asset_info_map: self
				.asset_info_map
				.into_iter()
				.map(|(contract_id, info)| {
					(
						contract_id,
						NativeAssetColoringInfo {
							output_map: info.output_map,
							static_blinding: info.static_blinding,
						},
					)
				})
				.collect(),
			static_blinding: self.static_blinding,
			nonce: self.nonce,
		}
	}

	#[cfg(all(feature = "rgb-wasm", not(feature = "rgb-native")))]
	fn into_wasm(self) -> WasmColoringInfo {
		WasmColoringInfo {
			asset_info_map: self
				.asset_info_map
				.into_iter()
				.map(|(contract_id, info)| {
					(
						contract_id,
						WasmAssetColoringInfo {
							output_map: info.output_map,
							static_blinding: info.static_blinding,
						},
					)
				})
				.collect(),
			static_blinding: self.static_blinding,
			nonce: self.nonce,
		}
	}
}

/// Result of accepting and validating an incoming RGB funding transfer.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct RgbFundingValidation {
	/// Serialized validated RGB consignment.
	pub consignment: Vec<u8>,
	/// Contract funded by the consignment.
	pub contract_id: ContractId,
	/// Asset schema funded by the consignment.
	pub schema: AssetSchema,
	/// RGB amount assigned to the funding output.
	pub received_amount: u64,
}

/// Parameters for creating an RGB channel funding transfer.
#[derive(Clone, Debug)]
pub struct RgbFundingTransferRequest {
	/// Contract allocated to the channel funding output.
	pub contract_id: ContractId,
	/// Asset schema of the contract.
	pub schema: AssetSchema,
	/// RGB amount allocated to the channel.
	pub amount: u64,
	/// Lightning funding output script.
	pub output_script: ScriptBuf,
	/// Bitcoin amount allocated to the Lightning funding output.
	pub channel_value_satoshis: u64,
	/// RGB proxy transport advertised to the channel peer.
	pub consignment_endpoint: RgbTransport,
	/// Bitcoin network used to encode the witness recipient.
	pub network: Network,
	/// Funding transaction fee rate in sat/vB.
	pub fee_rate: u64,
	/// Minimum confirmations required for selected wallet inputs.
	pub min_confirmations: u8,
}

/// Prepared RGB funding transaction that is not yet broadcast.
#[derive(Clone, Debug)]
pub struct PreparedRgbFundingTransfer {
	/// Signed PSBT retained until LDK reports the channel pending.
	pub signed_psbt: String,
	/// Signed funding transaction passed to `ChannelManager::funding_transaction_generated`.
	pub transaction: Transaction,
}

#[cfg(all(feature = "rgb-native", not(feature = "rgb-wasm")))]
fn native_bitcoin_network(network: Network) -> NativeBitcoinNetwork {
	match network {
		Network::Bitcoin => NativeBitcoinNetwork::Mainnet,
		Network::Testnet => NativeBitcoinNetwork::Testnet,
		Network::Testnet4 => NativeBitcoinNetwork::Testnet4,
		Network::Signet => NativeBitcoinNetwork::Signet,
		Network::Regtest => NativeBitcoinNetwork::Regtest,
	}
}

#[cfg(all(feature = "rgb-wasm", not(feature = "rgb-native")))]
fn wasm_bitcoin_network(network: Network) -> WasmBitcoinNetwork {
	match network {
		Network::Bitcoin => WasmBitcoinNetwork::Mainnet,
		Network::Testnet => WasmBitcoinNetwork::Testnet,
		Network::Testnet4 => WasmBitcoinNetwork::Testnet4,
		Network::Signet => WasmBitcoinNetwork::Signet,
		Network::Regtest => WasmBitcoinNetwork::Regtest,
	}
}

/// Long-lived native RGB wallet backend.
///
/// The same instance must be shared by the channel manager, channel signers, and all transaction
/// construction paths for the lifetime of the node.
#[cfg(all(feature = "rgb-native", not(feature = "rgb-wasm")))]
pub struct NativeRgbBackend {
	wallet: Mutex<Wallet>,
	online_options: OnlineOptions,
	transaction_processor: Mutex<()>,
}

/// The concrete RGB backend selected by the `rgb-native` build.
#[cfg(all(feature = "rgb-native", not(feature = "rgb-wasm")))]
pub type RgbBackend = NativeRgbBackend;

#[cfg(all(feature = "rgb-native", not(feature = "rgb-wasm")))]
impl NativeRgbBackend {
	/// Creates a persistent native RGB backend from an already restored production wallet.
	pub fn new(wallet: Wallet, online_options: OnlineOptions) -> Self {
		Self { wallet: Mutex::new(wallet), online_options, transaction_processor: Mutex::new(()) }
	}

	/// Prepares a deterministic colored transaction and durably consumes its fascia before
	/// returning.
	///
	/// Native transaction construction is synchronous, and child HTLC transactions may be colored
	/// immediately after their parent commitment transaction. Leaving the parent fascia pending
	/// until the application event loop runs makes the wallet report zero available assets while
	/// coloring that child transaction.
	pub fn prepare_transaction(
		&self, transaction: Transaction, coloring_info: ColoringInfo, kv_store: &dyn KVStoreSync,
	) -> Result<Transaction, RgbBackendError> {
		let _processor_guard = self.transaction_processor.lock().unwrap();
		let psbt = Psbt::from_unsigned_tx(transaction)
			.map_err(|error| RgbBackendError::Unexpected(error.to_string()))?;
		let mut psbt = RgbLibPsbt::from_str(&psbt.to_string())
			.map_err(|error| RgbBackendError::Unexpected(error.to_string()))?;
		let wallet = self.wallet.lock().unwrap();
		let (fascia, _) = wallet
			.color_psbt(&mut psbt, coloring_info.into_native())
			.map_err(RgbBackendError::from)?;
		let psbt = Psbt::from_str(&psbt.to_string())
			.map_err(|error| RgbBackendError::Unexpected(error.to_string()))?;
		let transaction = match psbt.extract_tx() {
			Ok(tx) => Ok(tx),
			Err(ExtractTxError::MissingInputValue { tx }) => Ok(tx),
			Err(error) => Err(RgbBackendError::Unexpected(error.to_string())),
		}?;
		let txid = transaction.compute_txid().to_string();
		if kv_store.read(RGB_PRIMARY_NS, RGB_CONSUMED_FASCIA_NS, &txid).is_err() {
			let serialized_fascia = serde_json::to_vec(&fascia)
				.map_err(|error| RgbBackendError::Unexpected(error.to_string()))?;
			kv_store
				.write(RGB_PRIMARY_NS, RGB_PENDING_FASCIA_NS, &txid, serialized_fascia)
				.map_err(|error| RgbBackendError::Unexpected(error.to_string()))?;
			wallet
				.consume_fascia(fascia, Some(WitnessOrd::Ignored))
				.map_err(RgbBackendError::from)?;
			kv_store
				.write(RGB_PRIMARY_NS, RGB_CONSUMED_FASCIA_NS, &txid, Vec::new())
				.map_err(|error| RgbBackendError::Unexpected(error.to_string()))?;
			kv_store
				.remove(RGB_PRIMARY_NS, RGB_PENDING_FASCIA_NS, &txid, false)
				.map_err(|error| RgbBackendError::Unexpected(error.to_string()))?;
		}
		Ok(transaction)
	}

	/// Returns whether a colored transaction's RGB fascia is durable.
	pub fn is_transaction_durable(&self, txid: &bitcoin::Txid, kv_store: &dyn KVStoreSync) -> bool {
		match kv_store.read(RGB_PRIMARY_NS, RGB_PENDING_FASCIA_NS, &txid.to_string()) {
			Ok(_) => false,
			Err(error) if error.kind() == io::ErrorKind::NotFound => true,
			Err(_) => false,
		}
	}

	/// Returns whether any prepared RGB transaction still requires durable fascia consumption.
	pub fn has_pending_transactions(
		&self, kv_store: &dyn KVStoreSync,
	) -> Result<bool, RgbBackendError> {
		kv_store
			.list(RGB_PRIMARY_NS, RGB_PENDING_FASCIA_NS)
			.map(|keys| !keys.is_empty())
			.map_err(|error| RgbBackendError::Unexpected(error.to_string()))
	}

	/// Durably consume all prepared RGB fascia before signing and message release are retried.
	pub async fn process_pending_transactions(
		self: &Arc<Self>, kv_store: Arc<dyn KVStoreSync + Send + Sync>,
	) -> Result<(), RgbBackendError> {
		let backend = Arc::clone(self);
		tokio::task::spawn_blocking(move || {
			let _processor_guard = backend.transaction_processor.lock().unwrap();
			let mut pending = kv_store
				.list(RGB_PRIMARY_NS, RGB_PENDING_FASCIA_NS)
				.map_err(|error| RgbBackendError::Unexpected(error.to_string()))?;
			pending.sort();
			while !pending.is_empty() {
				let mut deferred = Vec::new();
				let mut last_error = None;
				let mut progressed = false;
				for txid in pending {
					let bytes = kv_store
						.read(RGB_PRIMARY_NS, RGB_PENDING_FASCIA_NS, &txid)
						.map_err(|error| RgbBackendError::Unexpected(error.to_string()))?;
					let fascia = serde_json::from_slice(&bytes)
						.map_err(|error| RgbBackendError::Unexpected(error.to_string()))?;
					match backend
						.wallet
						.lock()
						.unwrap()
						.consume_fascia(fascia, Some(WitnessOrd::Ignored))
						.map_err(RgbBackendError::from)
					{
						Ok(()) => {
							progressed = true;
							kv_store
								.write(RGB_PRIMARY_NS, RGB_CONSUMED_FASCIA_NS, &txid, Vec::new())
								.map_err(|error| RgbBackendError::Unexpected(error.to_string()))?;
							kv_store
								.remove(RGB_PRIMARY_NS, RGB_PENDING_FASCIA_NS, &txid, false)
								.map_err(|error| RgbBackendError::Unexpected(error.to_string()))?;
						},
						Err(error) => {
							deferred.push(txid);
							last_error = Some(error);
						},
					}
				}
				if deferred.is_empty() {
					break;
				}
				if !progressed {
					return Err(last_error.expect("deferred fascia has an error"));
				}
				pending = deferred;
			}
			Ok(())
		})
		.await
		.map_err(|error| RgbBackendError::Unexpected(error.to_string()))?
	}

	/// Creates and signs an RGB funding transfer, posts its consignment, and leaves the transfer
	/// unbroadcast until [`Self::complete_funding_transfer`] is called.
	pub async fn prepare_funding_transfer(
		self: &Arc<Self>, request: RgbFundingTransferRequest,
	) -> Result<PreparedRgbFundingTransfer, RgbBackendError> {
		let backend = Arc::clone(self);
		tokio::task::spawn_blocking(move || {
			let mut wallet = backend.wallet.lock().unwrap();
			let online =
				wallet.go_online(backend.online_options.clone()).map_err(RgbBackendError::from)?;
			let assignment = match request.schema {
				AssetSchema::Nia | AssetSchema::Cfa | AssetSchema::Ifa => {
					NativeAssignment::Fungible(request.amount)
				},
				AssetSchema::Uda => NativeAssignment::NonFungible,
			};
			let funding_output_script = request.output_script.clone();
			let recipient_id = native_recipient_id_from_script_buf(
				request.output_script,
				native_bitcoin_network(request.network),
			);
			let recipient_map = HashMap::from([(
				request.contract_id.to_string(),
				vec![NativeRecipient {
					recipient_id: recipient_id.clone(),
					witness_data: Some(NativeWitnessData {
						amount_sat: request.channel_value_satoshis,
						blinding: Some(STATIC_BLINDING),
					}),
					assignment,
					transport_endpoints: vec![request.consignment_endpoint.to_string()],
				}],
			)]);
			let begin = wallet
				.send_begin(
					online,
					recipient_map,
					true,
					request.fee_rate,
					request.min_confirmations,
					None,
					false,
					Some(0),
				)
				.map_err(RgbBackendError::from)?;
			let fascia_bytes = std::fs::read(&begin.details.fascia_path)
				.map_err(|error| RgbBackendError::Unexpected(error.to_string()))?;
			let fascia: NativeFascia = serde_json::from_slice(&fascia_bytes)
				.map_err(|error| RgbBackendError::Unexpected(error.to_string()))?;
			wallet.consume_fascia(fascia, None).map_err(RgbBackendError::from)?;
			wallet.create_consignments(begin.psbt.clone()).map_err(RgbBackendError::from)?;
			let signed_psbt = wallet.sign_psbt(begin.psbt, None).map_err(RgbBackendError::from)?;
			let psbt = Psbt::from_str(&signed_psbt)
				.map_err(|error| RgbBackendError::Unexpected(error.to_string()))?;
			let transaction = psbt
				.clone()
				.extract_tx()
				.map_err(|error| RgbBackendError::Unexpected(error.to_string()))?;
			let txid = transaction.compute_txid().to_string();
			// Post the funding consignment under the txid (matching the rgb-lib `accept_transfer`
			// flow and the acceptor's txid lookup), not the P2V `recipient_id`. The witness
			// `recipient_id` is only used to build the transfer above.
			let funding_vout = transaction
				.output
				.iter()
				.position(|output| output.script_pubkey == funding_output_script)
				.ok_or_else(|| {
					RgbBackendError::Unexpected("funding output missing from colored tx".to_owned())
				})? as u32;
			wallet
				.upsert_witness(
					NativeRgbTxid::from_str(&txid)
						.map_err(|error| RgbBackendError::Unexpected(error.to_string()))?,
					WitnessOrd::Tentative,
				)
				.map_err(RgbBackendError::from)?;
			let proxy_url = NativeTransportEndpoint::new(request.consignment_endpoint.to_string())
				.map_err(RgbBackendError::from)?
				.endpoint;
			let consignment_path =
				wallet.get_send_consignment_path(&request.contract_id.to_string(), &txid);
			wallet
				.post_consignment(
					&proxy_url,
					txid.clone(),
					consignment_path,
					txid,
					Some(funding_vout),
				)
				.map_err(RgbBackendError::from)?;
			Ok(PreparedRgbFundingTransfer { signed_psbt, transaction })
		})
		.await
		.map_err(|error| RgbBackendError::Unexpected(error.to_string()))?
	}

	/// Completes and broadcasts an RGB funding transfer after LDK reports `ChannelPending`.
	///
	/// NOTE: unlike the wasm backend's `complete_funding_transfer`, this native path is not
	/// idempotent on replay. If the node restarts after `send_end` succeeds but before the caller
	/// records its completion marker, a second call re-invokes `send_end` on an already-sent batch
	/// transfer and fails. The wasm backend recovers via `is_batch_transfer_sent`; native
	/// `rgb-lib` does not expose that query yet.
	///
	/// TODO(rgb-native-idempotency): when `send_end` reports the transfer is already sent, derive
	/// the funding txid from `signed_psbt` and confirm via `wallet.list_transfers(None)` that a
	/// transfer with that txid is in a non-failed status, returning `Ok(txid)`. This first needs
	/// the exact native `send_end` replay error variant identified.
	pub async fn complete_funding_transfer(
		self: &Arc<Self>, signed_psbt: String,
	) -> Result<String, RgbBackendError> {
		let backend = Arc::clone(self);
		tokio::task::spawn_blocking(move || {
			let mut wallet = backend.wallet.lock().unwrap();
			let online =
				wallet.go_online(backend.online_options.clone()).map_err(RgbBackendError::from)?;
			wallet
				.send_end(online, signed_psbt)
				.map(|result| result.txid)
				.map_err(RgbBackendError::from)
		})
		.await
		.map_err(|error| RgbBackendError::Unexpected(error.to_string()))?
	}

	/// Accepts and validates an incoming RGB funding transfer without blocking the async caller.
	///
	/// `_funding_output_script` is currently unused: `rgb-lib`'s `accept_transfer` resolves the
	/// funding consignment by txid. It is retained for deriving a P2V `recipient_id` from the
	/// funding output if a hint-based lookup is ever needed.
	pub async fn accept_funding_transfer(
		self: &Arc<Self>, funding_txid: String, funding_vout: u32,
		consignment_endpoint: RgbTransport, _funding_output_script: Option<ScriptBuf>,
	) -> Result<RgbFundingValidation, RgbBackendError> {
		let backend = Arc::clone(self);
		tokio::task::spawn_blocking(move || {
			let mut wallet = backend.wallet.lock().unwrap();
			wallet.go_online(backend.online_options.clone()).map_err(RgbBackendError::from)?;
			let (consignment, assignments) = wallet
				.accept_transfer(funding_txid, funding_vout, consignment_endpoint, STATIC_BLINDING)
				.map_err(RgbBackendError::from)?;
			if assignments.len() != 1 {
				return Err(RgbBackendError::Unexpected(format!(
					"Unexpected number of RGB assignments: {}",
					assignments.len()
				)));
			}
			let received_amount = match assignments.into_iter().next().unwrap() {
				NativeAssignment::Fungible(amount) => amount,
				NativeAssignment::NonFungible => 1,
				NativeAssignment::InflationRight(_) | NativeAssignment::Any => {
					return Err(RgbBackendError::Unexpected(
						"Unsupported RGB funding assignment".to_owned(),
					))
				},
			};
			let contract_id = consignment.contract_id();
			let schema = NativeAssetSchema::from_schema_id(consignment.schema_id())
				.map(Into::into)
				.map_err(RgbBackendError::from)?;
			let mut consignment_bytes = Vec::new();
			consignment
				.save(&mut consignment_bytes)
				.map_err(|error| RgbBackendError::Unexpected(error.to_string()))?;
			Ok(RgbFundingValidation {
				consignment: consignment_bytes,
				contract_id,
				schema,
				received_amount,
			})
		})
		.await
		.map_err(|error| RgbBackendError::Unexpected(error.to_string()))?
	}
}

/// Long-lived browser RGB wallet backend.
///
/// Construct this backend only after restoring the wallet from IndexedDB. The backend and every
/// LDK object containing it are intentionally single-threaded because `rgb-lib-wasm::Wallet`
/// contains `Rc` and `RefCell` state.
#[cfg(all(feature = "rgb-wasm", not(feature = "rgb-native")))]
pub struct WasmRgbBackend {
	wallet: Rc<RefCell<WasmWallet>>,
	online: WasmOnline,
	transaction_processor: RefCell<()>,
	prepared_in_memory: RefCell<HashSet<String>>,
}

/// The concrete RGB backend selected by the `rgb-wasm` build.
#[cfg(all(feature = "rgb-wasm", not(feature = "rgb-native")))]
pub type RgbBackend = WasmRgbBackend;

#[cfg(all(feature = "rgb-wasm", not(feature = "rgb-native")))]
impl WasmRgbBackend {
	/// Creates a browser backend that shares ownership of an already-online wallet.
	pub fn new(wallet: Rc<RefCell<WasmWallet>>, online: WasmOnline) -> Self {
		Self {
			wallet,
			online,
			transaction_processor: RefCell::new(()),
			prepared_in_memory: RefCell::new(HashSet::new()),
		}
	}

	/// Restores a production wallet from IndexedDB, connects it to the indexer, and creates the
	/// browser backend.
	pub async fn restore(
		wallet_data: WasmWalletData, skip_consistency_check: bool, indexer_url: String,
	) -> Result<Self, RgbBackendError> {
		let mut wallet = WasmWallet::restore(wallet_data).await.map_err(RgbBackendError::from)?;
		let online = wallet
			.go_online(skip_consistency_check, indexer_url)
			.await
			.map_err(RgbBackendError::from)?;
		Ok(Self::new(Rc::new(RefCell::new(wallet)), online))
	}

	/// Prepares a deterministic colored transaction, consumes its fascia in memory so dependent
	/// transactions can be colored immediately, and persists it for asynchronous IndexedDB flush.
	pub fn prepare_transaction(
		&self, transaction: Transaction, coloring_info: ColoringInfo, kv_store: &dyn KVStoreSync,
	) -> Result<Transaction, RgbBackendError> {
		let psbt = Psbt::from_unsigned_tx(transaction)
			.map_err(|error| RgbBackendError::Unexpected(error.to_string()))?;
		let mut psbt = RgbLibPsbt::from_str(&psbt.to_string())
			.map_err(|error| RgbBackendError::Unexpected(error.to_string()))?;
		let wallet = self.wallet.try_borrow().map_err(|_| {
			RgbBackendError::Unexpected("RGB WASM wallet is already in use".to_owned())
		})?;
		let (fascia, _) = wallet
			.color_psbt(&mut psbt, coloring_info.into_wasm())
			.map_err(RgbBackendError::from)?;
		let psbt = Psbt::from_str(&psbt.to_string())
			.map_err(|error| RgbBackendError::Unexpected(error.to_string()))?;
		let transaction = match psbt.extract_tx() {
			Ok(tx) => Ok(tx),
			Err(ExtractTxError::MissingInputValue { tx }) => Ok(tx),
			Err(error) => Err(RgbBackendError::Unexpected(error.to_string())),
		}?;
		let txid = transaction.compute_txid().to_string();
		if kv_store.read(RGB_PRIMARY_NS, RGB_CONSUMED_FASCIA_NS, &txid).is_err() {
			let serialized_fascia = serde_json::to_vec(&fascia)
				.map_err(|error| RgbBackendError::Unexpected(error.to_string()))?;
			kv_store
				.write(RGB_PRIMARY_NS, RGB_PENDING_FASCIA_NS, &txid, serialized_fascia)
				.map_err(|error| RgbBackendError::Unexpected(error.to_string()))?;
			wallet
				.consume_fascia_in_memory(fascia, Some(WitnessOrd::Ignored))
				.map_err(RgbBackendError::from)?;
			self.prepared_in_memory.borrow_mut().insert(txid);
		}
		Ok(transaction)
	}

	/// Returns whether a colored transaction's RGB fascia is durable.
	pub fn is_transaction_durable(&self, txid: &bitcoin::Txid, kv_store: &dyn KVStoreSync) -> bool {
		match kv_store.read(RGB_PRIMARY_NS, RGB_PENDING_FASCIA_NS, &txid.to_string()) {
			Ok(_) => false,
			Err(error) if error.kind() == io::ErrorKind::NotFound => true,
			Err(_) => false,
		}
	}

	/// Returns whether any prepared RGB transaction still requires durable fascia consumption.
	pub fn has_pending_transactions(
		&self, kv_store: &dyn KVStoreSync,
	) -> Result<bool, RgbBackendError> {
		kv_store
			.list(RGB_PRIMARY_NS, RGB_PENDING_FASCIA_NS)
			.map(|keys| !keys.is_empty())
			.map_err(|error| RgbBackendError::Unexpected(error.to_string()))
	}

	/// Durably consumes all prepared RGB fascia in IndexedDB before signing and message release
	/// are retried.
	pub async fn process_pending_transactions(
		self: &Arc<Self>, kv_store: Arc<dyn KVStoreSync + Send + Sync>,
	) -> Result<(), RgbBackendError> {
		let _processor_guard = self.transaction_processor.try_borrow_mut().map_err(|_| {
			RgbBackendError::Unexpected(
				"RGB transaction persistence is already being processed".to_owned(),
			)
		})?;
		let mut pending = kv_store
			.list(RGB_PRIMARY_NS, RGB_PENDING_FASCIA_NS)
			.map_err(|error| RgbBackendError::Unexpected(error.to_string()))?;
		pending.sort();
		while !pending.is_empty() {
			let mut deferred = Vec::new();
			let mut last_error = None;
			let mut progressed = false;
			for txid in pending {
				let already_consumed = self.prepared_in_memory.borrow().contains(&txid);
				let result = {
					let wallet = self.wallet.try_borrow().map_err(|_| {
						RgbBackendError::Unexpected("RGB WASM wallet is already in use".to_owned())
					})?;
					if already_consumed {
						wallet.flush().await
					} else {
						let bytes = kv_store
							.read(RGB_PRIMARY_NS, RGB_PENDING_FASCIA_NS, &txid)
							.map_err(|error| RgbBackendError::Unexpected(error.to_string()))?;
						let fascia = serde_json::from_slice(&bytes)
							.map_err(|error| RgbBackendError::Unexpected(error.to_string()))?;
						wallet.consume_fascia(fascia, Some(WitnessOrd::Ignored)).await
					}
				};
				match result.map_err(RgbBackendError::from) {
					Ok(()) => {
						progressed = true;
						self.prepared_in_memory.borrow_mut().remove(&txid);
						kv_store
							.write(RGB_PRIMARY_NS, RGB_CONSUMED_FASCIA_NS, &txid, Vec::new())
							.map_err(|error| RgbBackendError::Unexpected(error.to_string()))?;
						kv_store
							.remove(RGB_PRIMARY_NS, RGB_PENDING_FASCIA_NS, &txid, false)
							.map_err(|error| RgbBackendError::Unexpected(error.to_string()))?;
					},
					Err(error) => {
						deferred.push(txid);
						last_error = Some(error);
					},
				}
			}
			if deferred.is_empty() {
				break;
			}
			if !progressed {
				return Err(last_error.expect("deferred fascia has an error"));
			}
			pending = deferred;
		}
		Ok(())
	}

	/// Creates and signs an RGB funding transfer, posts its consignment, and leaves the transfer
	/// unbroadcast until [`Self::complete_funding_transfer`] is called.
	pub async fn prepare_funding_transfer(
		self: &Arc<Self>, request: RgbFundingTransferRequest,
	) -> Result<PreparedRgbFundingTransfer, RgbBackendError> {
		let assignment = match request.schema {
			AssetSchema::Nia | AssetSchema::Ifa => WasmAssignment::Fungible(request.amount),
			schema => return Err(RgbBackendError::UnsupportedSchema(schema)),
		};
		let recipient_id = wasm_recipient_id_from_script_buf(
			request.output_script,
			wasm_bitcoin_network(request.network),
		);
		let recipient_map = HashMap::from([(
			request.contract_id.to_string(),
			vec![WasmRecipient {
				recipient_id,
				witness_data: Some(WasmWitnessData {
					amount_sat: request.channel_value_satoshis,
					blinding: Some(STATIC_BLINDING),
				}),
				assignment,
				transport_endpoints: vec![request.consignment_endpoint.to_string()],
			}],
		)]);
		let mut wallet = self.wallet.try_borrow_mut().map_err(|_| {
			RgbBackendError::Unexpected("RGB WASM wallet is already in use".to_owned())
		})?;
		let unsigned_psbt = wallet
			.send_begin(
				self.online.clone(),
				recipient_map,
				true,
				request.fee_rate,
				request.min_confirmations,
				// Pin the funding tx to a final (height 0) absolute locktime; LDK rejects a
				// funding transaction whose absolute timelock is non-final.
				Some(0),
			)
			.await
			.map_err(RgbBackendError::from)?;
		let signed_psbt = wallet.sign_psbt(unsigned_psbt, None).map_err(RgbBackendError::from)?;
		let psbt = Psbt::from_str(&signed_psbt)
			.map_err(|error| RgbBackendError::Unexpected(error.to_string()))?;
		let transaction = psbt
			.clone()
			.extract_tx()
			.map_err(|error| RgbBackendError::Unexpected(error.to_string()))?;
		let funding_txid = transaction.compute_txid().to_string();
		wallet
			.post_pending_consignments(funding_txid.clone())
			.await
			.map_err(RgbBackendError::from)?;
		// Also post the consignment keyed by the txid (mirroring the native backend above), so a
		// native acceptor — whose `accept_transfer` resolves the funding consignment by raw txid —
		// can fetch it. `post_pending_consignments` only posts under the P2V/witness recipient_id.
		wallet.post_consignment_by_txid(funding_txid).await.map_err(RgbBackendError::from)?;
		wallet.flush().await.map_err(RgbBackendError::from)?;
		Ok(PreparedRgbFundingTransfer { signed_psbt, transaction })
	}

	/// Completes and broadcasts an RGB funding transfer after LDK reports `ChannelPending`.
	///
	/// Idempotent: if `send_end` returns `UnknownTransfer` and the transfer is already recorded
	/// in the wallet database (non-failed status), we treat the operation as already completed.
	/// This handles the crash-inject boundary where the browser reloads after `flush()` but
	/// before the KV completion marker is written, causing replay to call `send_end` again.
	pub async fn complete_funding_transfer(
		self: &Arc<Self>, signed_psbt: String,
	) -> Result<String, RgbBackendError> {
		let mut wallet = self.wallet.try_borrow_mut().map_err(|_| {
			RgbBackendError::Unexpected("RGB WASM wallet is already in use".to_owned())
		})?;
		let result = match wallet.send_end(self.online.clone(), signed_psbt, false).await {
			Ok(r) => r,
			Err(WasmRgbLibError::UnknownTransfer { ref txid }) => {
				if wallet.is_batch_transfer_sent(txid).map_err(RgbBackendError::from)? {
					return Ok(txid.clone());
				}
				return Err(RgbBackendError::from(WasmRgbLibError::UnknownTransfer {
					txid: txid.clone(),
				}));
			},
			Err(e) => return Err(RgbBackendError::from(e)),
		};
		wallet.flush().await.map_err(RgbBackendError::from)?;
		Ok(result.txid)
	}

	/// Accepts, validates, and durably persists an incoming RGB funding transfer.
	///
	/// `_funding_output_script` is currently unused: `accept_transfer` resolves the funding
	/// consignment by txid. It is retained for deriving a P2V `recipient_id` from the funding
	/// output if a hint-based lookup is ever needed.
	pub async fn accept_funding_transfer(
		self: &Arc<Self>, funding_txid: String, funding_vout: u32,
		consignment_endpoint: RgbTransport, _funding_output_script: Option<ScriptBuf>,
	) -> Result<RgbFundingValidation, RgbBackendError> {
		let mut wallet = self.wallet.try_borrow_mut().map_err(|_| {
			RgbBackendError::Unexpected("RGB WASM wallet is already in use".to_owned())
		})?;
		let (consignment, assignments) = wallet
			.accept_transfer(
				self.online.clone(),
				funding_txid,
				funding_vout,
				consignment_endpoint,
				STATIC_BLINDING,
			)
			.await
			.map_err(RgbBackendError::from)?;
		if assignments.len() != 1 {
			return Err(RgbBackendError::Unexpected(format!(
				"Unexpected number of RGB assignments: {}",
				assignments.len()
			)));
		}
		let received_amount = match assignments.into_iter().next().unwrap() {
			WasmAssignment::Fungible(amount) => amount,
			WasmAssignment::NonFungible => 1,
			WasmAssignment::InflationRight(_) | WasmAssignment::Any => {
				return Err(RgbBackendError::Unexpected(
					"Unsupported RGB funding assignment".to_owned(),
				))
			},
		};
		let contract_id = consignment.contract_id();
		let schema = WasmAssetSchema::from_schema_id(consignment.schema_id())
			.map(Into::into)
			.map_err(RgbBackendError::from)?;
		let mut consignment_bytes = Vec::new();
		consignment
			.save(&mut consignment_bytes)
			.map_err(|error| RgbBackendError::Unexpected(error.to_string()))?;
		Ok(RgbFundingValidation {
			consignment: consignment_bytes,
			contract_id,
			schema,
			received_amount,
		})
	}
}

/// Static blinding constant (will be removed in the future)
pub const STATIC_BLINDING: u64 = 777;
// kv_store namespace constants for RGB data persistence
/// Primary namespace for all RGB data
pub const RGB_PRIMARY_NS: &str = "rgb";
/// Secondary namespace for channel info
pub const RGB_CHANNEL_INFO_NS: &str = "channel_info";
/// Secondary namespace for pending channel info
pub const RGB_CHANNEL_INFO_PENDING_NS: &str = "channel_info_pending";
/// Secondary namespace for inbound payment info
pub const RGB_PAYMENT_INFO_INBOUND_NS: &str = "payment_info_inbound";
/// Secondary namespace for outbound payment info
pub const RGB_PAYMENT_INFO_OUTBOUND_NS: &str = "payment_info_outbound";
/// Secondary namespace for transfer info
pub const RGB_TRANSFER_INFO_NS: &str = "transfer_info";
/// Secondary namespace for consignment data
pub const RGB_CONSIGNMENT_NS: &str = "consignment";
/// Secondary namespace for prepared RGB fascia awaiting durable consumption.
pub const RGB_PENDING_FASCIA_NS: &str = "pending_fascia";
/// Secondary namespace recording RGB fascia which have been durably consumed.
pub const RGB_CONSUMED_FASCIA_NS: &str = "consumed_fascia";

/// RGB channel info
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RgbInfo {
	/// Channel contract ID
	#[serde(with = "contract_id_serde")]
	pub contract_id: ContractId,
	/// Channel schema
	pub schema: AssetSchema,
	/// Channel RGB local amount
	pub local_rgb_amount: u64,
	/// Channel RGB remote amount
	pub remote_rgb_amount: u64,
	/// Batch transfer index from rgb-lib (set after rgb_send_begin).
	/// NOTE: no serde skip/default attributes here — RgbInfo is persisted via
	/// bincode (a positional, non-self-describing format), so the field must be
	/// serialized unconditionally to stay in sync on read.
	pub batch_transfer_idx: Option<i32>,
}

/// RGB payment info
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RgbPaymentInfo {
	/// RGB contract ID
	#[serde(with = "contract_id_serde")]
	pub contract_id: ContractId,
	/// RGB payment amount
	pub amount: u64,
	/// RGB local amount
	pub local_rgb_amount: u64,
	/// RGB remote amount
	pub remote_rgb_amount: u64,
	/// Whether the RGB amount in route should be overridden
	pub swap_payment: bool,
	/// Whether the payment is inbound
	pub inbound: bool,
}

/// RGB transfer info
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TransferInfo {
	/// Transfer contract ID
	#[serde(with = "contract_id_serde")]
	pub contract_id: ContractId,
	/// Transfer RGB amount
	pub rgb_amount: u64,
}

mod contract_id_serde {
	use super::*;
	use serde::{Deserializer, Serializer};
	use std::str::FromStr;

	pub fn serialize<S>(id: &ContractId, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		serializer.serialize_str(&id.to_string())
	}

	pub fn deserialize<'de, D>(deserializer: D) -> Result<ContractId, D::Error>
	where
		D: Deserializer<'de>,
	{
		let s = String::deserialize(deserializer)?;
		ContractId::from_str(&s).map_err(serde::de::Error::custom)
	}
}

fn _counterparty_output_index(
	outputs: &[TxOut], channel_type_features: &ChannelTypeFeatures, payment_key: &PublicKey,
) -> Option<usize> {
	let counterparty_payment_script =
		get_countersigner_payment_script(channel_type_features, payment_key);
	outputs
		.iter()
		.enumerate()
		.find(|(_, out)| out.script_pubkey == counterparty_payment_script)
		.map(|(idx, _)| idx)
}

/// Return the position of the OP_RETURN output, if present
pub fn op_return_position(tx: &Transaction) -> Option<usize> {
	tx.output.iter().position(|o| o.script_pubkey.is_op_return())
}

/// Whether the transaction is colored (i.e. it has an OP_RETURN output)
pub fn is_tx_colored(tx: &Transaction) -> bool {
	op_return_position(tx).is_some()
}

/// Maps an RGB coloring KVStore or (de)serialization failure to a channel-closing error, so a
/// storage fault closes the affected channel instead of panicking the whole node.
fn rgb_color_err<E: fmt::Display>(error: E) -> ChannelError {
	ChannelError::close(format!("RGB coloring persistence failed: {error}"))
}

/// Color commitment transaction
pub(crate) fn color_commitment<SP: Deref>(
	channel_context: &ChannelContext<SP>, funding_scope: &FundingScope,
	commitment_transaction: &mut CommitmentTransaction, counterparty: bool,
) -> Result<(), ChannelError>
where
	<SP as std::ops::Deref>::Target: SignerProvider,
{
	let channel_id = &channel_context.channel_id;
	let kv_store = channel_context.rgb_kv_store.as_ref();

	let commitment_tx = commitment_transaction.clone().built.transaction;

	let rgb_info = get_rgb_channel_info_pending(channel_id, kv_store).map_err(rgb_color_err)?;
	let contract_id = rgb_info.contract_id;

	let chan_id = channel_id.0.as_hex();
	let mut rgb_offered_htlc = 0;
	let mut rgb_received_htlc = 0;
	let mut last_rgb_payment_info = None;
	let mut output_map = HashMap::new();

	for htlc in commitment_transaction.nondust_htlcs() {
		if htlc.rgb_payment.is_none_or(|(_, a)| a == 0) {
			continue;
		}
		let (_, htlc_amount_rgb) = htlc.rgb_payment.expect("this HTLC has RGB assets");

		let htlc_vout = htlc.transaction_output_index.unwrap();

		let inbound = htlc.offered == counterparty;

		let htlc_payment_hash = htlc.payment_hash.0.as_hex().to_string();
		let htlc_proxy_id = format!("{chan_id}{htlc_payment_hash}");
		let htlc_proxy_id_pending = format!("{htlc_proxy_id}_pending");
		let pending_key = format!("{htlc_payment_hash}_pending");
		let namespace =
			if inbound { RGB_PAYMENT_INFO_INBOUND_NS } else { RGB_PAYMENT_INFO_OUTBOUND_NS };

		if let Ok(data) = kv_store.read(RGB_PRIMARY_NS, namespace, &pending_key) {
			let mut rgb_payment_info: RgbPaymentInfo =
				bincode::deserialize(&data).map_err(rgb_color_err)?;
			rgb_payment_info.local_rgb_amount = rgb_info.local_rgb_amount;
			rgb_payment_info.remote_rgb_amount = rgb_info.remote_rgb_amount;
			let data = bincode::serialize(&rgb_payment_info).map_err(rgb_color_err)?;
			kv_store
				.write(RGB_PRIMARY_NS, namespace, &htlc_proxy_id, data.clone())
				.map_err(rgb_color_err)?;
			kv_store
				.write(RGB_PRIMARY_NS, namespace, &htlc_proxy_id_pending, data)
				.map_err(rgb_color_err)?;
			kv_store
				.remove(RGB_PRIMARY_NS, namespace, &pending_key, false)
				.map_err(rgb_color_err)?;
		}

		// Only accept a stored candidate if it actually describes THIS HTLC on THIS channel.
		// Matches the pre-KVStore guard in `color_commitment`: a record whose contract_id,
		// amount, or direction disagrees with what's being coloured right now cannot have been
		// written for this HTLC, so treating it as authoritative would poison the commitment
		// (e.g. two legs of an atomic RGB swap sharing a payment_hash under different assets).
		let is_compatible = |info: &RgbPaymentInfo| {
			info.contract_id == contract_id
				&& info.amount == htlc_amount_rgb
				&& info.inbound == inbound
		};

		let cached_payment_info = match kv_store.read(RGB_PRIMARY_NS, namespace, &htlc_proxy_id) {
			Ok(data) => Some(bincode::deserialize::<RgbPaymentInfo>(&data).map_err(rgb_color_err)?),
			Err(_) => None,
		};
		let rgb_payment_info =
			if let Some(info) = cached_payment_info.filter(|info| is_compatible(info)) {
				// Cache hit on the per-channel record. Preserve stored balances: they were the
				// channel's snapshot at the time this HTLC was first coloured, and the later
				// `remote_rgb_amount - rgb_received_htlc` (and local/offered) subtraction assumes
				// that snapshot — using current `rgb_info` values can underflow if the channel
				// state has since moved. Matches pre-KVStore `channel_rgb_payment_info_path`
				// behaviour, where `should_persist_channel_info` stayed false on this branch.
				info
			} else if let Some(mut info) = kv_store
				.read_rgb_payment_info(&htlc.payment_hash, inbound)
				.ok()
				.filter(|info| is_compatible(info))
			{
				// Fall back to the canonical payment-hash-keyed record written by the sender/payee
				// via `write_rgb_payment_info_file`. Lets a second channel on the same node recover
				// the authoritative payment info once the first channel has consumed the
				// `<payment_hash>_pending` marker. Refresh balances, then persist a per-channel
				// copy so subsequent commitment updates hit the cached branch above.
				info.local_rgb_amount = rgb_info.local_rgb_amount;
				info.remote_rgb_amount = rgb_info.remote_rgb_amount;
				let data = bincode::serialize(&info).map_err(rgb_color_err)?;
				kv_store
					.write(RGB_PRIMARY_NS, namespace, &htlc_proxy_id, data.clone())
					.map_err(rgb_color_err)?;
				kv_store
					.write(RGB_PRIMARY_NS, namespace, &htlc_proxy_id_pending, data)
					.map_err(rgb_color_err)?;
				info
			} else {
				// No compatible record available (e.g. a forwarder that never saw a
				// sender/payee-side write). Synthesize from the channel's own RGB info plus the
				// HTLC's amount.
				let rgb_payment_info = RgbPaymentInfo {
					contract_id,
					amount: htlc_amount_rgb,
					local_rgb_amount: rgb_info.local_rgb_amount,
					remote_rgb_amount: rgb_info.remote_rgb_amount,
					swap_payment: true,
					inbound,
				};
				let data = bincode::serialize(&rgb_payment_info).map_err(rgb_color_err)?;
				kv_store
					.write(RGB_PRIMARY_NS, namespace, &htlc_proxy_id, data.clone())
					.map_err(rgb_color_err)?;
				kv_store
					.write(RGB_PRIMARY_NS, namespace, &htlc_proxy_id_pending, data)
					.map_err(rgb_color_err)?;
				rgb_payment_info
			};

		if kv_store.read(RGB_PRIMARY_NS, namespace, &htlc_proxy_id_pending).is_err() {
			let data = bincode::serialize(&rgb_payment_info).map_err(rgb_color_err)?;
			kv_store
				.write(RGB_PRIMARY_NS, namespace, &htlc_proxy_id_pending, data)
				.map_err(rgb_color_err)?;
		}

		if inbound {
			rgb_received_htlc += rgb_payment_info.amount
		} else {
			rgb_offered_htlc += rgb_payment_info.amount
		};

		output_map.insert(htlc_vout, rgb_payment_info.amount);

		last_rgb_payment_info = Some(rgb_payment_info);
	}

	if channel_context.is_trusted_no_broadcast() {
		return Ok(());
	}

	let (local_amt, remote_amt) = if let Some(last_rgb_payment_info) = last_rgb_payment_info {
		(
			last_rgb_payment_info.local_rgb_amount - rgb_offered_htlc,
			last_rgb_payment_info.remote_rgb_amount - rgb_received_htlc,
		)
	} else {
		(rgb_info.local_rgb_amount, rgb_info.remote_rgb_amount)
	};
	let (vout_p2wpkh_amt, vout_p2wsh_amt) =
		if counterparty { (local_amt, remote_amt) } else { (remote_amt, local_amt) };

	let payment_point = if counterparty {
		funding_scope.get_holder_pubkeys().payment_point
	} else {
		funding_scope.get_counterparty_pubkeys().payment_point
	};

	if let Some(vout_p2wpkh) = _counterparty_output_index(
		&commitment_tx.output,
		funding_scope.get_channel_type(),
		&payment_point,
	) {
		output_map.insert(vout_p2wpkh as u32, vout_p2wpkh_amt);
	}

	if let Some(vout_p2wsh) = commitment_transaction.trust().revokeable_output_index() {
		output_map.insert(vout_p2wsh as u32, vout_p2wsh_amt);
	}

	let asset_coloring_info =
		AssetColoringInfo { output_map, static_blinding: Some(STATIC_BLINDING) };
	let coloring_info = ColoringInfo {
		asset_info_map: HashMap::from_iter([(contract_id, asset_coloring_info)]),
		static_blinding: Some(STATIC_BLINDING),
		nonce: None,
	};
	let modified_tx = channel_context
		.rgb_backend
		.prepare_transaction(commitment_tx.clone(), coloring_info, kv_store)
		.map_err(|error| {
			ChannelError::close(format!("Failed to color RGB commitment: {error:?}"))
		})?;

	let txid = modified_tx.compute_txid();
	commitment_transaction.built = BuiltCommitmentTransaction { transaction: modified_tx, txid };

	let rgb_amount = if counterparty {
		vout_p2wpkh_amt + rgb_offered_htlc
	} else {
		vout_p2wsh_amt + rgb_received_htlc
	};
	let transfer_info = TransferInfo { contract_id, rgb_amount };
	kv_store.write_rgb_transfer_info(&txid.to_string(), &transfer_info).map_err(rgb_color_err)?;

	Ok(())
}

/// Color HTLC transaction
pub(crate) fn color_htlc(
	htlc_tx: &mut Transaction, htlc: &HTLCOutputInCommitment, rgb_backend: &RgbBackend,
	kv_store: &dyn KVStoreSync,
) -> Result<(), ChannelError> {
	if htlc.rgb_payment.is_none_or(|(_, a)| a == 0) {
		return Ok(());
	}
	let (_, htlc_amount_rgb) = htlc.rgb_payment.expect("this HTLC has RGB assets");

	let consignment_htlc_outpoint = htlc_tx
		.input
		.first()
		.ok_or_else(|| ChannelError::close("HTLC transaction has no inputs".to_owned()))?
		.previous_output;
	let commitment_txid = consignment_htlc_outpoint.txid.to_string();

	let transfer_info = kv_store
		.read_rgb_transfer_info(&commitment_txid)
		.map_err(|e| ChannelError::close(format!("Failed to read RGB transfer info: {e}")))?;
	let contract_id = transfer_info.contract_id;

	let asset_coloring_info = AssetColoringInfo {
		output_map: HashMap::from([(0, htlc_amount_rgb)]),
		static_blinding: Some(STATIC_BLINDING),
	};
	let coloring_info = ColoringInfo {
		asset_info_map: HashMap::from_iter([(contract_id, asset_coloring_info)]),
		static_blinding: Some(STATIC_BLINDING),
		nonce: Some(1),
	};
	let modified_tx = rgb_backend
		.prepare_transaction(htlc_tx.clone(), coloring_info, kv_store)
		.map_err(|error| ChannelError::close(format!("Failed to color RGB HTLC: {error:?}")))?;
	let txid = &modified_tx.compute_txid();
	*htlc_tx = modified_tx;

	let transfer_info = TransferInfo { contract_id, rgb_amount: htlc_amount_rgb };
	kv_store
		.write_rgb_transfer_info(&txid.to_string(), &transfer_info)
		.map_err(|e| ChannelError::close(format!("Failed to write RGB transfer info: {e}")))?;

	Ok(())
}

/// Color closing transaction
pub(crate) fn color_closing(
	channel_id: &ChannelId, closing_transaction: &mut ClosingTransaction, rgb_backend: &RgbBackend,
	kv_store: &dyn KVStoreSync,
) -> Result<(), ChannelError> {
	let closing_tx = closing_transaction.clone().built;

	let rgb_info = get_rgb_channel_info_pending(channel_id, kv_store)
		.map_err(|e| ChannelError::close(format!("Failed to read RGB channel info: {e}")))?;
	let contract_id = rgb_info.contract_id;

	let holder_vout_amount = rgb_info.local_rgb_amount;
	let counterparty_vout_amount = rgb_info.remote_rgb_amount;

	let mut output_map = HashMap::new();

	if closing_transaction.to_holder_value_sat() > 0 {
		let holder_vout = closing_tx
			.output
			.iter()
			.position(|o| &o.script_pubkey == closing_transaction.to_holder_script())
			.ok_or_else(|| ChannelError::close("Missing holder output in closing tx".to_owned()))?;
		output_map.insert(holder_vout as u32, holder_vout_amount);
	}

	if closing_transaction.to_counterparty_value_sat() > 0 {
		let counterparty_vout = closing_tx
			.output
			.iter()
			.position(|o| &o.script_pubkey == closing_transaction.to_counterparty_script())
			.ok_or_else(|| {
				ChannelError::close("Missing counterparty output in closing tx".to_owned())
			})?;
		output_map.insert(counterparty_vout as u32, counterparty_vout_amount);
	}

	let asset_coloring_info =
		AssetColoringInfo { output_map, static_blinding: Some(STATIC_BLINDING) };
	let coloring_info = ColoringInfo {
		asset_info_map: HashMap::from_iter([(contract_id, asset_coloring_info)]),
		static_blinding: Some(STATIC_BLINDING),
		nonce: None,
	};
	let modified_tx = rgb_backend
		.prepare_transaction(closing_tx.clone(), coloring_info, kv_store)
		.map_err(|error| ChannelError::close(format!("Failed to color RGB close: {error:?}")))?;

	let txid = &modified_tx.compute_txid();
	closing_transaction.built = modified_tx;

	let transfer_info = TransferInfo { contract_id, rgb_amount: holder_vout_amount };
	kv_store
		.write_rgb_transfer_info(&txid.to_string(), &transfer_info)
		.map_err(|e| ChannelError::close(format!("Failed to write RGB transfer info: {e}")))?;

	Ok(())
}

/// Get RgbInfo from KVStore
pub(crate) fn get_rgb_channel_info(
	channel_id: &str, pending: bool, kv_store: &dyn KVStoreSync,
) -> Result<RgbInfo, io::Error> {
	kv_store.read_rgb_channel_info(channel_id, pending)
}

/// Get pending RgbInfo from KVStore
pub fn get_rgb_channel_info_pending(
	channel_id: &ChannelId, kv_store: &dyn KVStoreSync,
) -> Result<RgbInfo, io::Error> {
	get_rgb_channel_info(&channel_id.0.as_hex().to_string(), true, kv_store)
}

/// Whether the channel has RGB data in KVStore
pub fn is_channel_rgb(channel_id: &ChannelId, kv_store: &dyn KVStoreSync) -> bool {
	let channel_id_str = channel_id.0.as_hex().to_string();
	kv_store.read_rgb_channel_info(&channel_id_str, false).is_ok()
}

/// Write RGB payment info to database
pub fn write_rgb_payment_info_file(
	payment_hash: &PaymentHash, contract_id: ContractId, amount_rgb: u64, swap_payment: bool,
	inbound: bool, kv_store: &Arc<dyn KVStoreSync + Send + Sync>,
) -> Result<(), io::Error> {
	let rgb_payment_info = RgbPaymentInfo {
		contract_id,
		amount: amount_rgb,
		local_rgb_amount: 0,
		remote_rgb_amount: 0,
		swap_payment,
		inbound,
	};
	kv_store.write_rgb_payment_info(payment_hash, &rgb_payment_info)?;
	let payment_hash_hex = payment_hash.0.as_hex();
	let pending_key = format!("{payment_hash_hex}_pending");
	let namespace =
		if inbound { RGB_PAYMENT_INFO_INBOUND_NS } else { RGB_PAYMENT_INFO_OUTBOUND_NS };
	let data = bincode::serialize(&rgb_payment_info)
		.map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
	kv_store.write(RGB_PRIMARY_NS, namespace, &pending_key, data)
}

/// Rename RGB channel info from temporary to final channel ID in KVStore
pub(crate) fn rename_rgb_files(
	channel_id: &ChannelId, temporary_channel_id: &ChannelId, kv_store: &dyn KVStoreSync,
) -> Result<(), io::Error> {
	let temp_chan_id = temporary_channel_id.0.as_hex().to_string();
	let chan_id = channel_id.0.as_hex().to_string();

	let rgb_info = kv_store.read_rgb_channel_info(&temp_chan_id, false)?;
	kv_store.write_rgb_channel_info(&chan_id, &rgb_info, false)?;
	kv_store.remove_rgb_channel_info(&temp_chan_id, false)?;

	let rgb_info = kv_store.read_rgb_channel_info(&temp_chan_id, true)?;
	kv_store.write_rgb_channel_info(&chan_id, &rgb_info, true)?;
	kv_store.remove_rgb_channel_info(&temp_chan_id, true)?;

	if let Ok(consignment_data) = kv_store.read_rgb_consignment(&temp_chan_id) {
		kv_store.write_rgb_consignment(&chan_id, consignment_data)?;
		kv_store.remove_rgb_consignment(&temp_chan_id)?;
	}
	Ok(())
}

/// Persist a successfully validated incoming RGB funding transfer.
pub(crate) fn persist_funding_validation(
	temporary_channel_id: &ChannelId, funding_txid: &str, validation: RgbFundingValidation,
	push_asset_amount: Option<u64>, kv_store: &dyn KVStoreSync,
) -> Result<(), ChannelError> {
	let push_amount = push_asset_amount.unwrap_or(0);
	if push_amount > validation.received_amount {
		return Err(ChannelError::close(format!(
			"RGB push amount {push_amount} exceeds funding amount {}",
			validation.received_amount
		)));
	}
	let persist = |namespace: &str, key: &str, value: Vec<u8>| {
		kv_store.write(RGB_PRIMARY_NS, namespace, key, value).map_err(|error| {
			ChannelError::Ignore(format!("Failed to persist RGB funding validation: {error}"))
		})
	};
	persist(RGB_CONSIGNMENT_NS, funding_txid, validation.consignment.clone())?;
	let temp_chan_id = temporary_channel_id.0.as_hex().to_string();
	persist(RGB_CONSIGNMENT_NS, &temp_chan_id, validation.consignment)?;
	let rgb_info = RgbInfo {
		contract_id: validation.contract_id,
		schema: validation.schema,
		local_rgb_amount: push_amount,
		remote_rgb_amount: validation.received_amount - push_amount,
		batch_transfer_idx: None,
	};
	let rgb_info = bincode::serialize(&rgb_info).map_err(|error| {
		ChannelError::Ignore(format!("Failed to serialize RGB funding validation: {error}"))
	})?;
	persist(RGB_CHANNEL_INFO_PENDING_NS, &temp_chan_id, rgb_info.clone())?;
	persist(RGB_CHANNEL_INFO_NS, &temp_chan_id, rgb_info)?;

	Ok(())
}

/// Update RGB channel amount in KVStore
pub fn update_rgb_channel_amount(
	channel_id: &str, rgb_offered_htlc: u64, rgb_received_htlc: u64, pending: bool,
	kv_store: &dyn KVStoreSync,
) -> Result<(), io::Error> {
	let mut rgb_info = get_rgb_channel_info(channel_id, pending, kv_store)?;

	if rgb_offered_htlc > rgb_received_htlc {
		let spent = rgb_offered_htlc - rgb_received_htlc;
		rgb_info.local_rgb_amount -= spent;
		rgb_info.remote_rgb_amount += spent;
	} else {
		let received = rgb_received_htlc - rgb_offered_htlc;
		rgb_info.local_rgb_amount += received;
		rgb_info.remote_rgb_amount -= received;
	}

	kv_store.write_rgb_channel_info(channel_id, &rgb_info, pending)
}

/// Update pending RGB channel amount
pub(crate) fn update_rgb_channel_amount_pending(
	channel_id: &ChannelId, rgb_offered_htlc: u64, rgb_received_htlc: u64,
	kv_store: &dyn KVStoreSync,
) -> Result<(), io::Error> {
	update_rgb_channel_amount(
		&channel_id.0.as_hex().to_string(),
		rgb_offered_htlc,
		rgb_received_htlc,
		true,
		kv_store,
	)
}

/// extension trait for RGB-specific KVStore operations
pub trait RgbKvStoreExt {
	/// read transfer info from KVStore
	fn read_rgb_transfer_info(&self, txid: &str) -> Result<TransferInfo, io::Error>;
	/// write transfer info to KVStore
	fn write_rgb_transfer_info(&self, txid: &str, info: &TransferInfo) -> Result<(), io::Error>;
	/// read channel info from KVStore
	fn read_rgb_channel_info(&self, channel_id: &str, pending: bool) -> Result<RgbInfo, io::Error>;
	/// write channel info to KVStore
	fn write_rgb_channel_info(
		&self, channel_id: &str, rgb_info: &RgbInfo, pending: bool,
	) -> Result<(), io::Error>;
	/// read payment info from KVStore
	fn read_rgb_payment_info(
		&self, payment_hash: &PaymentHash, inbound: bool,
	) -> Result<RgbPaymentInfo, io::Error>;
	/// write payment info to KVStore
	fn write_rgb_payment_info(
		&self, payment_hash: &PaymentHash, info: &RgbPaymentInfo,
	) -> Result<(), io::Error>;
	/// read consignment from KVStore
	fn read_rgb_consignment(&self, id: &str) -> Result<Vec<u8>, io::Error>;
	/// write consignment to KVStore
	fn write_rgb_consignment(&self, id: &str, data: Vec<u8>) -> Result<(), io::Error>;
	/// remove channel info from KVStore
	fn remove_rgb_channel_info(&self, channel_id: &str, pending: bool) -> Result<(), io::Error>;
	/// remove consignment from KVStore
	fn remove_rgb_consignment(&self, id: &str) -> Result<(), io::Error>;
	/// whether the payment is colored
	fn is_payment_rgb(&self, payment_hash: &PaymentHash) -> bool;
	/// filter first hops to only include channels with sufficient RGB assets
	fn filter_first_hops(&self, payment_hash: &PaymentHash, first_hops: &mut Vec<ChannelDetails>);
}

impl<K: KVStoreSync + ?Sized> RgbKvStoreExt for K {
	fn read_rgb_transfer_info(&self, txid: &str) -> Result<TransferInfo, io::Error> {
		let data = self.read(RGB_PRIMARY_NS, RGB_TRANSFER_INFO_NS, txid)?;
		bincode::deserialize(&data)
			.map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
	}

	fn write_rgb_transfer_info(&self, txid: &str, info: &TransferInfo) -> Result<(), io::Error> {
		let data = bincode::serialize(info)
			.map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
		self.write(RGB_PRIMARY_NS, RGB_TRANSFER_INFO_NS, txid, data)
	}

	fn read_rgb_channel_info(&self, channel_id: &str, pending: bool) -> Result<RgbInfo, io::Error> {
		let namespace = if pending { RGB_CHANNEL_INFO_PENDING_NS } else { RGB_CHANNEL_INFO_NS };
		let data = self.read(RGB_PRIMARY_NS, namespace, channel_id)?;
		bincode::deserialize(&data)
			.map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
	}

	fn write_rgb_channel_info(
		&self, channel_id: &str, rgb_info: &RgbInfo, pending: bool,
	) -> Result<(), io::Error> {
		let namespace = if pending { RGB_CHANNEL_INFO_PENDING_NS } else { RGB_CHANNEL_INFO_NS };
		let data = bincode::serialize(rgb_info)
			.map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
		self.write(RGB_PRIMARY_NS, namespace, channel_id, data)
	}

	fn read_rgb_payment_info(
		&self, payment_hash: &PaymentHash, inbound: bool,
	) -> Result<RgbPaymentInfo, io::Error> {
		let namespace =
			if inbound { RGB_PAYMENT_INFO_INBOUND_NS } else { RGB_PAYMENT_INFO_OUTBOUND_NS };
		let key = payment_hash.0.as_hex().to_string();
		let data = self.read(RGB_PRIMARY_NS, namespace, &key)?;
		bincode::deserialize(&data)
			.map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
	}

	fn write_rgb_payment_info(
		&self, payment_hash: &PaymentHash, info: &RgbPaymentInfo,
	) -> Result<(), io::Error> {
		let namespace =
			if info.inbound { RGB_PAYMENT_INFO_INBOUND_NS } else { RGB_PAYMENT_INFO_OUTBOUND_NS };
		let key = payment_hash.0.as_hex().to_string();
		let data = bincode::serialize(info)
			.map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
		self.write(RGB_PRIMARY_NS, namespace, &key, data)
	}

	fn read_rgb_consignment(&self, id: &str) -> Result<Vec<u8>, io::Error> {
		self.read(RGB_PRIMARY_NS, RGB_CONSIGNMENT_NS, id)
	}

	fn write_rgb_consignment(&self, id: &str, data: Vec<u8>) -> Result<(), io::Error> {
		self.write(RGB_PRIMARY_NS, RGB_CONSIGNMENT_NS, id, data)
	}

	fn remove_rgb_channel_info(&self, channel_id: &str, pending: bool) -> Result<(), io::Error> {
		let namespace = if pending { RGB_CHANNEL_INFO_PENDING_NS } else { RGB_CHANNEL_INFO_NS };
		self.remove(RGB_PRIMARY_NS, namespace, channel_id, false)
	}

	fn remove_rgb_consignment(&self, id: &str) -> Result<(), io::Error> {
		self.remove(RGB_PRIMARY_NS, RGB_CONSIGNMENT_NS, id, false)
	}

	fn is_payment_rgb(&self, payment_hash: &PaymentHash) -> bool {
		self.read_rgb_payment_info(payment_hash, false).is_ok()
			|| self.read_rgb_payment_info(payment_hash, true).is_ok()
	}

	fn filter_first_hops(&self, payment_hash: &PaymentHash, first_hops: &mut Vec<ChannelDetails>) {
		let rgb_payment_info = match self.read_rgb_payment_info(payment_hash, false) {
			Ok(info) => info,
			Err(_) => return,
		};
		let contract_id = rgb_payment_info.contract_id;
		let rgb_amount = rgb_payment_info.amount;
		first_hops.retain(|h| {
			let channel_id_str = h.channel_id.0.as_hex().to_string();
			match self.read_rgb_channel_info(&channel_id_str, false) {
				Ok(rgb_info) => {
					rgb_info.contract_id == contract_id && rgb_info.local_rgb_amount >= rgb_amount
				},
				Err(_) => false,
			}
		});
	}
}

thread_local! {
	static HOLDER_VALIDATE_PSBT_WITNESS_SCRIPTS_HEX: RefCell<Option<Vec<String>>> =
		const { RefCell::new(None) };
}

/// Installed by [`crate::ln::channel`] before [`crate::sign::ChannelSigner::validate_holder_commitment`]
/// on RGB-colored holder commitments so an external signer can attach PSBT `witness_script`s for VLS.
pub fn holder_validate_install_psbt_output_witness_scripts_hex(hex_scripts: Vec<String>) {
	HOLDER_VALIDATE_PSBT_WITNESS_SCRIPTS_HEX.with(|c| *c.borrow_mut() = Some(hex_scripts));
}

/// Removes and returns witness script hex strings installed by [`holder_validate_install_psbt_output_witness_scripts_hex`], if any.
pub fn holder_validate_take_psbt_output_witness_scripts_hex() -> Option<Vec<String>> {
	HOLDER_VALIDATE_PSBT_WITNESS_SCRIPTS_HEX.with(|c| c.borrow_mut().take())
}

#[cfg(all(test, feature = "rgb-native"))]
mod tests {
	use super::*;

	#[test]
	fn native_schemas_convert_to_shared_schemas() {
		assert_eq!(AssetSchema::from(NativeAssetSchema::Nia), AssetSchema::Nia);
		assert_eq!(AssetSchema::from(NativeAssetSchema::Uda), AssetSchema::Uda);
		assert_eq!(AssetSchema::from(NativeAssetSchema::Cfa), AssetSchema::Cfa);
		assert_eq!(AssetSchema::from(NativeAssetSchema::Ifa), AssetSchema::Ifa);
	}

	#[test]
	fn native_assignments_convert_to_shared_assignments() {
		assert_eq!(
			Assignment::from(NativeAssignment::InflationRight(42)),
			Assignment::InflationRight(42)
		);
		assert_eq!(Assignment::from(NativeAssignment::NonFungible), Assignment::NonFungible);
	}

	#[test]
	fn native_errors_convert_to_shared_errors() {
		assert_eq!(
			RgbBackendError::from(RgbLibError::InvalidConsignment),
			RgbBackendError::InvalidConsignment
		);
		assert_eq!(
			RgbBackendError::from(RgbLibError::UnsupportedSchema {
				asset_schema: NativeAssetSchema::Cfa,
			}),
			RgbBackendError::UnsupportedSchema(AssetSchema::Cfa)
		);
	}
}
