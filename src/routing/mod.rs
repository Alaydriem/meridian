mod backend;
mod record;
mod registry_provider;
pub(crate) mod resolve;
mod routing_table;

pub use backend::Backend;
pub use record::{RecordKey, RecordVersion, RegistryRecord};
pub use registry_provider::{LocalProvider, RegistryProvider};
pub use routing_table::RoutingTable;
