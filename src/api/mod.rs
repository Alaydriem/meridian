pub mod dto;

#[cfg(feature = "client")]
pub mod client;

#[cfg(feature = "server")]
mod api_error;
#[cfg(feature = "server")]
mod backend_service;
#[cfg(feature = "server")]
mod handlers;
#[cfg(feature = "server")]
mod server;

#[cfg(feature = "client")]
pub use client::MeridianClient;
#[cfg(feature = "server")]
pub use backend_service::BackendService;
#[cfg(feature = "server")]
pub use server::ControlPlane;
