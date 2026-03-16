// -- Always available --
pub mod api;

// -- Server feature: proxy engine, config, routing --
#[cfg(feature = "server")]
pub mod config;
#[cfg(feature = "server")]
mod meridian;
#[cfg(feature = "server")]
mod meridian_builder;
#[cfg(feature = "server")]
pub mod routing;
#[cfg(feature = "server")]
pub mod tcp;
#[cfg(feature = "server")]
pub mod tls;
#[cfg(feature = "server")]
pub mod udp;

#[cfg(feature = "server")]
pub use meridian::Meridian;
#[cfg(feature = "server")]
pub use meridian_builder::MeridianBuilder;
