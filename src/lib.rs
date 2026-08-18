//! Library target -- exists solely so `tests/*.rs` integration tests can `use rproxy::...`.
//! The binary (`main.rs`) declares its own copy of these `mod` statements and does not depend
//! on this file; both compile the same source files independently, by design, to avoid any
//! risk of touching the production binary's module graph.
pub mod backend;
pub mod balancer;
pub mod buf_pool;
pub mod config;
pub mod cycles;
pub mod fast_proxy;
pub mod header_util;
pub mod health;
pub mod jwt;
pub mod platform;
pub mod shared;
