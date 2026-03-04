//! # kvlar-core
//!
//! Core policy engine for Kvlar. Evaluates agent actions against YAML-based
//! security policies. Pure logic — no I/O, no async, fully deterministic.
//!
//! ## Architecture
//!
//! - **Policy**: A set of rules defining what agents can and cannot do
//! - **Action**: A description of something an agent wants to do (tool call, data access, etc.)
//! - **Decision**: The engine's verdict — Allow, Deny, or RequireApproval
//! - **Engine**: Evaluates actions against loaded policies

pub mod action;
pub mod decision;
pub mod engine;
pub mod error;
pub mod policy;
pub mod testing;

pub use action::Action;
pub use decision::Decision;
pub use engine::Engine;
pub use error::KvlarError;
pub use policy::Policy;
