// SPDX-License-Identifier: MIT
//! TDX evidence verification.
//!
//! Two levels:
//!   - **Local** (`extract`): parse raw quote bytes to extract fields.
//!     Always available, no network required.
//!   - **ITA** (`ita`, feature = `ita-verify`): POST to Intel Trust Authority
//!     for server-side appraisal. Public helpers that only parse the returned
//!     JWT are explicitly named `*_unauthenticated`; stored-token verification
//!     validates the JWT first.

pub(crate) mod extract;

#[cfg(feature = "ita-verify")]
pub(crate) mod codec;

#[cfg(feature = "ita-verify")]
pub(crate) mod ita;
