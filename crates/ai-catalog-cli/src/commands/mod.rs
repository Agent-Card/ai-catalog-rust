// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

pub mod catalog_add;
pub mod catalog_list;
pub mod catalog_remove;
pub mod catalog_update;
pub mod pull;
pub mod search;
pub mod show;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    Table,
    Json,
}
