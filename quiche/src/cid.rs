// Copyright (C) 2022, Cloudflare, Inc.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright notice,
//       this list of conditions and the following disclaimer.
//
//     * Redistributions in binary form must reproduce the above copyright
//       notice, this list of conditions and the following disclaimer in the
//       documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
// IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
// PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
// CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
// EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
// PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
// LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
// NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

use crate::Error;
use crate::Result;
use std::cmp;

use crate::frame;

use crate::packet::ConnectionId;

#[cfg(feature = "multipath")]
use std::collections::BTreeMap;
use std::collections::HashSet;
use std::collections::VecDeque;

use smallvec::SmallVec;

/// Used to calculate the cap for the queue of retired connection IDs for which
/// a RETIRED_CONNECTION_ID frame have not been sent, as a multiple of
/// `active_conn_id_limit` (see RFC 9000, section 5.1.2).
const RETIRED_CONN_ID_LIMIT_MULTIPLIER: u64 = 3;

#[derive(Default)]
struct BoundedSeqSet<T: Eq + std::hash::Hash> {
    /// The inner set.
    inner: HashSet<T>,

    /// The maximum number of elements that the set can have.
    capacity: usize,
}

impl<T: Eq + std::hash::Hash> BoundedSeqSet<T> {
    /// Creates a set bounded by `capacity`.
    fn new(capacity: usize) -> Self {
        Self {
            inner: HashSet::new(),
            capacity,
        }
    }

    fn insert(&mut self, e: T) -> Result<bool> {
        // An element that is already present does not consume any additional
        // capacity, so re-inserting it (e.g., upon retransmission of a frame
        // that retires the same sequence number again) must not fail, even
        // when the set is full.
        if self.inner.contains(&e) {
            return Ok(false);
        }

        if self.inner.len() >= self.capacity {
            return Err(Error::IdLimit);
        }

        Ok(self.inner.insert(e))
    }

    /// Updates the maximum capacity of the set to `new_capacity`. The
    /// capacity only grows: this does nothing if `new_capacity` is lower
    /// than or equal to the current one.
    #[cfg(feature = "multipath")]
    fn set_capacity(&mut self, new_capacity: usize) {
        if new_capacity > self.capacity {
            self.capacity = new_capacity;
        }
    }

    fn remove(&mut self, e: &T) -> bool {
        self.inner.remove(e)
    }

    fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

/// Type alias for the single-sequence-number variant used by the legacy
/// connection ID pools.
type BoundedConnectionIdSeqSet = BoundedSeqSet<u64>;

/// A structure holding a `ConnectionId` and all its related metadata.
#[derive(Debug, Default)]
pub struct ConnectionIdEntry {
    /// The Connection ID.
    pub cid: ConnectionId<'static>,

    /// Its associated sequence number.
    pub seq: u64,

    /// Its associated reset token. Initial CIDs may not have any reset token.
    pub reset_token: Option<u128>,

    /// The path identifier using this CID, if any.
    pub path_id: Option<usize>,
}

#[derive(Default)]
struct BoundedNonEmptyConnectionIdVecDeque {
    /// The inner `VecDeque`.
    inner: VecDeque<ConnectionIdEntry>,

    /// The maximum number of elements that the `VecDeque` can have.
    capacity: usize,
}

impl BoundedNonEmptyConnectionIdVecDeque {
    /// Creates a `VecDeque` bounded by `capacity` and inserts
    /// `initial_entry` in it.
    fn new(capacity: usize, initial_entry: ConnectionIdEntry) -> Self {
        let mut inner = VecDeque::with_capacity(1);
        inner.push_back(initial_entry);
        Self { inner, capacity }
    }

    /// Updates the maximum capacity of the inner `VecDeque` to `new_capacity`.
    /// Does nothing if `new_capacity` is lower or equal to the current
    /// `capacity`.
    fn resize(&mut self, new_capacity: usize) {
        if new_capacity > self.capacity {
            self.capacity = new_capacity;
        }
    }

    /// Returns the oldest inserted entry still present in the `VecDeque`.
    fn get_oldest(&self) -> &ConnectionIdEntry {
        self.inner.front().expect("vecdeque is empty")
    }

    /// Gets a immutable reference to the entry having the provided `seq`.
    fn get(&self, seq: u64) -> Option<&ConnectionIdEntry> {
        // We need to iterate over the whole map to find the key.
        self.inner.iter().find(|e| e.seq == seq)
    }

    /// Gets a mutable reference to the entry having the provided `seq`.
    fn get_mut(&mut self, seq: u64) -> Option<&mut ConnectionIdEntry> {
        // We need to iterate over the whole map to find the key.
        self.inner.iter_mut().find(|e| e.seq == seq)
    }

    /// Returns an iterator over the entries in the `VecDeque`.
    fn iter(&self) -> impl Iterator<Item = &ConnectionIdEntry> {
        self.inner.iter()
    }

    /// Returns the number of elements in the `VecDeque`.
    fn len(&self) -> usize {
        self.inner.len()
    }

    /// Inserts the provided entry in the `VecDeque`.
    ///
    /// This method ensures the unicity of the `seq` associated to an entry. If
    /// an entry has the same `seq` than `e`, this method updates the entry in
    /// the `VecDeque` and the number of stored elements remains unchanged.
    ///
    /// If inserting a new element would exceed the collection's capacity, this
    /// method raises an [`IdLimit`].
    ///
    /// [`IdLimit`]: enum.Error.html#IdLimit
    fn insert(&mut self, e: ConnectionIdEntry) -> Result<()> {
        // Ensure we don't have duplicates.
        match self.get_mut(e.seq) {
            Some(oe) => *oe = e,
            None => {
                if self.inner.len() >= self.capacity {
                    return Err(Error::IdLimit);
                }
                self.inner.push_back(e);
            },
        };
        Ok(())
    }

    /// Removes all the elements in the collection and inserts the provided one.
    fn clear_and_insert(&mut self, e: ConnectionIdEntry) {
        self.inner.clear();
        self.inner.push_back(e);
    }

    /// Removes the element in the collection having the provided `seq`.
    ///
    /// If this method is called when there remains a single element in the
    /// collection, this method raises an [`OutOfIdentifiers`].
    ///
    /// Returns `Some` if the element was in the collection and removed, or
    /// `None` if it was not and nothing was modified.
    ///
    /// [`OutOfIdentifiers`]: enum.Error.html#OutOfIdentifiers
    fn remove(&mut self, seq: u64) -> Result<Option<ConnectionIdEntry>> {
        if self.inner.len() <= 1 {
            return Err(Error::OutOfIdentifiers);
        }

        Ok(self
            .inner
            .iter()
            .position(|e| e.seq == seq)
            .and_then(|index| self.inner.remove(index)))
    }

    /// Removes the element in the collection having the provided `seq`,
    /// allowing the collection to become empty.
    ///
    /// Unlike [`remove`], this does **not** enforce the non-empty invariant.
    /// It is intended for per-path SCID pools only: the non-empty invariant
    /// is correct for the legacy CID space (where the carrying packet's DCID
    /// always remains), but per-path pools may legitimately drain to zero
    /// when a peer retires our only SCID for that path (RFC 9000 §19.16 per
    /// path; draft-ietf-quic-multipath-21 §4.5). Only seq-never-issued and
    /// CID == carrying-packet-DCID are wire error conditions, not emptiness.
    ///
    /// Returns `Some` if the element was present and removed, `None`
    /// otherwise.
    ///
    /// [`remove`]: #method.remove
    #[cfg(feature = "multipath")]
    fn remove_allow_empty(
        &mut self, seq: u64,
    ) -> Option<ConnectionIdEntry> {
        self.inner
            .iter()
            .position(|e| e.seq == seq)
            .and_then(|index| self.inner.remove(index))
    }

    /// Removes all the elements in the collection, allowing it to become
    /// empty. Used when all the connection IDs of an abandoned path are
    /// implicitly retired at once (draft-ietf-quic-multipath-21 §3.4).
    #[cfg(feature = "multipath")]
    fn clear_allow_empty(&mut self) {
        self.inner.clear();
    }
}

#[derive(Default)]
pub struct ConnectionIdentifiers {
    /// All the Destination Connection IDs provided by our peer.
    dcids: BoundedNonEmptyConnectionIdVecDeque,

    /// All the Source Connection IDs we provide to our peer.
    scids: BoundedNonEmptyConnectionIdVecDeque,

    /// Source Connection IDs that should be announced to the peer.
    advertise_new_scid_seqs: VecDeque<u64>,

    /// Retired Destination Connection IDs that should be announced to the peer.
    retire_dcid_seqs: BoundedConnectionIdSeqSet,

    /// Retired Source Connection IDs that should be notified to the
    /// application.
    retired_scids: VecDeque<ConnectionId<'static>>,

    /// Largest "Retire Prior To" we received from the peer.
    largest_peer_retire_prior_to: u64,

    /// Largest sequence number we received from the peer.
    largest_destination_seq: u64,

    /// Next sequence number to use.
    next_scid_seq: u64,

    /// "Retire Prior To" value to advertise to the peer.
    retire_prior_to: u64,

    /// The maximum number of source Connection IDs our peer allows us.
    source_conn_id_limit: usize,

    /// Does the host use zero-length source Connection ID.
    zero_length_scid: bool,

    /// Does the host use zero-length destination Connection ID.
    zero_length_dcid: bool,

    /// Per-Path ID connection ID pools for non-zero path identifiers
    /// (draft-ietf-quic-multipath-21, Section 2.2). Path ID 0 uses the
    /// legacy `scids`/`dcids` collections above.
    #[cfg(feature = "multipath")]
    mp_pools: BTreeMap<u64, PathCidPool>,

    /// Per-path source CIDs that should be advertised to the peer through
    /// PATH_NEW_CONNECTION_ID frames, as (path_id, seq) pairs.
    #[cfg(feature = "multipath")]
    mp_advertise_new_scid_seqs: VecDeque<(u64, u64)>,

    /// Per-path retired destination CIDs that should be advertised to the
    /// peer through PATH_RETIRE_CONNECTION_ID frames, as (path_id, seq)
    /// pairs. Bounded to `destination_conn_id_limit *
    /// RETIRED_CONN_ID_LIMIT_MULTIPLIER` to prevent unbounded growth.
    #[cfg(feature = "multipath")]
    mp_retire_dcid_seqs: BoundedSeqSet<(u64, u64)>,
}

/// Per-Path ID connection ID pool (draft-ietf-quic-multipath-21, Sections
/// 2.2 and 3.2).
///
/// Every non-zero path identifier has its own connection ID sequence number
/// spaces in both directions, each starting at 0, with the active connection
/// ID limits applying per path. Path ID 0 reuses the legacy `scids`/`dcids`
/// collections of `ConnectionIdentifiers`, so that legacy NEW_CONNECTION_ID
/// and RETIRE_CONNECTION_ID frames and their PATH_* equivalents carrying
/// Path ID 0 operate on the very same spaces.
///
/// The pools reuse `BoundedNonEmptyConnectionIdVecDeque` but start empty
/// (via `Default`, with capacity adjusted on insertion); its `remove()`
/// invariant then enforces that a path keeps at least one active CID once
/// populated, mirroring the legacy behavior.
#[cfg(feature = "multipath")]
#[derive(Default)]
struct PathCidPool {
    /// Source CIDs we issued to the peer for this path.
    scids: BoundedNonEmptyConnectionIdVecDeque,

    /// Destination CIDs the peer issued to us for this path.
    dcids: BoundedNonEmptyConnectionIdVecDeque,

    /// Next source CID sequence number to issue on this path.
    next_scid_seq: u64,

    /// "Retire Prior To" value to advertise to the peer for this path.
    retire_prior_to: u64,

    /// Largest "Retire Prior To" received from the peer on this path.
    largest_peer_retire_prior_to: u64,

    /// Largest DCID sequence number received from the peer on this path.
    largest_destination_seq: u64,
}

impl ConnectionIdentifiers {
    /// Creates a new `ConnectionIdentifiers` with the specified destination
    /// connection ID limit and initial source Connection ID. The destination
    /// Connection ID is set to the empty one.
    pub fn new(
        mut destination_conn_id_limit: usize, initial_scid: &ConnectionId,
        initial_path_id: usize, reset_token: Option<u128>,
    ) -> ConnectionIdentifiers {
        // It must be at least 2.
        if destination_conn_id_limit < 2 {
            destination_conn_id_limit = 2;
        }

        // Initially, the limit of active source connection IDs is 2.
        let source_conn_id_limit = 2;

        // Record the zero-length SCID status.
        let zero_length_scid = initial_scid.is_empty();

        let initial_scid =
            ConnectionId::from_ref(initial_scid.as_ref()).into_owned();

        // We need to track up to (2 * source_conn_id_limit - 1) source
        // Connection IDs when the host wants to force their renewal.
        let scids = BoundedNonEmptyConnectionIdVecDeque::new(
            2 * source_conn_id_limit - 1,
            ConnectionIdEntry {
                cid: initial_scid,
                seq: 0,
                reset_token,
                path_id: Some(initial_path_id),
            },
        );

        let dcids = BoundedNonEmptyConnectionIdVecDeque::new(
            destination_conn_id_limit,
            ConnectionIdEntry {
                cid: ConnectionId::default(),
                seq: 0,
                reset_token: None,
                path_id: Some(initial_path_id),
            },
        );

        // Guard against overflow.
        let value =
            (destination_conn_id_limit as u64) * RETIRED_CONN_ID_LIMIT_MULTIPLIER;
        let size = cmp::min(usize::MAX as u64, value) as usize;
        // Because we already inserted the initial SCID.
        let next_scid_seq = 1;
        ConnectionIdentifiers {
            scids,
            dcids,
            retire_dcid_seqs: BoundedConnectionIdSeqSet::new(size),
            next_scid_seq,
            source_conn_id_limit,
            zero_length_scid,
            #[cfg(feature = "multipath")]
            mp_retire_dcid_seqs: BoundedSeqSet::new(size),
            ..Default::default()
        }
    }

    /// Sets the maximum number of source connection IDs our peer allows us.
    pub fn set_source_conn_id_limit(&mut self, v: u64) {
        // Bound conn id limit so our scids queue sizing is valid.
        let v = cmp::min(v, (usize::MAX / 2) as u64) as usize;

        // It must be at least 2.
        if v >= 2 {
            self.source_conn_id_limit = v;
            // We need to track up to (2 * source_conn_id_limit - 1) source
            // Connection IDs when the host wants to force their renewal.
            self.scids.resize(2 * v - 1);
        }
    }

    /// Gets the destination Connection ID associated with the provided sequence
    /// number.
    #[inline]
    pub fn get_dcid(&self, seq_num: u64) -> Result<&ConnectionIdEntry> {
        self.dcids.get(seq_num).ok_or(Error::InvalidState)
    }

    /// Gets the source Connection ID associated with the provided sequence
    /// number.
    #[inline]
    pub fn get_scid(&self, seq_num: u64) -> Result<&ConnectionIdEntry> {
        self.scids.get(seq_num).ok_or(Error::InvalidState)
    }

    /// Adds a new source identifier, and indicates whether it should be
    /// advertised through a `NEW_CONNECTION_ID` frame or not.
    ///
    /// At any time, the peer cannot have more Destination Connection IDs than
    /// the maximum number of active Connection IDs it negotiated. In such case
    /// (i.e., when [`active_source_cids()`] - `peer_active_conn_id_limit` = 0,
    /// if the caller agrees to request the removal of previous connection IDs,
    /// it sets the `retire_if_needed` parameter. Otherwise, an [`IdLimit`] is
    /// returned.
    ///
    /// Note that setting `retire_if_needed` does not prevent this function from
    /// returning an [`IdLimit`] in the case the caller wants to retire still
    /// unannounced Connection IDs.
    ///
    /// When setting the initial Source Connection ID, the `reset_token` may be
    /// `None`. However, other Source CIDs must have an associated
    /// `reset_token`. Providing `None` as the `reset_token` for non-initial
    /// SCIDs raises an [`InvalidState`].
    ///
    /// In the case the provided `cid` is already present, it does not add it.
    /// If the provided `reset_token` differs from the one already registered,
    /// returns an `InvalidState`.
    ///
    /// Returns the sequence number associated to that new source identifier.
    ///
    /// [`active_source_cids()`]:  struct.ConnectionIdentifiers.html#method.active_source_cids
    /// [`InvalidState`]: enum.Error.html#InvalidState
    /// [`IdLimit`]: enum.Error.html#IdLimit
    pub fn new_scid(
        &mut self, cid: ConnectionId<'static>, reset_token: Option<u128>,
        advertise: bool, path_id: Option<usize>, retire_if_needed: bool,
    ) -> Result<u64> {
        if self.zero_length_scid {
            return Err(Error::InvalidState);
        }

        // Check whether the number of source Connection IDs does not exceed the
        // limit. If the host agrees to retire old CIDs, it can store up to
        // (2 * source_active_conn_id - 1) source CIDs. This limit is enforced
        // when calling `self.scids.insert()`.
        if self.scids.len() >= self.source_conn_id_limit {
            if !retire_if_needed {
                return Err(Error::IdLimit);
            }

            // We need to retire the lowest one.
            self.retire_prior_to = self.lowest_usable_scid_seq()? + 1;
        }

        let seq = self.next_scid_seq;

        if reset_token.is_none() && seq != 0 {
            return Err(Error::InvalidState);
        }

        // Check first that the SCID has not been inserted before.
        if let Some(e) = self.scids.iter().find(|e| e.cid == cid) {
            if e.reset_token != reset_token {
                return Err(Error::InvalidState);
            }
            return Ok(e.seq);
        }

        // When multipath is enabled, CID bytes must be globally unique across
        // all paths and both directions (draft-ietf-quic-multipath-21 §3.2.1).
        // The legacy-scids check above already short-circuited any CID
        // present in the path-0 SCID space, so `mp_cid_in_use()`'s extra
        // scids scan is always false here and the check is equivalent to
        // scanning the legacy DCID pool and every per-path (non-zero)
        // SCID/DCID pool.
        #[cfg(feature = "multipath")]
        if self.mp_cid_in_use(&cid) {
            return Err(Error::InvalidState);
        }

        self.scids.insert(ConnectionIdEntry {
            cid,
            seq,
            reset_token,
            path_id,
        })?;
        self.next_scid_seq += 1;

        self.mark_advertise_new_scid_seq(seq, advertise);

        Ok(seq)
    }

    /// Sets the initial destination identifier.
    pub fn set_initial_dcid(
        &mut self, cid: ConnectionId<'static>, reset_token: Option<u128>,
        path_id: Option<usize>,
    ) {
        // Record the zero-length DCID status.
        self.zero_length_dcid = cid.is_empty();
        self.dcids.clear_and_insert(ConnectionIdEntry {
            cid,
            seq: 0,
            reset_token,
            path_id,
        });
    }

    /// Adds a new Destination Connection ID (originating from a
    /// NEW_CONNECTION_ID frame) and process all its related metadata.
    ///
    /// Returns an error if the provided Connection ID or its metadata are
    /// invalid.
    ///
    /// Returns a list of tuples (DCID sequence number, Path ID), containing the
    /// sequence number of retired DCIDs that were linked to their respective
    /// Path ID.
    // Keep in sync with `mp_new_dcid()`, which replicates this logic (in
    // particular the delayed propagation of the retire-queue `IdLimit`
    // error) for non-zero multipath path IDs.
    pub fn new_dcid(
        &mut self, cid: ConnectionId<'static>, seq: u64, reset_token: u128,
        retire_prior_to: u64, retired_path_ids: &mut SmallVec<[(u64, usize); 1]>,
    ) -> Result<()> {
        if self.zero_length_dcid {
            return Err(Error::InvalidState);
        }

        // If an endpoint receives a NEW_CONNECTION_ID frame that repeats a
        // previously issued connection ID with a different Stateless Reset
        // Token field value or a different Sequence Number field value, or if a
        // sequence number is used for different connection IDs, the endpoint
        // MAY treat that receipt as a connection error of type
        // PROTOCOL_VIOLATION.
        if let Some(e) = self.dcids.iter().find(|e| e.cid == cid || e.seq == seq)
        {
            if e.cid != cid || e.seq != seq || e.reset_token != Some(reset_token)
            {
                return Err(Error::InvalidFrame);
            }
            // The identifier is already there, nothing to do.
            return Ok(());
        }

        // The value in the Retire Prior To field MUST be less than or equal to
        // the value in the Sequence Number field. Receiving a value in the
        // Retire Prior To field that is greater than that in the Sequence
        // Number field MUST be treated as a connection error of type
        // FRAME_ENCODING_ERROR.
        if retire_prior_to > seq {
            return Err(Error::InvalidFrame);
        }

        // An endpoint that receives a NEW_CONNECTION_ID frame with a sequence
        // number smaller than the Retire Prior To field of a previously
        // received NEW_CONNECTION_ID frame MUST send a corresponding
        // RETIRE_CONNECTION_ID frame that retires the newly received connection
        // ID, unless it has already done so for that sequence number.
        if seq < self.largest_peer_retire_prior_to {
            self.mark_retire_dcid_seq(seq, true)?;
            return Ok(());
        }

        if seq > self.largest_destination_seq {
            self.largest_destination_seq = seq;
        }

        let new_entry = ConnectionIdEntry {
            cid: cid.clone(),
            seq,
            reset_token: Some(reset_token),
            path_id: None,
        };

        let mut retired_dcid_queue_err = None;

        // A receiver MUST ignore any Retire Prior To fields that do not
        // increase the largest received Retire Prior To value.
        //
        // After processing a NEW_CONNECTION_ID frame and adding and retiring
        // active connection IDs, if the number of active connection IDs exceeds
        // the value advertised in its active_connection_id_limit transport
        // parameter, an endpoint MUST close the connection with an error of type
        // CONNECTION_ID_LIMIT_ERROR.
        if retire_prior_to > self.largest_peer_retire_prior_to {
            let retired = &mut self.retire_dcid_seqs;

            // The insert entry MUST have a sequence higher or equal to the ones
            // being retired.
            if new_entry.seq < retire_prior_to {
                return Err(Error::OutOfIdentifiers);
            }

            // To avoid exceeding the capacity of the inner `VecDeque`, we first
            // remove the elements and then insert the new one.
            let index = self
                .dcids
                .inner
                .partition_point(|e| e.seq < retire_prior_to);

            for e in self.dcids.inner.drain(..index) {
                if let Some(pid) = e.path_id {
                    retired_path_ids.push((e.seq, pid));
                }

                if let Err(e) = retired.insert(e.seq) {
                    // Delay propagating the error as we need to try to insert
                    // the new DCID first.
                    retired_dcid_queue_err = Some(e);
                    break;
                }
            }

            self.largest_peer_retire_prior_to = retire_prior_to;
        }

        // Note that if no element has been retired and the `VecDeque` reaches
        // its capacity limit, this will raise an `IdLimit`.
        self.dcids.insert(new_entry)?;

        // Propagate the error triggered when inserting a retired DCID seq to
        // the queue.
        if let Some(e) = retired_dcid_queue_err {
            return Err(e);
        }

        Ok(())
    }

    /// Retires the Source Connection ID having the provided sequence number.
    ///
    /// In case the retired Connection ID is the same as the one used by the
    /// packet requesting the retiring, or if the retired sequence number is
    /// greater than any previously advertised sequence numbers, it returns an
    /// [`InvalidState`].
    ///
    /// Returns the path ID that was associated to the retired CID, if any.
    ///
    /// [`InvalidState`]: enum.Error.html#InvalidState
    pub fn retire_scid(
        &mut self, seq: u64, pkt_dcid: &ConnectionId,
    ) -> Result<Option<usize>> {
        if seq >= self.next_scid_seq {
            return Err(Error::InvalidState);
        }

        let pid = if let Some(e) = self.scids.remove(seq)? {
            if e.cid == *pkt_dcid {
                return Err(Error::InvalidState);
            }

            // Notifies the application.
            self.retired_scids.push_back(e.cid);

            // Retiring this SCID may increase the retire prior to.
            let lowest_scid_seq = self.lowest_usable_scid_seq()?;
            self.retire_prior_to = lowest_scid_seq;

            e.path_id
        } else {
            None
        };

        Ok(pid)
    }

    /// Retires the Destination Connection ID having the provided sequence
    /// number.
    ///
    /// If the caller tries to retire the last destination Connection ID, this
    /// method triggers an [`OutOfIdentifiers`].
    ///
    /// If the caller tries to retire a non-existing Destination Connection
    /// ID sequence number, this method returns an [`InvalidState`].
    ///
    /// Returns the path ID that was associated to the retired CID, if any.
    ///
    /// [`OutOfIdentifiers`]: enum.Error.html#OutOfIdentifiers
    /// [`InvalidState`]: enum.Error.html#InvalidState
    pub fn retire_dcid(&mut self, seq: u64) -> Result<Option<usize>> {
        if self.zero_length_dcid {
            return Err(Error::InvalidState);
        }

        let e = self.dcids.remove(seq)?.ok_or(Error::InvalidState)?;

        self.mark_retire_dcid_seq(seq, true)?;

        Ok(e.path_id)
    }

    /// Returns an iterator over the source connection IDs.
    pub fn scids_iter(&self) -> impl Iterator<Item = &ConnectionId<'_>> {
        self.scids.iter().map(|e| &e.cid)
    }

    /// Updates the Source Connection ID entry with the provided sequence number
    /// to indicate that it is now linked to the provided path ID.
    pub fn link_scid_to_path_id(
        &mut self, dcid_seq: u64, path_id: usize,
    ) -> Result<()> {
        let e = self.scids.get_mut(dcid_seq).ok_or(Error::InvalidState)?;
        e.path_id = Some(path_id);
        Ok(())
    }

    /// Updates the Destination Connection ID entry with the provided sequence
    /// number to indicate that it is now linked to the provided path ID.
    pub fn link_dcid_to_path_id(
        &mut self, dcid_seq: u64, path_id: usize,
    ) -> Result<()> {
        let e = self.dcids.get_mut(dcid_seq).ok_or(Error::InvalidState)?;
        e.path_id = Some(path_id);
        Ok(())
    }

    /// Gets the minimum Source Connection ID sequence number whose removal has
    /// not been requested yet.
    #[inline]
    pub fn lowest_usable_scid_seq(&self) -> Result<u64> {
        self.scids
            .iter()
            .filter_map(|e| {
                if e.seq >= self.retire_prior_to {
                    Some(e.seq)
                } else {
                    None
                }
            })
            .min()
            .ok_or(Error::InvalidState)
    }

    /// Gets the lowest Destination Connection ID sequence number that is not
    /// associated to a path.
    #[inline]
    pub fn lowest_available_dcid_seq(&self) -> Option<u64> {
        self.dcids
            .iter()
            .filter_map(|e| {
                if e.path_id.is_none() {
                    Some(e.seq)
                } else {
                    None
                }
            })
            .min()
    }

    /// Finds the sequence number of the Source Connection ID having the
    /// provided value and the identifier of the path using it, if any.
    #[inline]
    pub fn find_scid_seq(
        &self, scid: &ConnectionId,
    ) -> Option<(u64, Option<usize>)> {
        self.scids.iter().find_map(|e| {
            if e.cid == *scid {
                Some((e.seq, e.path_id))
            } else {
                None
            }
        })
    }

    /// Returns the number of Source Connection IDs that have not been
    /// assigned to a path yet.
    ///
    /// Note that this function is only meaningful if the host uses non-zero
    /// length Source Connection IDs.
    #[inline]
    pub fn available_scids(&self) -> usize {
        self.scids.iter().filter(|e| e.path_id.is_none()).count()
    }

    /// Returns the number of Destination Connection IDs that have not been
    /// assigned to a path yet.
    ///
    /// Note that this function returns 0 if the host uses zero length
    /// Destination Connection IDs.
    #[inline]
    pub fn available_dcids(&self) -> usize {
        if self.zero_length_dcid() {
            return 0;
        }
        self.dcids.iter().filter(|e| e.path_id.is_none()).count()
    }

    /// Returns the oldest active source Connection ID of this connection.
    #[inline]
    pub fn oldest_scid(&self) -> &ConnectionIdEntry {
        self.scids.get_oldest()
    }

    /// Returns the oldest known active destination Connection ID of this
    /// connection.
    ///
    /// Note that due to e.g., reordering at reception side, the oldest known
    /// active destination Connection ID is not necessarily the one having the
    /// lowest sequence.
    #[inline]
    pub fn oldest_dcid(&self) -> &ConnectionIdEntry {
        self.dcids.get_oldest()
    }

    /// Adds or remove the source Connection ID sequence number from the
    /// source Connection ID set that need to be advertised to the peer through
    /// NEW_CONNECTION_ID frames.
    #[inline]
    pub fn mark_advertise_new_scid_seq(
        &mut self, scid_seq: u64, advertise: bool,
    ) {
        if advertise {
            self.advertise_new_scid_seqs.push_back(scid_seq);
        } else if let Some(index) = self
            .advertise_new_scid_seqs
            .iter()
            .position(|s| *s == scid_seq)
        {
            self.advertise_new_scid_seqs.remove(index);
        }
    }

    /// Adds or remove the destination Connection ID sequence number from the
    /// retired destination Connection ID set that need to be advertised to the
    /// peer through RETIRE_CONNECTION_ID frames.
    #[inline]
    pub fn mark_retire_dcid_seq(
        &mut self, dcid_seq: u64, retire: bool,
    ) -> Result<()> {
        if retire {
            self.retire_dcid_seqs.insert(dcid_seq)?;
        } else {
            self.retire_dcid_seqs.remove(&dcid_seq);
        }

        Ok(())
    }

    /// Gets a source Connection ID's sequence number requiring advertising it
    /// to the peer through NEW_CONNECTION_ID frame, if any.
    ///
    /// If `Some`, it always returns the same value until it has been removed
    /// using `mark_advertise_new_scid_seq`.
    #[inline]
    pub fn next_advertise_new_scid_seq(&self) -> Option<u64> {
        self.advertise_new_scid_seqs.front().copied()
    }

    /// Returns a copy of the set of destination Connection IDs's sequence
    /// numbers to send RETIRE_CONNECTION_ID frames.
    ///
    /// Note that the set includes sequence numbers at the time the copy was
    /// created. To account for newly inserted or removed sequence numbers, a
    /// new copy needs to be created.
    #[inline]
    pub fn retire_dcid_seqs(&self) -> HashSet<u64> {
        self.retire_dcid_seqs.inner.clone()
    }

    /// Returns true if there are new source Connection IDs to advertise.
    #[inline]
    pub fn has_new_scids(&self) -> bool {
        !self.advertise_new_scid_seqs.is_empty()
    }

    /// Returns true if there are retired destination Connection IDs to\
    /// advertise.
    #[inline]
    pub fn has_retire_dcids(&self) -> bool {
        !self.retire_dcid_seqs.is_empty()
    }

    /// Returns whether zero-length source CIDs are used.
    #[inline]
    pub fn zero_length_scid(&self) -> bool {
        self.zero_length_scid
    }

    /// Returns whether zero-length destination CIDs are used.
    #[inline]
    pub fn zero_length_dcid(&self) -> bool {
        self.zero_length_dcid
    }

    /// Gets the NEW_CONNECTION_ID frame related to the source connection ID
    /// with sequence `seq_num`.
    pub fn get_new_connection_id_frame_for(
        &self, seq_num: u64,
    ) -> Result<frame::Frame> {
        let e = self.scids.get(seq_num).ok_or(Error::InvalidState)?;
        Ok(frame::Frame::NewConnectionId {
            seq_num,
            retire_prior_to: self.retire_prior_to,
            conn_id: e.cid.to_vec(),
            reset_token: e.reset_token.ok_or(Error::InvalidState)?.to_be_bytes(),
        })
    }

    /// Returns the number of source Connection IDs that are active. This is
    /// only meaningful if the host uses non-zero length Source Connection IDs.
    #[inline]
    pub fn active_source_cids(&self) -> usize {
        self.scids.len()
    }

    /// Returns the number of source Connection IDs that are retired. This is
    /// only meaningful if the host uses non-zero length Source Connection IDs.
    #[inline]
    pub fn retired_source_cids(&self) -> usize {
        self.retired_scids.len()
    }

    pub fn pop_retired_scid(&mut self) -> Option<ConnectionId<'static>> {
        self.retired_scids.pop_front()
    }
}

/// Per-Path ID connection ID pool management
/// (draft-ietf-quic-multipath-21, Sections 2.2 and 3.2).
///
/// All methods taking a `path_id` treat Path ID 0 as the initial path and
/// delegate to the legacy single-space methods, so that legacy
/// NEW_CONNECTION_ID/RETIRE_CONNECTION_ID frames and PATH_* frames carrying
/// Path ID 0 are equivalent.
// TODO(multipath): drop the `allow(dead_code)` once the PATH_NEW_CONNECTION_ID
// and PATH_RETIRE_CONNECTION_ID frame handlers and the send-side wiring use
// these methods.
#[cfg(feature = "multipath")]
#[allow(dead_code)]
impl ConnectionIdentifiers {
    /// Returns whether the provided CID bytes are already used by any
    /// connection ID known to this connection, on any path and on either the
    /// source or destination side.
    ///
    /// Connection ID values must be unique across the whole connection,
    /// whatever the path ID (draft-ietf-quic-multipath-21, Section 3.2.1).
    fn mp_cid_in_use(&self, cid: &ConnectionId) -> bool {
        self.scids.iter().any(|e| e.cid == *cid) ||
            self.dcids.iter().any(|e| e.cid == *cid) ||
            self.mp_pools.values().any(|p| {
                p.scids.iter().any(|e| e.cid == *cid) ||
                    p.dcids.iter().any(|e| e.cid == *cid)
            })
    }

    /// Ensures that a connection ID pool exists for the provided non-zero
    /// path ID, creating an empty one if needed.
    ///
    /// Whenever a new pool is created, the capacity of the pending
    /// PATH_RETIRE_CONNECTION_ID set is grown to `(1 + number of pools) *
    /// destination_conn_id_limit * RETIRED_CONN_ID_LIMIT_MULTIPLIER`, so
    /// that a legitimate retirement wave spanning several paths cannot
    /// spuriously exhaust a single path's budget and close the connection
    /// with an [`IdLimit`].
    ///
    /// [`IdLimit`]: enum.Error.html#IdLimit
    fn mp_ensure_pool(&mut self, path_id: u64) {
        if self.mp_pools.contains_key(&path_id) {
            return;
        }

        self.mp_pools.insert(path_id, PathCidPool::default());

        // Guard against overflow, like in `new()`. `self.dcids.capacity` is
        // the destination connection ID limit.
        let value = (1 + self.mp_pools.len() as u64)
            .saturating_mul(self.dcids.capacity as u64)
            .saturating_mul(RETIRED_CONN_ID_LIMIT_MULTIPLIER);
        let size = cmp::min(usize::MAX as u64, value) as usize;
        self.mp_retire_dcid_seqs.set_capacity(size);
    }

    /// Adds a new source identifier for the provided path ID and queues its
    /// advertisement through a PATH_NEW_CONNECTION_ID frame. For path ID 0,
    /// the advertisement is instead queued through the legacy
    /// NEW_CONNECTION_ID queue, as legacy frames are the ones carrying
    /// path-0 CIDs.
    ///
    /// The sequence number spaces are per path and start at 0. The number of
    /// active source CIDs is limited per path by the maximum number of
    /// source Connection IDs our peer allows us; exceeding it raises an
    /// [`IdLimit`].
    ///
    /// Providing a CID whose bytes are already used anywhere on the
    /// connection raises an [`InvalidState`].
    ///
    /// For path ID 0, this delegates to [`new_scid()`], operating on the
    /// very same sequence number space as legacy NEW_CONNECTION_ID frames.
    ///
    /// Returns the sequence number associated to that new source identifier
    /// in the path's sequence number space.
    ///
    /// [`new_scid()`]: struct.ConnectionIdentifiers.html#method.new_scid
    /// [`InvalidState`]: enum.Error.html#InvalidState
    /// [`IdLimit`]: enum.Error.html#IdLimit
    pub fn mp_new_scid(
        &mut self, path_id: u64, cid: ConnectionId<'static>, reset_token: u128,
    ) -> Result<u64> {
        if path_id == 0 {
            return self.new_scid(cid, Some(reset_token), true, None, false);
        }

        if self.zero_length_scid {
            return Err(Error::InvalidState);
        }

        // CID bytes must be unique across all paths and both directions.
        if self.mp_cid_in_use(&cid) {
            return Err(Error::InvalidState);
        }

        let limit = self.source_conn_id_limit;
        self.mp_ensure_pool(path_id);
        let pool = self
            .mp_pools
            .get_mut(&path_id)
            .expect("pool exists after mp_ensure_pool");

        // The active connection ID limit applies per path.
        if pool.scids.len() >= limit {
            return Err(Error::IdLimit);
        }
        pool.scids.resize(limit);

        let seq = pool.next_scid_seq;
        pool.scids.insert(ConnectionIdEntry {
            cid,
            seq,
            reset_token: Some(reset_token),
            path_id: None,
        })?;
        pool.next_scid_seq += 1;

        self.mp_advertise_new_scid_seqs.push_back((path_id, seq));

        Ok(seq)
    }

    /// Adds a new Destination Connection ID for the provided path ID
    /// (originating from a PATH_NEW_CONNECTION_ID frame) and processes all
    /// its related metadata, with RFC 9000 Section 19.15 semantics applied
    /// per path.
    ///
    /// Returns an error if the provided Connection ID or its metadata are
    /// invalid.
    ///
    /// DCIDs retired by the Retire Prior To field are appended to `retired`
    /// as `(path ID, sequence number, slab path ID)` triples — the last
    /// element being the (4-tuple) path that was using the retired DCID, if
    /// any — and queued for later PATH_RETIRE_CONNECTION_ID emission. The
    /// caller must unlink/re-fund any affected 4-tuple path, even when this
    /// method returns an error: entries may have been retired before the
    /// error was detected.
    ///
    /// For path ID 0, this delegates to [`new_dcid()`], operating on the
    /// very same sequence number space as legacy NEW_CONNECTION_ID frames.
    /// Note an asymmetry, kept from the legacy method: for path 0 only
    /// drained entries that were linked to a 4-tuple path are reported
    /// (always with `Some` slab path ID), while for non-zero path IDs every
    /// drained entry is reported, linked or not.
    ///
    /// [`new_dcid()`]: struct.ConnectionIdentifiers.html#method.new_dcid
    // Keep in sync with `new_dcid()`, in particular its delayed propagation
    // of the retire-queue `IdLimit` error.
    pub fn mp_new_dcid(
        &mut self, path_id: u64, cid: ConnectionId<'static>, seq: u64,
        reset_token: u128, retire_prior_to: u64,
        retired: &mut Vec<(u64, u64, Option<usize>)>,
    ) -> Result<()> {
        if path_id == 0 {
            let mut retired_path_ids = SmallVec::new();
            let res = self.new_dcid(
                cid,
                seq,
                reset_token,
                retire_prior_to,
                &mut retired_path_ids,
            );
            // The legacy call may have retired entries even on error.
            retired.extend(
                retired_path_ids
                    .iter()
                    .map(|(seq, pid)| (0, *seq, Some(*pid))),
            );
            return res;
        }

        if self.zero_length_dcid {
            return Err(Error::InvalidState);
        }

        // The active connection ID limit applies per path.
        let dcid_limit = self.dcids.capacity;
        self.mp_ensure_pool(path_id);
        let pool = self
            .mp_pools
            .get_mut(&path_id)
            .expect("pool exists after mp_ensure_pool");
        pool.dcids.resize(dcid_limit);

        // If an endpoint receives a PATH_NEW_CONNECTION_ID frame that
        // repeats a previously issued connection ID for the same path with a
        // different Stateless Reset Token field value or a different
        // Sequence Number field value, or if a sequence number is used for
        // different connection IDs on the same path, the endpoint MAY treat
        // that receipt as a connection error of type PROTOCOL_VIOLATION.
        if let Some(e) = pool.dcids.iter().find(|e| e.cid == cid || e.seq == seq)
        {
            if e.cid != cid || e.seq != seq || e.reset_token != Some(reset_token)
            {
                return Err(Error::InvalidFrame);
            }
            // The identifier is already there, nothing to do.
            return Ok(());
        }

        // The value in the Retire Prior To field MUST be less than or equal
        // to the value in the Sequence Number field.
        if retire_prior_to > seq {
            return Err(Error::InvalidFrame);
        }

        // An endpoint that receives a sequence number smaller than the
        // Retire Prior To field of a previously received frame for the same
        // path MUST send a corresponding PATH_RETIRE_CONNECTION_ID frame,
        // unless it has already done so for that sequence number.
        if seq < pool.largest_peer_retire_prior_to {
            self.mp_retire_dcid_seqs.insert((path_id, seq))?;
            return Ok(());
        }

        if seq > pool.largest_destination_seq {
            pool.largest_destination_seq = seq;
        }

        let new_entry = ConnectionIdEntry {
            cid,
            seq,
            reset_token: Some(reset_token),
            path_id: None,
        };

        let mut retired_dcid_queue_err = None;

        // A receiver MUST ignore any Retire Prior To fields that do not
        // increase the largest received Retire Prior To value for that path.
        if retire_prior_to > pool.largest_peer_retire_prior_to {
            // The inserted entry MUST have a sequence higher or equal to the
            // ones being retired.
            if new_entry.seq < retire_prior_to {
                return Err(Error::OutOfIdentifiers);
            }

            // To avoid exceeding the capacity of the inner `VecDeque`, we
            // first remove the elements and then insert the new one.
            let index = pool
                .dcids
                .inner
                .partition_point(|e| e.seq < retire_prior_to);

            for e in pool.dcids.inner.drain(..index) {
                retired.push((path_id, e.seq, e.path_id));

                if let Err(e) = self.mp_retire_dcid_seqs.insert((path_id, e.seq))
                {
                    // Delay propagating the error as we need to try to
                    // insert the new DCID first.
                    retired_dcid_queue_err = Some(e);
                    break;
                }
            }

            pool.largest_peer_retire_prior_to = retire_prior_to;
        }

        // Note that if no element has been retired and the `VecDeque`
        // reaches its capacity limit, this will raise an `IdLimit`.
        pool.dcids.insert(new_entry)?;

        // Propagate the error triggered when inserting a retired DCID seq to
        // the queue.
        if let Some(e) = retired_dcid_queue_err {
            return Err(e);
        }

        Ok(())
    }

    /// Gets the lowest Destination Connection ID sequence number of the
    /// provided path ID that is not associated to a (4-tuple) path, if any.
    ///
    /// Path ID 0 delegates to [`lowest_available_dcid_seq()`].
    ///
    /// [`lowest_available_dcid_seq()`]: struct.ConnectionIdentifiers.html#method.lowest_available_dcid_seq
    pub fn mp_lowest_available_dcid_seq(&self, path_id: u64) -> Option<u64> {
        if path_id == 0 {
            return self.lowest_available_dcid_seq();
        }

        self.mp_pools
            .get(&path_id)?
            .dcids
            .iter()
            .filter_map(|e| {
                if e.path_id.is_none() {
                    Some(e.seq)
                } else {
                    None
                }
            })
            .min()
    }

    /// Returns the number of Destination Connection IDs of the provided
    /// path ID that have not been assigned to a (4-tuple) path yet.
    ///
    /// Path ID 0 delegates to [`available_dcids()`].
    ///
    /// [`available_dcids()`]: struct.ConnectionIdentifiers.html#method.available_dcids
    pub fn mp_available_dcids(&self, path_id: u64) -> usize {
        if path_id == 0 {
            return self.available_dcids();
        }

        self.mp_pools
            .get(&path_id)
            .map(|p| p.dcids.iter().filter(|e| e.path_id.is_none()).count())
            .unwrap_or(0)
    }

    /// Gets the destination Connection ID of the provided path ID associated
    /// with the provided sequence number. Path ID 0 delegates to
    /// [`get_dcid()`].
    ///
    /// [`get_dcid()`]: struct.ConnectionIdentifiers.html#method.get_dcid
    pub fn mp_get_dcid(
        &self, path_id: u64, seq_num: u64,
    ) -> Result<&ConnectionIdEntry> {
        if path_id == 0 {
            return self.get_dcid(seq_num);
        }

        self.mp_pools
            .get(&path_id)
            .and_then(|p| p.dcids.get(seq_num))
            .ok_or(Error::InvalidState)
    }

    /// Gets the source Connection ID of the provided path ID associated with
    /// the provided sequence number. Path ID 0 delegates to [`get_scid()`].
    ///
    /// [`get_scid()`]: struct.ConnectionIdentifiers.html#method.get_scid
    pub fn mp_get_scid(
        &self, path_id: u64, seq_num: u64,
    ) -> Result<&ConnectionIdEntry> {
        if path_id == 0 {
            return self.get_scid(seq_num);
        }

        self.mp_pools
            .get(&path_id)
            .and_then(|p| p.scids.get(seq_num))
            .ok_or(Error::InvalidState)
    }

    /// Updates the Destination Connection ID entry of the provided path ID
    /// with the provided sequence number to indicate that it is now linked
    /// to the provided (4-tuple) path ID. Path ID 0 delegates to
    /// [`link_dcid_to_path_id()`].
    ///
    /// [`link_dcid_to_path_id()`]: struct.ConnectionIdentifiers.html#method.link_dcid_to_path_id
    pub fn mp_link_dcid_to_path_id(
        &mut self, path_id: u64, dcid_seq: u64, four_tuple_path_id: usize,
    ) -> Result<()> {
        if path_id == 0 {
            return self.link_dcid_to_path_id(dcid_seq, four_tuple_path_id);
        }

        let e = self
            .mp_pools
            .get_mut(&path_id)
            .and_then(|p| p.dcids.get_mut(dcid_seq))
            .ok_or(Error::InvalidState)?;
        e.path_id = Some(four_tuple_path_id);
        Ok(())
    }

    /// Retires the Source Connection ID of the provided path ID having the
    /// provided sequence number, mirroring [`retire_scid()`] per path.
    ///
    /// In case the retired Connection ID is the same as the one used by the
    /// packet requesting the retiring, or if the retired sequence number is
    /// greater than any previously advertised sequence numbers on that path,
    /// it returns an [`InvalidState`].
    ///
    /// Returns the retired Connection ID, if any, so that the caller can
    /// tell whether an actual retirement happened (and of which CID). Note
    /// that this differs from [`retire_scid()`], which returns the (4-tuple)
    /// slab path that was using the CID: per-path SCID pools are not linked
    /// to 4-tuple paths yet, so there is no slab path to unlink here. Once
    /// path management links pools to paths (Task 2.x), this should be
    /// aligned with [`retire_scid()`]'s return contract. The application is
    /// notified of the retirement through the retired SCIDs queue (see
    /// [`pop_retired_scid()`]) in all cases, and can check
    /// [`mp_scids_left()`] to decide whether to supply a replacement.
    ///
    /// Path ID 0 delegates to [`retire_scid()`].
    ///
    /// [`retire_scid()`]: struct.ConnectionIdentifiers.html#method.retire_scid
    /// [`pop_retired_scid()`]: struct.ConnectionIdentifiers.html#method.pop_retired_scid
    /// [`mp_scids_left()`]: struct.ConnectionIdentifiers.html#method.mp_scids_left
    /// [`InvalidState`]: enum.Error.html#InvalidState
    pub fn mp_retire_scid(
        &mut self, path_id: u64, seq: u64, pkt_dcid: &ConnectionId,
    ) -> Result<Option<ConnectionId<'static>>> {
        if path_id == 0 {
            let cid = self.scids.get(seq).map(|e| e.cid.clone());
            self.retire_scid(seq, pkt_dcid)?;
            return Ok(cid);
        }

        let pool = self.mp_pools.get_mut(&path_id).ok_or(Error::InvalidState)?;

        if seq >= pool.next_scid_seq {
            return Err(Error::InvalidState);
        }

        // Use `remove_allow_empty` here: per-path SCID pools may legally
        // drain to zero when the peer retires our only SCID for that path
        // (draft-ietf-quic-multipath-21 §4.5). The non-empty invariant
        // enforced by `remove` is only correct for the legacy CID space (path
        // ID 0), where the carrying packet's DCID always remains.
        let cid = if let Some(e) = pool.scids.remove_allow_empty(seq) {
            if e.cid == *pkt_dcid {
                return Err(Error::InvalidState);
            }

            // Notifies the application.
            self.retired_scids.push_back(e.cid.clone());

            // Retiring this SCID may increase the path's retire prior to.
            // If the pool is now empty there is no active CID to anchor the
            // retire_prior_to value to, so we leave it unchanged: when the
            // application supplies a replacement SCID the value will be
            // recomputed on the next retirement.
            if let Some(lowest_scid_seq) = pool
                .scids
                .iter()
                .filter_map(|e| {
                    if e.seq >= pool.retire_prior_to {
                        Some(e.seq)
                    } else {
                        None
                    }
                })
                .min()
            {
                pool.retire_prior_to = lowest_scid_seq;
            }

            Some(e.cid)
        } else {
            None
        };

        Ok(cid)
    }

    /// Retires the Destination Connection ID of the provided path ID having
    /// the provided sequence number, mirroring [`retire_dcid()`] per path.
    ///
    /// If the caller tries to retire the last destination Connection ID of
    /// the path, this method triggers an [`OutOfIdentifiers`].
    ///
    /// If the caller tries to retire a non-existing Destination Connection
    /// ID sequence number, this method returns an [`InvalidState`].
    ///
    /// Returns the (4-tuple) path ID that was associated to the retired CID,
    /// if any. Path ID 0 delegates to [`retire_dcid()`].
    ///
    /// [`retire_dcid()`]: struct.ConnectionIdentifiers.html#method.retire_dcid
    /// [`OutOfIdentifiers`]: enum.Error.html#OutOfIdentifiers
    /// [`InvalidState`]: enum.Error.html#InvalidState
    pub fn mp_retire_dcid(
        &mut self, path_id: u64, seq: u64,
    ) -> Result<Option<usize>> {
        if path_id == 0 {
            return self.retire_dcid(seq);
        }

        if self.zero_length_dcid {
            return Err(Error::InvalidState);
        }

        let pool = self.mp_pools.get_mut(&path_id).ok_or(Error::InvalidState)?;

        let e = pool.dcids.remove(seq)?.ok_or(Error::InvalidState)?;

        self.mp_retire_dcid_seqs.insert((path_id, seq))?;

        Ok(e.path_id)
    }

    /// Treats all the destination Connection IDs the peer issued for the
    /// provided path ID as immediately retired, without queueing
    /// PATH_RETIRE_CONNECTION_ID frames: when a PATH_ABANDON frame is sent
    /// or received for a path, retirement of its connection IDs is
    /// implicit and no explicit retirement frames are exchanged
    /// (draft-ietf-quic-multipath-21 §3.4). Any retirement frames already
    /// queued for that path are dropped as well.
    ///
    /// Our own source Connection IDs for the path are intentionally *not*
    /// touched: knowledge of the connection IDs issued to the peer is
    /// retained until the retention window expires (§3.4.2), see
    /// [`mp_remove_path_pools()`].
    ///
    /// Path ID 0 draws from the legacy DCID pool, which is shared with
    /// pre-multipath machinery that assumes it is never empty (e.g.
    /// fallback Destination Connection ID lookups); for that reason the
    /// legacy pool is left in place and only its queued retirements are
    /// dropped. Sending on an abandoned path 0 is prevented by the path
    /// state (`mp_closing`) instead.
    ///
    /// [`mp_remove_path_pools()`]: struct.ConnectionIdentifiers.html#method.mp_remove_path_pools
    #[cfg(feature = "multipath")]
    pub fn mp_retire_dcid_pool(&mut self, path_id: u64) {
        if path_id == 0 {
            self.retire_dcid_seqs.inner.clear();
            return;
        }

        if let Some(pool) = self.mp_pools.get_mut(&path_id) {
            pool.dcids.clear_allow_empty();
        }

        self.mp_retire_dcid_seqs
            .inner
            .retain(|&(pid, _)| pid != path_id);
    }

    /// Removes the whole per-path Connection ID pool of the provided path
    /// ID, both directions, together with any pending advertisements for
    /// it. Called when all state associated with an abandoned path is
    /// finally deleted, at the end of the post-abandon retention window
    /// (draft-ietf-quic-multipath-21 §3.4).
    ///
    /// Path ID 0 shares the legacy pools, which are left in place (see
    /// [`mp_retire_dcid_pool()`]).
    ///
    /// [`mp_retire_dcid_pool()`]: struct.ConnectionIdentifiers.html#method.mp_retire_dcid_pool
    #[cfg(feature = "multipath")]
    pub fn mp_remove_path_pools(&mut self, path_id: u64) {
        if path_id == 0 {
            return;
        }

        self.mp_pools.remove(&path_id);

        self.mp_advertise_new_scid_seqs
            .retain(|&(pid, _)| pid != path_id);
        self.mp_retire_dcid_seqs
            .inner
            .retain(|&(pid, _)| pid != path_id);
    }

    /// Returns the number of source Connection IDs that can still be issued
    /// to the peer on the provided path ID without exceeding the per-path
    /// active connection ID limit it advertised (the same limit
    /// [`mp_new_scid()`] enforces).
    ///
    /// A non-zero value after a PATH_RETIRE_CONNECTION_ID means the
    /// application should supply replacement Connection IDs for that path
    /// (RFC 9000, Section 5.1.2, applied per path); the transport never
    /// mints Connection IDs on its own, as the application must know every
    /// source CID for packet routing.
    ///
    /// Path ID 0 reports the legacy space's accounting.
    ///
    /// [`mp_new_scid()`]: struct.ConnectionIdentifiers.html#method.mp_new_scid
    pub fn mp_scids_left(&self, path_id: u64) -> usize {
        let active = if path_id == 0 {
            self.scids.len()
        } else {
            self.mp_pools
                .get(&path_id)
                .map(|p| p.scids.len())
                .unwrap_or(0)
        };

        self.source_conn_id_limit.saturating_sub(active)
    }

    /// Returns the next source CID sequence number we would issue for the
    /// provided path ID. Path ID 0 reports the legacy space's next sequence
    /// number.
    pub fn mp_next_scid_seq(&self, path_id: u64) -> u64 {
        if path_id == 0 {
            return self.next_scid_seq;
        }

        self.mp_pools
            .get(&path_id)
            .map(|p| p.next_scid_seq)
            .unwrap_or(0)
    }

    /// Finds the multipath path ID owning one of our source Connection IDs
    /// having the provided value, if any. SCIDs from the legacy pool belong
    /// to path ID 0.
    pub fn mp_find_scid_path_id(&self, cid: &ConnectionId) -> Option<u64> {
        self.mp_find_scid(cid).map(|(path_id, _)| path_id)
    }

    /// Finds one of our source Connection IDs having the provided value and
    /// returns the multipath path ID owning it along with its sequence
    /// number in that path's sequence number space, if any. SCIDs from the
    /// legacy pool belong to path ID 0 (with their legacy sequence number).
    pub fn mp_find_scid(&self, cid: &ConnectionId) -> Option<(u64, u64)> {
        if let Some(e) = self.scids.iter().find(|e| e.cid == *cid) {
            return Some((0, e.seq));
        }

        self.mp_pools.iter().find_map(|(path_id, p)| {
            p.scids
                .iter()
                .find(|e| e.cid == *cid)
                .map(|e| (*path_id, e.seq))
        })
    }

    /// Returns the sequence number of the next destination Connection ID we
    /// expect the peer to issue for the provided non-zero path ID (the
    /// "Next Sequence Number" of a PATH_CIDS_BLOCKED frame, §3.2.1).
    ///
    /// This is derived from the largest DCID sequence number seen on the
    /// path's pool: 0 when no DCID was ever received for that path ID,
    /// largest + 1 otherwise. One approximation: if the only DCID ever
    /// received had sequence number 0 and was since retired, this reports 0
    /// instead of 1; the value is informational, so this is harmless.
    pub fn mp_next_expected_dcid_seq(&self, path_id: u64) -> u64 {
        match self.mp_pools.get(&path_id) {
            None => 0,

            Some(p) =>
                if p.dcids.len() == 0 &&
                    p.largest_destination_seq == 0 &&
                    p.largest_peer_retire_prior_to == 0
                {
                    0
                } else {
                    p.largest_destination_seq + 1
                },
        }
    }

    /// Returns an iterator over the non-zero path IDs that have a
    /// connection ID pool.
    pub fn mp_pools_path_ids(&self) -> impl Iterator<Item = u64> + '_ {
        self.mp_pools.keys().copied()
    }

    /// Adds or removes the (path ID, sequence number) pair from the set of
    /// source Connection IDs that need to be advertised to the peer through
    /// PATH_NEW_CONNECTION_ID frames.
    pub fn mp_mark_advertise_new_scid(
        &mut self, path_id: u64, seq: u64, advertise: bool,
    ) {
        if advertise {
            self.mp_advertise_new_scid_seqs.push_back((path_id, seq));
        } else if let Some(index) = self
            .mp_advertise_new_scid_seqs
            .iter()
            .position(|e| *e == (path_id, seq))
        {
            self.mp_advertise_new_scid_seqs.remove(index);
        }
    }

    /// Gets a (path ID, sequence number) pair requiring advertising it to
    /// the peer through a PATH_NEW_CONNECTION_ID frame, if any.
    ///
    /// If `Some`, it always returns the same value until it has been removed
    /// using `mp_mark_advertise_new_scid`.
    pub fn mp_next_advertise_new_scid(&self) -> Option<(u64, u64)> {
        self.mp_advertise_new_scid_seqs.front().copied()
    }

    /// Returns true if there are per-path source Connection IDs to
    /// advertise.
    pub fn mp_has_new_scids(&self) -> bool {
        !self.mp_advertise_new_scid_seqs.is_empty()
    }

    /// Adds or removes the (path ID, sequence number) pair from the set of
    /// retired destination Connection IDs that need to be advertised to the
    /// peer through PATH_RETIRE_CONNECTION_ID frames.
    pub fn mp_mark_retire_dcid(
        &mut self, path_id: u64, seq: u64, retire: bool,
    ) -> Result<()> {
        if retire {
            self.mp_retire_dcid_seqs.insert((path_id, seq))?;
        } else {
            self.mp_retire_dcid_seqs.remove(&(path_id, seq));
        }

        Ok(())
    }

    /// Returns a copy of the set of (path ID, sequence number) pairs to send
    /// PATH_RETIRE_CONNECTION_ID frames for.
    ///
    /// Note that the set includes pairs at the time the copy was created. To
    /// account for newly inserted or removed pairs, a new copy needs to be
    /// created.
    pub fn mp_retire_dcid_seqs(&self) -> HashSet<(u64, u64)> {
        self.mp_retire_dcid_seqs.inner.clone()
    }

    /// Returns true if there are retired per-path destination Connection IDs
    /// to advertise.
    pub fn mp_has_retire_dcids(&self) -> bool {
        !self.mp_retire_dcid_seqs.is_empty()
    }

    /// Gets the PATH_NEW_CONNECTION_ID frame related to the source
    /// Connection ID of the provided path ID with sequence `seq_num`,
    /// mirroring [`get_new_connection_id_frame_for()`] per path.
    ///
    /// Path ID 0 reads from the legacy SCID space, as path ID 0 frames
    /// operate on the very same sequence number space as legacy
    /// NEW_CONNECTION_ID frames (draft-ietf-quic-multipath-21, Section
    /// 4.4); note that path-0 CIDs are normally advertised through legacy
    /// frames instead.
    ///
    /// [`get_new_connection_id_frame_for()`]: struct.ConnectionIdentifiers.html#method.get_new_connection_id_frame_for
    pub fn mp_get_path_new_connection_id_frame_for(
        &self, path_id: u64, seq_num: u64,
    ) -> Result<frame::Frame> {
        let (entry, retire_prior_to) = if path_id == 0 {
            (self.scids.get(seq_num), self.retire_prior_to)
        } else {
            let pool = self.mp_pools.get(&path_id).ok_or(Error::InvalidState)?;
            (pool.scids.get(seq_num), pool.retire_prior_to)
        };

        let e = entry.ok_or(Error::InvalidState)?;

        Ok(frame::Frame::PathNewConnectionId {
            path_id,
            seq_num,
            retire_prior_to,
            conn_id: e.cid.to_vec(),
            reset_token: e.reset_token.ok_or(Error::InvalidState)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::create_cid_and_reset_token;

    #[test]
    fn ids_new_scids() {
        let (scid, _) = create_cid_and_reset_token(16);
        let (dcid, _) = create_cid_and_reset_token(16);

        let mut ids = ConnectionIdentifiers::new(2, &scid, 0, None);
        ids.set_source_conn_id_limit(3);
        ids.set_initial_dcid(dcid, None, Some(0));

        assert_eq!(ids.available_dcids(), 0);
        assert_eq!(ids.available_scids(), 0);
        assert!(!ids.has_new_scids());
        assert_eq!(ids.next_advertise_new_scid_seq(), None);

        let (scid2, rt2) = create_cid_and_reset_token(16);

        assert_eq!(ids.new_scid(scid2, Some(rt2), true, None, false), Ok(1));
        assert_eq!(ids.available_dcids(), 0);
        assert_eq!(ids.available_scids(), 1);
        assert!(ids.has_new_scids());
        assert_eq!(ids.next_advertise_new_scid_seq(), Some(1));

        let (scid3, rt3) = create_cid_and_reset_token(16);

        assert_eq!(ids.new_scid(scid3, Some(rt3), true, None, false), Ok(2));
        assert_eq!(ids.available_dcids(), 0);
        assert_eq!(ids.available_scids(), 2);
        assert!(ids.has_new_scids());
        assert_eq!(ids.next_advertise_new_scid_seq(), Some(1));

        // If now we give another CID, it reports an error since it exceeds the
        // limit of active CIDs.
        let (scid4, rt4) = create_cid_and_reset_token(16);

        assert_eq!(
            ids.new_scid(scid4, Some(rt4), true, None, false),
            Err(Error::IdLimit),
        );
        assert_eq!(ids.available_dcids(), 0);
        assert_eq!(ids.available_scids(), 2);
        assert!(ids.has_new_scids());
        assert_eq!(ids.next_advertise_new_scid_seq(), Some(1));

        // Assume we sent one of them.
        ids.mark_advertise_new_scid_seq(1, false);
        assert_eq!(ids.available_dcids(), 0);
        assert_eq!(ids.available_scids(), 2);
        assert!(ids.has_new_scids());
        assert_eq!(ids.next_advertise_new_scid_seq(), Some(2));

        // Send the other.
        ids.mark_advertise_new_scid_seq(2, false);

        assert_eq!(ids.available_dcids(), 0);
        assert_eq!(ids.available_scids(), 2);
        assert!(!ids.has_new_scids());
        assert_eq!(ids.next_advertise_new_scid_seq(), None);
    }

    #[test]
    fn new_dcid_event() {
        let (scid, _) = create_cid_and_reset_token(16);
        let (dcid, _) = create_cid_and_reset_token(16);

        let mut retired_path_ids = SmallVec::new();

        let mut ids = ConnectionIdentifiers::new(2, &scid, 0, None);
        ids.set_initial_dcid(dcid, None, Some(0));

        assert_eq!(ids.available_dcids(), 0);
        assert_eq!(ids.dcids.len(), 1);

        let (dcid2, rt2) = create_cid_and_reset_token(16);

        assert_eq!(
            ids.new_dcid(dcid2, 1, rt2, 0, &mut retired_path_ids),
            Ok(()),
        );
        assert_eq!(retired_path_ids, SmallVec::from_buf([]));
        assert_eq!(ids.available_dcids(), 1);
        assert_eq!(ids.dcids.len(), 2);

        // Now we assume that the client wants to advertise more source
        // Connection IDs than the advertised limit. This is valid if it
        // requests its peer to retire enough Connection IDs to fit within the
        // limits.
        let (dcid3, rt3) = create_cid_and_reset_token(16);
        assert_eq!(
            ids.new_dcid(dcid3, 2, rt3, 1, &mut retired_path_ids),
            Ok(())
        );
        assert_eq!(retired_path_ids, SmallVec::from_buf([(0, 0)]));
        // The CID module does not handle path replacing. Fake it now.
        ids.link_dcid_to_path_id(1, 0).unwrap();
        assert_eq!(ids.available_dcids(), 1);
        assert_eq!(ids.dcids.len(), 2);
        assert!(ids.has_retire_dcids());
        assert_eq!(ids.retire_dcid_seqs().iter().next(), Some(&0));

        // Fake RETIRE_CONNECTION_ID sending.
        let _ = ids.mark_retire_dcid_seq(0, false);
        assert!(!ids.has_retire_dcids());
        assert_eq!(ids.retire_dcid_seqs().iter().next(), None);

        // Now tries to experience CID retirement. If the server tries to remove
        // non-existing DCIDs, it fails.
        assert_eq!(ids.retire_dcid(0), Err(Error::InvalidState));
        assert_eq!(ids.retire_dcid(3), Err(Error::InvalidState));
        assert!(!ids.has_retire_dcids());
        assert_eq!(ids.dcids.len(), 2);

        // Now it removes DCID with sequence 1.
        assert_eq!(ids.retire_dcid(1), Ok(Some(0)));
        // The CID module does not handle path replacing. Fake it now.
        ids.link_dcid_to_path_id(2, 0).unwrap();
        assert_eq!(ids.available_dcids(), 0);
        assert!(ids.has_retire_dcids());
        assert_eq!(ids.retire_dcid_seqs().iter().next(), Some(&1));
        assert_eq!(ids.dcids.len(), 1);

        // Fake RETIRE_CONNECTION_ID sending.
        let _ = ids.mark_retire_dcid_seq(1, false);
        assert!(!ids.has_retire_dcids());
        assert_eq!(ids.retire_dcid_seqs().iter().next(), None);

        // Trying to remove the last DCID triggers an error.
        assert_eq!(ids.retire_dcid(2), Err(Error::OutOfIdentifiers));
        assert_eq!(ids.available_dcids(), 0);
        assert!(!ids.has_retire_dcids());
        assert_eq!(ids.dcids.len(), 1);
    }

    #[test]
    fn new_dcid_reordered() {
        let (scid, _) = create_cid_and_reset_token(16);
        let (dcid, _) = create_cid_and_reset_token(16);

        let mut retired_path_ids = SmallVec::new();

        let mut ids = ConnectionIdentifiers::new(2, &scid, 0, None);
        ids.set_initial_dcid(dcid, None, Some(0));

        assert_eq!(ids.available_dcids(), 0);
        assert_eq!(ids.dcids.len(), 1);

        // Skip DCID #1 (e.g due to packet loss) and insert DCID #2.
        let (dcid, rt) = create_cid_and_reset_token(16);
        assert!(ids.new_dcid(dcid, 2, rt, 1, &mut retired_path_ids).is_ok());
        assert_eq!(ids.dcids.len(), 1);

        let (dcid, rt) = create_cid_and_reset_token(16);
        assert!(ids.new_dcid(dcid, 3, rt, 2, &mut retired_path_ids).is_ok());
        assert_eq!(ids.dcids.len(), 2);

        let (dcid, rt) = create_cid_and_reset_token(16);
        assert!(ids.new_dcid(dcid, 4, rt, 3, &mut retired_path_ids).is_ok());
        assert_eq!(ids.dcids.len(), 2);

        // Insert DCID #1 (e.g due to packet reordering).
        let (dcid, rt) = create_cid_and_reset_token(16);
        assert!(ids.new_dcid(dcid, 1, rt, 0, &mut retired_path_ids).is_ok());
        assert_eq!(ids.dcids.len(), 2);

        // Try inserting DCID #1 again (e.g. due to retransmission).
        let (dcid, rt) = create_cid_and_reset_token(16);
        assert!(ids.new_dcid(dcid, 1, rt, 0, &mut retired_path_ids).is_ok());
        assert_eq!(ids.dcids.len(), 2);
    }

    #[test]
    fn new_dcid_partial_retire_prior_to() {
        let (scid, _) = create_cid_and_reset_token(16);
        let (dcid, _) = create_cid_and_reset_token(16);

        let mut retired_path_ids = SmallVec::new();

        let mut ids = ConnectionIdentifiers::new(5, &scid, 0, None);
        ids.set_initial_dcid(dcid, None, Some(0));

        assert_eq!(ids.available_dcids(), 0);
        assert_eq!(ids.dcids.len(), 1);

        let (dcid, rt) = create_cid_and_reset_token(16);
        assert!(ids.new_dcid(dcid, 1, rt, 0, &mut retired_path_ids).is_ok());
        assert_eq!(ids.dcids.len(), 2);

        let (dcid, rt) = create_cid_and_reset_token(16);
        assert!(ids.new_dcid(dcid, 2, rt, 0, &mut retired_path_ids).is_ok());
        assert_eq!(ids.dcids.len(), 3);

        let (dcid, rt) = create_cid_and_reset_token(16);
        assert!(ids.new_dcid(dcid, 3, rt, 0, &mut retired_path_ids).is_ok());
        assert_eq!(ids.dcids.len(), 4);

        let (dcid, rt) = create_cid_and_reset_token(16);
        assert!(ids.new_dcid(dcid, 4, rt, 0, &mut retired_path_ids).is_ok());
        assert_eq!(ids.dcids.len(), 5);

        // Retire a DCID from the middle of the list
        assert!(ids.retire_dcid(3).is_ok());

        // Retire prior to DCID that was just retired.
        //
        // This is largely to test that the `partition_point()` call above
        // returns a meaningful value even if the actual sequence that is
        // searched isn't present in the list.
        let (dcid, rt) = create_cid_and_reset_token(16);
        assert!(ids.new_dcid(dcid, 5, rt, 3, &mut retired_path_ids).is_ok());
        assert_eq!(ids.dcids.len(), 2);
    }

    #[test]
    fn retire_scids() {
        let (scid, _) = create_cid_and_reset_token(16);
        let (dcid, _) = create_cid_and_reset_token(16);

        let mut ids = ConnectionIdentifiers::new(3, &scid, 0, None);
        ids.set_initial_dcid(dcid, None, Some(0));
        ids.set_source_conn_id_limit(3);

        let (scid2, rt2) = create_cid_and_reset_token(16);
        let (scid3, rt3) = create_cid_and_reset_token(16);

        assert_eq!(
            ids.new_scid(scid2.clone(), Some(rt2), true, None, false),
            Ok(1),
        );
        assert_eq!(ids.scids.len(), 2);
        assert_eq!(
            ids.new_scid(scid3.clone(), Some(rt3), true, None, false),
            Ok(2),
        );
        assert_eq!(ids.scids.len(), 3);

        assert_eq!(ids.pop_retired_scid(), None);

        assert_eq!(ids.retire_scid(0, &scid2), Ok(Some(0)));

        assert_eq!(ids.pop_retired_scid(), Some(scid));
        assert_eq!(ids.pop_retired_scid(), None);

        assert_eq!(ids.retire_scid(1, &scid3), Ok(None));

        assert_eq!(ids.pop_retired_scid(), Some(scid2));
        assert_eq!(ids.pop_retired_scid(), None);
    }

    #[cfg(feature = "multipath")]
    #[test]
    fn mp_scid_per_path_seq_spaces() {
        let (scid, _) = create_cid_and_reset_token(16);
        let (dcid, _) = create_cid_and_reset_token(16);

        let mut ids = ConnectionIdentifiers::new(2, &scid, 0, None);
        ids.set_source_conn_id_limit(3);
        ids.set_initial_dcid(dcid, None, Some(0));

        // Path 1 and path 2 have independent, 0-based sequence spaces.
        let (c10, rt10) = create_cid_and_reset_token(16);
        let (c11, rt11) = create_cid_and_reset_token(16);
        let (c20, rt20) = create_cid_and_reset_token(16);

        assert_eq!(ids.mp_new_scid(1, c10.clone(), rt10), Ok(0));
        assert_eq!(ids.mp_new_scid(1, c11.clone(), rt11), Ok(1));
        assert_eq!(ids.mp_new_scid(2, c20.clone(), rt20), Ok(0));

        assert_eq!(ids.mp_next_scid_seq(1), 2);
        assert_eq!(ids.mp_next_scid_seq(2), 1);
        assert_eq!(ids.mp_next_scid_seq(0), 1);

        assert_eq!(ids.mp_get_scid(1, 0).unwrap().cid, c10);
        assert_eq!(ids.mp_get_scid(1, 1).unwrap().cid, c11);
        assert_eq!(ids.mp_get_scid(2, 0).unwrap().cid, c20);
        assert_eq!(ids.mp_get_scid(2, 1).err(), Some(Error::InvalidState));

        // Pools exist for paths 1 and 2 only; path 0 uses the legacy space.
        let pids: Vec<u64> = ids.mp_pools_path_ids().collect();
        assert_eq!(pids, vec![1, 2]);
    }

    #[cfg(feature = "multipath")]
    #[test]
    fn mp_scid_path_zero_delegation() {
        let (scid, _) = create_cid_and_reset_token(16);
        let (dcid, _) = create_cid_and_reset_token(16);

        let mut ids = ConnectionIdentifiers::new(2, &scid, 0, None);
        ids.set_source_conn_id_limit(3);
        ids.set_initial_dcid(dcid, None, Some(0));

        // Issue via the legacy API, observe through the multipath one.
        let (scid2, rt2) = create_cid_and_reset_token(16);
        assert_eq!(
            ids.new_scid(scid2.clone(), Some(rt2), true, None, false),
            Ok(1)
        );
        assert_eq!(ids.mp_get_scid(0, 1).unwrap().cid, scid2);

        // Issue via the multipath API for path 0, observe through legacy.
        let (scid3, rt3) = create_cid_and_reset_token(16);
        assert_eq!(ids.mp_new_scid(0, scid3.clone(), rt3), Ok(2));
        assert_eq!(ids.get_scid(2).unwrap().cid, scid3);
        assert_eq!(ids.mp_next_scid_seq(0), 3);
        assert_eq!(ids.next_scid_seq, 3);

        // Path-0 issuance goes through the legacy advertise queue, not the
        // multipath one.
        assert_eq!(ids.next_advertise_new_scid_seq(), Some(1));
        assert_eq!(ids.mp_next_advertise_new_scid(), None);

        // Path 0 never creates a pool.
        assert_eq!(ids.mp_pools_path_ids().count(), 0);
    }

    #[cfg(feature = "multipath")]
    #[test]
    fn mp_scid_global_duplicate_rejected() {
        let (scid, _) = create_cid_and_reset_token(16);
        let (dcid, _) = create_cid_and_reset_token(16);

        let mut ids = ConnectionIdentifiers::new(2, &scid, 0, None);
        ids.set_source_conn_id_limit(3);
        ids.set_initial_dcid(dcid.clone(), None, Some(0));

        // Reusing the initial (path 0) SCID bytes on another path is invalid.
        assert_eq!(
            ids.mp_new_scid(1, scid.clone(), 42),
            Err(Error::InvalidState)
        );

        // Reusing the initial DCID bytes is also invalid.
        assert_eq!(
            ids.mp_new_scid(1, dcid.clone(), 43),
            Err(Error::InvalidState)
        );

        // Same bytes on path 1 then path 2.
        let (ca, rta) = create_cid_and_reset_token(16);
        assert_eq!(ids.mp_new_scid(1, ca.clone(), rta), Ok(0));
        assert_eq!(
            ids.mp_new_scid(2, ca.clone(), rta),
            Err(Error::InvalidState)
        );
        // Even on the same path.
        assert_eq!(
            ids.mp_new_scid(1, ca.clone(), rta),
            Err(Error::InvalidState)
        );

        // Bytes already used by a per-path DCID are rejected too.
        let (dx, rtx) = create_cid_and_reset_token(16);
        let mut retired = Vec::new();
        assert_eq!(
            ids.mp_new_dcid(1, dx.clone(), 0, rtx, 0, &mut retired),
            Ok(())
        );
        assert_eq!(ids.mp_new_scid(2, dx, 44), Err(Error::InvalidState));
    }

    #[cfg(feature = "multipath")]
    #[test]
    fn mp_scid_per_path_limit() {
        let (scid, _) = create_cid_and_reset_token(16);
        let (dcid, _) = create_cid_and_reset_token(16);

        let mut ids = ConnectionIdentifiers::new(2, &scid, 0, None);
        ids.set_source_conn_id_limit(3);
        ids.set_initial_dcid(dcid, None, Some(0));

        // The active CID limit applies per path, not summed across paths.
        for path_id in 1..=2 {
            for seq in 0..3 {
                let (c, rt) = create_cid_and_reset_token(16);
                assert_eq!(ids.mp_new_scid(path_id, c, rt), Ok(seq));
            }
            let (c, rt) = create_cid_and_reset_token(16);
            assert_eq!(ids.mp_new_scid(path_id, c, rt), Err(Error::IdLimit));
        }
    }

    #[cfg(feature = "multipath")]
    #[test]
    fn mp_new_dcid_per_path() {
        let (scid, _) = create_cid_and_reset_token(16);
        let (dcid, _) = create_cid_and_reset_token(16);

        let mut retired = Vec::new();

        let mut ids = ConnectionIdentifiers::new(2, &scid, 0, None);
        ids.set_initial_dcid(dcid, None, Some(0));

        let (d0, rt0) = create_cid_and_reset_token(16);
        let (d1, rt1) = create_cid_and_reset_token(16);

        assert_eq!(
            ids.mp_new_dcid(1, d0.clone(), 0, rt0, 0, &mut retired),
            Ok(())
        );
        assert!(retired.is_empty());
        assert_eq!(ids.mp_get_dcid(1, 0).unwrap().cid, d0);

        assert_eq!(
            ids.mp_new_dcid(1, d1.clone(), 1, rt1, 0, &mut retired),
            Ok(())
        );
        assert_eq!(ids.mp_pools[&1].dcids.len(), 2);

        // Exceeding the per-path destination CID limit (2) errors.
        let (d2, rt2) = create_cid_and_reset_token(16);
        assert_eq!(
            ids.mp_new_dcid(1, d2, 2, rt2, 0, &mut retired),
            Err(Error::IdLimit)
        );

        // Retire Prior To drains entries below it on that path only.
        let (d3, rt3) = create_cid_and_reset_token(16);
        assert_eq!(ids.mp_new_dcid(1, d3, 3, rt3, 1, &mut retired), Ok(()));
        assert_eq!(retired, vec![(1, 0, None)]);
        assert_eq!(ids.mp_pools[&1].dcids.len(), 2);
        assert!(ids.mp_has_retire_dcids());
        assert!(ids.mp_retire_dcid_seqs().contains(&(1, 0)));

        // Path 2 has its own independent space and limit.
        retired.clear();
        let (e0, ert0) = create_cid_and_reset_token(16);
        let (e1, ert1) = create_cid_and_reset_token(16);
        assert_eq!(ids.mp_new_dcid(2, e0, 0, ert0, 0, &mut retired), Ok(()));
        assert_eq!(ids.mp_new_dcid(2, e1, 1, ert1, 0, &mut retired), Ok(()));
        assert!(retired.is_empty());
        assert_eq!(ids.mp_pools[&2].dcids.len(), 2);

        // Path 0 delegates to the legacy pool.
        let (f1, frt1) = create_cid_and_reset_token(16);
        assert_eq!(
            ids.mp_new_dcid(0, f1.clone(), 1, frt1, 0, &mut retired),
            Ok(())
        );
        assert_eq!(ids.get_dcid(1).unwrap().cid, f1);
        assert_eq!(ids.dcids.len(), 2);

        // Path 0 retirement is reported with path_id 0, carrying the slab
        // path link of the initial DCID, and goes through the legacy retire
        // queue.
        let (f2, frt2) = create_cid_and_reset_token(16);
        assert_eq!(ids.mp_new_dcid(0, f2, 2, frt2, 1, &mut retired), Ok(()));
        assert_eq!(retired, vec![(0, 0, Some(0))]);
        assert!(ids.has_retire_dcids());
        assert!(ids.retire_dcid_seqs().contains(&0));
    }

    #[cfg(feature = "multipath")]
    #[test]
    fn mp_new_dcid_mismatch_and_invalid_rpt() {
        let (scid, _) = create_cid_and_reset_token(16);
        let (dcid, _) = create_cid_and_reset_token(16);

        let mut retired = Vec::new();

        let mut ids = ConnectionIdentifiers::new(2, &scid, 0, None);
        ids.set_initial_dcid(dcid, None, Some(0));

        let (d0, rt0) = create_cid_and_reset_token(16);
        assert_eq!(
            ids.mp_new_dcid(1, d0.clone(), 0, rt0, 0, &mut retired),
            Ok(())
        );

        // Exact duplicate is tolerated.
        assert_eq!(
            ids.mp_new_dcid(1, d0.clone(), 0, rt0, 0, &mut retired),
            Ok(())
        );
        assert_eq!(ids.mp_pools[&1].dcids.len(), 1);

        // Same CID with a different sequence number.
        assert_eq!(
            ids.mp_new_dcid(1, d0.clone(), 1, rt0, 0, &mut retired),
            Err(Error::InvalidFrame)
        );

        // Same sequence number with a different CID.
        let (dx, rtx) = create_cid_and_reset_token(16);
        assert_eq!(
            ids.mp_new_dcid(1, dx.clone(), 0, rtx, 0, &mut retired),
            Err(Error::InvalidFrame)
        );

        // Same CID and seq with a different reset token.
        assert_eq!(
            ids.mp_new_dcid(
                1,
                d0.clone(),
                0,
                rt0.wrapping_add(1),
                0,
                &mut retired
            ),
            Err(Error::InvalidFrame)
        );

        // Retire Prior To greater than the sequence number.
        let (dy, rty) = create_cid_and_reset_token(16);
        assert_eq!(
            ids.mp_new_dcid(1, dy, 9, rty, 10, &mut retired),
            Err(Error::InvalidFrame)
        );
    }

    #[cfg(feature = "multipath")]
    #[test]
    fn mp_new_dcid_reordered_per_path() {
        let (scid, _) = create_cid_and_reset_token(16);
        let (dcid, _) = create_cid_and_reset_token(16);

        let mut retired = Vec::new();

        let mut ids = ConnectionIdentifiers::new(2, &scid, 0, None);
        ids.set_initial_dcid(dcid, None, Some(0));

        // Skip DCID #1 (e.g due to packet loss) and insert DCID #2.
        let (d, rt) = create_cid_and_reset_token(16);
        assert!(ids.mp_new_dcid(1, d, 2, rt, 1, &mut retired).is_ok());
        assert_eq!(ids.mp_pools[&1].dcids.len(), 1);

        let (d, rt) = create_cid_and_reset_token(16);
        assert!(ids.mp_new_dcid(1, d, 3, rt, 2, &mut retired).is_ok());
        assert_eq!(ids.mp_pools[&1].dcids.len(), 2);

        let (d, rt) = create_cid_and_reset_token(16);
        assert!(ids.mp_new_dcid(1, d, 4, rt, 3, &mut retired).is_ok());
        assert_eq!(ids.mp_pools[&1].dcids.len(), 2);

        // Insert DCID #1 (e.g due to packet reordering): it is below the
        // path's Retire Prior To, so it is immediately queued for retirement.
        let (d, rt) = create_cid_and_reset_token(16);
        assert!(ids.mp_new_dcid(1, d, 1, rt, 0, &mut retired).is_ok());
        assert_eq!(ids.mp_pools[&1].dcids.len(), 2);
        assert!(ids.mp_retire_dcid_seqs().contains(&(1, 1)));

        // Try inserting DCID #1 again (e.g. due to retransmission).
        let (d, rt) = create_cid_and_reset_token(16);
        assert!(ids.mp_new_dcid(1, d, 1, rt, 0, &mut retired).is_ok());
        assert_eq!(ids.mp_pools[&1].dcids.len(), 2);
    }

    #[cfg(feature = "multipath")]
    #[test]
    fn mp_new_dcid_partial_retire_prior_to_per_path() {
        let (scid, _) = create_cid_and_reset_token(16);
        let (dcid, _) = create_cid_and_reset_token(16);

        let mut retired = Vec::new();

        let mut ids = ConnectionIdentifiers::new(5, &scid, 0, None);
        ids.set_initial_dcid(dcid, None, Some(0));

        for seq in 0..5 {
            let (d, rt) = create_cid_and_reset_token(16);
            assert!(ids.mp_new_dcid(1, d, seq, rt, 0, &mut retired).is_ok());
        }
        assert_eq!(ids.mp_pools[&1].dcids.len(), 5);

        // Retire a DCID from the middle of the list.
        assert!(ids.mp_retire_dcid(1, 3).is_ok());

        // Retire prior to the DCID that was just retired; the drain point
        // must be meaningful even if the sequence is absent from the list.
        let (d, rt) = create_cid_and_reset_token(16);
        assert!(ids.mp_new_dcid(1, d, 5, rt, 3, &mut retired).is_ok());
        assert_eq!(ids.mp_pools[&1].dcids.len(), 2);
        assert_eq!(retired, vec![(1, 0, None), (1, 1, None), (1, 2, None)]);
    }

    #[cfg(feature = "multipath")]
    #[test]
    fn mp_lowest_available_dcid_seq_per_path() {
        let (scid, _) = create_cid_and_reset_token(16);
        let (dcid, _) = create_cid_and_reset_token(16);

        let mut retired = Vec::new();

        let mut ids = ConnectionIdentifiers::new(2, &scid, 0, None);
        ids.set_initial_dcid(dcid, None, Some(0));

        // No pool yet.
        assert_eq!(ids.mp_lowest_available_dcid_seq(1), None);

        let (d0, rt0) = create_cid_and_reset_token(16);
        let (d1, rt1) = create_cid_and_reset_token(16);
        assert_eq!(ids.mp_new_dcid(1, d0, 0, rt0, 0, &mut retired), Ok(()));
        assert_eq!(ids.mp_new_dcid(1, d1, 1, rt1, 0, &mut retired), Ok(()));

        assert_eq!(ids.mp_lowest_available_dcid_seq(1), Some(0));

        // Linking a DCID to a live 4-tuple (slab path) makes it unavailable.
        assert_eq!(ids.mp_link_dcid_to_path_id(1, 0, 4), Ok(()));
        assert_eq!(ids.mp_lowest_available_dcid_seq(1), Some(1));

        assert_eq!(ids.mp_link_dcid_to_path_id(1, 1, 5), Ok(()));
        assert_eq!(ids.mp_lowest_available_dcid_seq(1), None);

        // Path 0 delegates to the legacy accessor: the initial DCID (seq 0)
        // is linked to the initial 4-tuple path, so nothing is available.
        assert_eq!(ids.mp_lowest_available_dcid_seq(0), None);

        // A fresh, unlinked legacy DCID becomes path 0's lowest available.
        let mut retired_path_ids = SmallVec::new();
        let (f1, frt1) = create_cid_and_reset_token(16);
        assert_eq!(ids.new_dcid(f1, 1, frt1, 0, &mut retired_path_ids), Ok(()));
        assert_eq!(ids.mp_lowest_available_dcid_seq(0), Some(1));
    }

    #[cfg(feature = "multipath")]
    #[test]
    fn mp_retire_dcid_round_trip() {
        let (scid, _) = create_cid_and_reset_token(16);
        let (dcid, _) = create_cid_and_reset_token(16);

        let mut retired = Vec::new();

        let mut ids = ConnectionIdentifiers::new(2, &scid, 0, None);
        ids.set_initial_dcid(dcid, None, Some(0));

        let (d0, rt0) = create_cid_and_reset_token(16);
        let (d1, rt1) = create_cid_and_reset_token(16);
        assert_eq!(ids.mp_new_dcid(1, d0, 0, rt0, 0, &mut retired), Ok(()));
        assert_eq!(ids.mp_new_dcid(1, d1, 1, rt1, 0, &mut retired), Ok(()));

        // Retiring a non-existing sequence number fails.
        assert_eq!(ids.mp_retire_dcid(1, 7), Err(Error::InvalidState));

        // Retiring an existing one removes it and queues the retirement.
        assert_eq!(ids.mp_retire_dcid(1, 0), Ok(None));
        assert_eq!(ids.mp_pools[&1].dcids.len(), 1);
        assert!(ids.mp_has_retire_dcids());
        assert!(ids.mp_retire_dcid_seqs().contains(&(1, 0)));

        // Fake RETIRE frame emission.
        assert_eq!(ids.mp_mark_retire_dcid(1, 0, false), Ok(()));
        assert!(!ids.mp_has_retire_dcids());

        // Retiring the last DCID of the path fails.
        assert_eq!(ids.mp_retire_dcid(1, 1), Err(Error::OutOfIdentifiers));
    }

    #[cfg(feature = "multipath")]
    #[test]
    fn mp_retire_scid_round_trip() {
        let (scid, _) = create_cid_and_reset_token(16);
        let (dcid, _) = create_cid_and_reset_token(16);

        let mut ids = ConnectionIdentifiers::new(2, &scid, 0, None);
        ids.set_source_conn_id_limit(3);
        ids.set_initial_dcid(dcid, None, Some(0));

        let (c0, rt0) = create_cid_and_reset_token(16);
        let (c1, rt1) = create_cid_and_reset_token(16);
        let (c2, rt2) = create_cid_and_reset_token(16);
        assert_eq!(ids.mp_new_scid(1, c0.clone(), rt0), Ok(0));
        assert_eq!(ids.mp_new_scid(1, c1.clone(), rt1), Ok(1));
        assert_eq!(ids.mp_new_scid(1, c2.clone(), rt2), Ok(2));

        // Sequence numbers we never issued on that path are invalid.
        assert_eq!(ids.mp_retire_scid(1, 5, &c1), Err(Error::InvalidState));
        // Path 1 issued seq 0..2, but path 2 issued nothing.
        assert_eq!(ids.mp_retire_scid(2, 0, &c1), Err(Error::InvalidState));

        // A packet cannot retire the CID it arrived on.
        assert_eq!(ids.mp_retire_scid(1, 0, &c0), Err(Error::InvalidState));

        // Valid retirement returns the retired CID and notifies the app.
        assert_eq!(ids.mp_retire_scid(1, 1, &c2), Ok(Some(c1.clone())));
        assert_eq!(ids.pop_retired_scid(), Some(c1));
        assert_eq!(ids.pop_retired_scid(), None);

        // Path 0 delegates to the legacy logic.
        let (s2, srt2) = create_cid_and_reset_token(16);
        assert_eq!(
            ids.new_scid(s2.clone(), Some(srt2), true, None, false),
            Ok(1)
        );
        assert_eq!(ids.mp_retire_scid(0, 0, &s2), Ok(Some(scid.clone())));
        assert_eq!(ids.pop_retired_scid(), Some(scid));
    }

    #[cfg(feature = "multipath")]
    #[test]
    fn mp_find_scid_path_id_resolves_pools() {
        let (scid, _) = create_cid_and_reset_token(16);
        let (dcid, _) = create_cid_and_reset_token(16);

        let mut ids = ConnectionIdentifiers::new(2, &scid, 0, None);
        ids.set_source_conn_id_limit(3);
        ids.set_initial_dcid(dcid, None, Some(0));

        // Legacy-pool SCIDs belong to path 0.
        assert_eq!(ids.mp_find_scid_path_id(&scid), Some(0));

        let (s2, rt2) = create_cid_and_reset_token(16);
        assert_eq!(
            ids.new_scid(s2.clone(), Some(rt2), true, None, false),
            Ok(1)
        );
        assert_eq!(ids.mp_find_scid_path_id(&s2), Some(0));

        let (c1, rt1) = create_cid_and_reset_token(16);
        let (c2, crt2) = create_cid_and_reset_token(16);
        assert_eq!(ids.mp_new_scid(1, c1.clone(), rt1), Ok(0));
        assert_eq!(ids.mp_new_scid(2, c2.clone(), crt2), Ok(0));
        assert_eq!(ids.mp_find_scid_path_id(&c1), Some(1));
        assert_eq!(ids.mp_find_scid_path_id(&c2), Some(2));

        let (unknown, _) = create_cid_and_reset_token(16);
        assert_eq!(ids.mp_find_scid_path_id(&unknown), None);
    }

    #[cfg(feature = "multipath")]
    #[test]
    fn mp_advertise_queue_drain() {
        let (scid, _) = create_cid_and_reset_token(16);
        let (dcid, _) = create_cid_and_reset_token(16);

        let mut ids = ConnectionIdentifiers::new(2, &scid, 0, None);
        ids.set_source_conn_id_limit(3);
        ids.set_initial_dcid(dcid, None, Some(0));

        assert_eq!(ids.mp_next_advertise_new_scid(), None);

        let (c1, rt1) = create_cid_and_reset_token(16);
        let (c2, rt2) = create_cid_and_reset_token(16);
        assert_eq!(ids.mp_new_scid(1, c1, rt1), Ok(0));
        assert_eq!(ids.mp_new_scid(2, c2, rt2), Ok(0));

        // Issued SCIDs are queued for PATH_NEW_CONNECTION_ID advertisement.
        assert_eq!(ids.mp_next_advertise_new_scid(), Some((1, 0)));

        // Fake the frame being sent.
        ids.mp_mark_advertise_new_scid(1, 0, false);
        assert_eq!(ids.mp_next_advertise_new_scid(), Some((2, 0)));

        // A lost frame can be re-queued.
        ids.mp_mark_advertise_new_scid(1, 0, true);
        ids.mp_mark_advertise_new_scid(2, 0, false);
        assert_eq!(ids.mp_next_advertise_new_scid(), Some((1, 0)));

        ids.mp_mark_advertise_new_scid(1, 0, false);
        assert_eq!(ids.mp_next_advertise_new_scid(), None);
    }

    /// Issue 1: CIDs issued in a per-path pool must not be re-issuable on
    /// path 0, neither through `mp_new_scid(0, …)` nor through `new_scid`.
    #[cfg(feature = "multipath")]
    #[test]
    fn mp_path0_rejects_cid_already_in_per_path_pool() {
        let (scid, _) = create_cid_and_reset_token(16);
        let (dcid, _) = create_cid_and_reset_token(16);

        let mut ids = ConnectionIdentifiers::new(2, &scid, 0, None);
        ids.set_source_conn_id_limit(4);
        ids.set_initial_dcid(dcid, None, Some(0));

        // Issue CID bytes X on path 1.
        let (x, rtx) = create_cid_and_reset_token(16);
        assert_eq!(ids.mp_new_scid(1, x.clone(), rtx), Ok(0));

        // Re-issuing the same bytes on path 0 via the multipath shim must fail.
        assert_eq!(
            ids.mp_new_scid(0, x.clone(), rtx),
            Err(Error::InvalidState),
            "mp_new_scid(0) must reject CID bytes already in a per-path pool",
        );

        // Re-issuing the same bytes directly via new_scid must also fail.
        let other_token: u128 = rtx.wrapping_add(1);
        assert_eq!(
            ids.new_scid(x.clone(), Some(other_token), true, None, false),
            Err(Error::InvalidState),
            "new_scid must reject CID bytes already in a per-path pool",
        );
    }

    /// Issue 2: `mp_retire_dcid_seqs` must be bounded; once the cap is
    /// reached, further inserts via `mp_mark_retire_dcid` must return
    /// `Error::IdLimit`.
    #[cfg(feature = "multipath")]
    #[test]
    fn mp_retire_dcid_seqs_bounded() {
        let (scid, _) = create_cid_and_reset_token(16);
        let (dcid, _) = create_cid_and_reset_token(16);

        // destination_conn_id_limit = 2 → cap = 2 * 3 = 6.
        let dcid_limit = 2usize;
        let cap = dcid_limit * (RETIRED_CONN_ID_LIMIT_MULTIPLIER as usize);

        let mut ids = ConnectionIdentifiers::new(dcid_limit, &scid, 0, None);
        ids.set_initial_dcid(dcid, None, Some(0));

        // Fill the set to the cap — all inserts must succeed.
        for seq in 0..cap as u64 {
            assert_eq!(
                ids.mp_mark_retire_dcid(1, seq, true),
                Ok(()),
                "insert {seq} should succeed (cap = {cap})",
            );
        }

        // One more insert must return IdLimit.
        assert_eq!(
            ids.mp_mark_retire_dcid(1, cap as u64, true),
            Err(Error::IdLimit),
            "insert past cap must return IdLimit",
        );

        // Re-inserting an already-present element at capacity (e.g., upon
        // frame retransmission) is not an error.
        assert_eq!(
            ids.mp_mark_retire_dcid(1, 0, true),
            Ok(()),
            "re-inserting a present element at cap must not error",
        );
    }

    /// `BoundedSeqSet::insert` must report success for an already-present
    /// element even when the set is at capacity, so that e.g. re-receiving
    /// a frame retiring an already-queued sequence number does not close
    /// the connection. This exercises the legacy (`u64`) alias.
    #[test]
    fn retire_dcid_seqs_reinsert_at_capacity() {
        let (scid, _) = create_cid_and_reset_token(16);
        let (dcid, _) = create_cid_and_reset_token(16);

        // destination_conn_id_limit = 2 → cap = 2 * 3 = 6.
        let cap = 2 * RETIRED_CONN_ID_LIMIT_MULTIPLIER;

        let mut ids = ConnectionIdentifiers::new(2, &scid, 0, None);
        ids.set_initial_dcid(dcid, None, Some(0));

        for seq in 0..cap {
            assert_eq!(ids.mark_retire_dcid_seq(seq, true), Ok(()));
        }

        // A new element does not fit.
        assert_eq!(ids.mark_retire_dcid_seq(cap, true), Err(Error::IdLimit));

        // An already-present one is fine.
        assert_eq!(ids.mark_retire_dcid_seq(0, true), Ok(()));
        assert_eq!(ids.retire_dcid_seqs().len(), cap as usize);
    }

    /// Fix: the pending PATH_RETIRE_CONNECTION_ID set capacity must scale
    /// with the number of per-path pools, so that a legitimate retirement
    /// wave across several paths does not spuriously hit `IdLimit`.
    #[cfg(feature = "multipath")]
    #[test]
    fn mp_retire_dcid_seqs_capacity_scales_with_pools() {
        let (scid, _) = create_cid_and_reset_token(16);
        let (dcid, _) = create_cid_and_reset_token(16);

        // destination_conn_id_limit = 2 → single-path cap = 2 * 3 = 6.
        let dcid_limit = 2usize;
        let single_cap = dcid_limit * (RETIRED_CONN_ID_LIMIT_MULTIPLIER as usize);

        let mut ids = ConnectionIdentifiers::new(dcid_limit, &scid, 0, None);
        ids.set_initial_dcid(dcid, None, Some(0));

        // Create 3 per-path pools.
        let mut retired = Vec::new();
        for path_id in 1..=3 {
            let (d, rt) = create_cid_and_reset_token(16);
            assert_eq!(
                ids.mp_new_dcid(path_id, d, 0, rt, 0, &mut retired),
                Ok(())
            );
        }

        // With 3 pools the cap is (1 + 3) * 2 * 3 = 24.
        let scaled_cap = (1 + 3) * single_cap;

        // Drive retirements across all 3 paths, well beyond the single-path
        // cap of 6 (the 7th insert would fail without capacity scaling):
        // every insert up to the scaled cap must succeed.
        let per_path = (scaled_cap / 3) as u64;
        for seq in 0..per_path {
            for path_id in 1..=3 {
                assert_eq!(
                    ids.mp_mark_retire_dcid(path_id, seq, true),
                    Ok(()),
                    "retire ({path_id}, {seq}) must fit in the scaled cap",
                );
            }
        }

        // The very next (new) insert exceeds the scaled cap.
        assert_eq!(
            ids.mp_mark_retire_dcid(1, per_path, true),
            Err(Error::IdLimit),
        );
    }

    /// `mp_new_dcid` must replicate `new_dcid`'s delayed-error handling:
    /// when queueing a retired sequence number hits the set's capacity, the
    /// drain still completes, the path's largest Retire Prior To advances
    /// and the new DCID is inserted before the error is propagated.
    #[cfg(feature = "multipath")]
    #[test]
    fn mp_new_dcid_retire_queue_error_is_delayed() {
        let (scid, _) = create_cid_and_reset_token(16);
        let (dcid, _) = create_cid_and_reset_token(16);

        let mut retired = Vec::new();

        let mut ids = ConnectionIdentifiers::new(2, &scid, 0, None);
        ids.set_initial_dcid(dcid, None, Some(0));

        // Populate path 1 with seqs 0 and 1 (creating the pool grows the
        // retire set capacity to (1 + 1) * 2 * 3 = 12).
        let (d0, rt0) = create_cid_and_reset_token(16);
        let (d1, rt1) = create_cid_and_reset_token(16);
        assert_eq!(ids.mp_new_dcid(1, d0, 0, rt0, 0, &mut retired), Ok(()));
        assert_eq!(ids.mp_new_dcid(1, d1, 1, rt1, 0, &mut retired), Ok(()));

        // Fill the retire set to its capacity with unrelated entries.
        for seq in 0..12 {
            assert_eq!(ids.mp_mark_retire_dcid(9, seq, true), Ok(()));
        }

        // Seq 2 with Retire Prior To 2 drains seqs 0 and 1, but queueing
        // them for PATH_RETIRE_CONNECTION_ID emission fails.
        let (d2, rt2) = create_cid_and_reset_token(16);
        retired.clear();
        assert_eq!(
            ids.mp_new_dcid(1, d2.clone(), 2, rt2, 2, &mut retired),
            Err(Error::IdLimit)
        );

        // The drained entry that hit the error is still reported.
        assert_eq!(retired, vec![(1, 0, None)]);

        // Despite the error, the drain completed, the path's Retire Prior
        // To advanced and the new DCID was inserted.
        assert_eq!(ids.mp_pools[&1].largest_peer_retire_prior_to, 2);
        assert_eq!(ids.mp_pools[&1].dcids.len(), 1);
        assert_eq!(ids.mp_get_dcid(1, 2).unwrap().cid, d2);
    }

    /// Retired entries reported by `mp_new_dcid` carry the (4-tuple) slab
    /// path that was using them, if any, so that the caller can unlink and
    /// re-fund the affected path.
    #[cfg(feature = "multipath")]
    #[test]
    fn mp_new_dcid_reports_slab_link_of_retired_entries() {
        let (scid, _) = create_cid_and_reset_token(16);
        let (dcid, _) = create_cid_and_reset_token(16);

        let mut retired = Vec::new();

        let mut ids = ConnectionIdentifiers::new(2, &scid, 0, None);
        ids.set_initial_dcid(dcid, None, Some(0));

        let (d0, rt0) = create_cid_and_reset_token(16);
        let (d1, rt1) = create_cid_and_reset_token(16);
        assert_eq!(ids.mp_new_dcid(1, d0, 0, rt0, 0, &mut retired), Ok(()));
        assert_eq!(ids.mp_new_dcid(1, d1, 1, rt1, 0, &mut retired), Ok(()));

        // Link seq 0 to slab path 4; seq 1 stays unlinked.
        assert_eq!(ids.mp_link_dcid_to_path_id(1, 0, 4), Ok(()));

        // Retire both: the slab link must be surfaced for seq 0.
        let (d2, rt2) = create_cid_and_reset_token(16);
        assert_eq!(ids.mp_new_dcid(1, d2, 2, rt2, 2, &mut retired), Ok(()));
        assert_eq!(retired, vec![(1, 0, Some(4)), (1, 1, None)]);
    }

    /// B1: retiring the sole SCID on a per-path pool must succeed; the pool
    /// becomes empty, headroom opens up to the full limit, and the sequence
    /// number space continues (no reuse of seq 0).
    #[cfg(feature = "multipath")]
    #[test]
    fn mp_retire_last_per_path_scid_pool_empties() {
        let (scid, _) = create_cid_and_reset_token(16);
        let (dcid, _) = create_cid_and_reset_token(16);
        let other_cid = {
            let (c, _) = create_cid_and_reset_token(16);
            c
        };

        let mut ids = ConnectionIdentifiers::new(2, &scid, 0, None);
        ids.set_source_conn_id_limit(2);
        ids.set_initial_dcid(dcid, None, Some(0));

        // Issue exactly 1 SCID on path 1.
        let (c0, rt0) = create_cid_and_reset_token(16);
        assert_eq!(ids.mp_new_scid(1, c0.clone(), rt0), Ok(0));
        assert_eq!(ids.mp_scids_left(1), 1); // 2 limit, 1 active → 1 left

        // Retiring the only SCID must succeed (carried on another CID).
        assert_eq!(
            ids.mp_retire_scid(1, 0, &other_cid),
            Ok(Some(c0.clone())),
            "retiring the last per-path SCID must not error",
        );

        // The retired CID is surfaced to the application.
        assert_eq!(ids.pop_retired_scid(), Some(c0));
        assert_eq!(ids.pop_retired_scid(), None);

        // Pool is now empty: full headroom is available.
        assert_eq!(
            ids.mp_scids_left(1),
            2,
            "after draining the pool, full limit headroom must be available",
        );

        // Sequence number space continues; a fresh issue must use seq 1.
        let (c1, rt1) = create_cid_and_reset_token(16);
        assert_eq!(
            ids.mp_new_scid(1, c1, rt1),
            Ok(1),
            "next issued SCID on path 1 must use seq 1, not reuse seq 0",
        );
    }

    /// `mp_scids_left` mirrors the legacy accounting per path: it reports
    /// how many SCIDs can still be issued on the path, and increases when
    /// one is retired (signalling that the application should supply a
    /// replacement).
    #[cfg(feature = "multipath")]
    #[test]
    fn mp_scids_left_per_path() {
        let (scid, _) = create_cid_and_reset_token(16);
        let (dcid, _) = create_cid_and_reset_token(16);

        let mut ids = ConnectionIdentifiers::new(2, &scid, 0, None);
        ids.set_source_conn_id_limit(3);
        ids.set_initial_dcid(dcid, None, Some(0));

        // Path 0 reports the legacy space: 1 active SCID out of 3.
        assert_eq!(ids.mp_scids_left(0), 2);

        // A path without a pool has the full budget available.
        assert_eq!(ids.mp_scids_left(1), 3);

        let (c0, rt0) = create_cid_and_reset_token(16);
        let (c1, rt1) = create_cid_and_reset_token(16);
        let (c2, rt2) = create_cid_and_reset_token(16);
        assert_eq!(ids.mp_new_scid(1, c0.clone(), rt0), Ok(0));
        assert_eq!(ids.mp_new_scid(1, c1.clone(), rt1), Ok(1));
        assert_eq!(ids.mp_new_scid(1, c2, rt2), Ok(2));
        assert_eq!(ids.mp_scids_left(1), 0);

        // Retiring one frees one slot: a replacement is needed.
        assert_eq!(ids.mp_retire_scid(1, 1, &c0), Ok(Some(c1)));
        assert_eq!(ids.mp_scids_left(1), 1);

        // Other paths are not affected.
        assert_eq!(ids.mp_scids_left(2), 3);
        assert_eq!(ids.mp_scids_left(0), 2);
    }
}
