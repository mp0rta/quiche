//! Send pipeline — packet construction and frame assembly.

use super::*;

impl<F: BufFactory> Connection<F> {
    pub(crate) fn send_single(
        &mut self, out: &mut [u8], send_pid: usize, has_initial: bool,
        now: Instant,
    ) -> Result<(Type, usize)> {
        if out.is_empty() {
            return Err(Error::BufferTooShort);
        }

        if self.is_draining() {
            return Err(Error::Done);
        }

        let is_closing = self.local_error.is_some();

        let mp = self.mp_enabled();

        let out_len = out.len();

        let mut b = octets::OctetsMut::with_slice(out);

        let pkt_type = self.write_pkt_type(send_pid)?;

        let max_dgram_len = if !self.dgram_send_queue.is_empty() {
            self.dgram_max_writable_len()
        } else {
            None
        };

        let epoch = pkt_type.to_epoch()?;
        let pkt_space = &mut self.pkt_num_spaces[epoch];
        let crypto_ctx = &mut self.crypto_ctx[epoch];

        // Process lost frames. There might be several paths having lost frames.
        //
        // Vecs to accumulate path_id values for PATH_ABANDON / PATH_STATUS
        // lost frames requiring retransmission (deferred to avoid nested
        // mutable borrows of self.paths).
        #[cfg(feature = "multipath")]
        let mut mp_abandon_lost: SmallVec<[u64; 2]> = SmallVec::new();
        #[cfg(feature = "multipath")]
        let mut mp_status_lost: SmallVec<[(u64, u64); 2]> = SmallVec::new();
        #[cfg(feature = "multipath")]
        let mut mp_retire_dcid_lost: SmallVec<[(u64, u64); 2]> =
            SmallVec::new();
        #[cfg(feature = "multipath")]
        let mut legacy_retire_dcid_lost: SmallVec<[u64; 2]> = SmallVec::new();
        #[cfg(feature = "multipath")]
        let mut mp_paths_blocked_lost = false;
        #[cfg(feature = "multipath")]
        let mut mp_cids_blocked_lost = false;

        for (_, p) in self.paths.iter_mut() {
            while let Some(lost) = p.recovery.next_lost_frame(epoch) {
                match lost {
                    frame::Frame::CryptoHeader { offset, length } => {
                        crypto_ctx.crypto_stream.send.retransmit(offset, length);

                        self.stream_retrans_bytes += length as u64;
                        p.stream_retrans_bytes += length as u64;

                        self.retrans_count += 1;
                        p.retrans_count += 1;
                    },

                    frame::Frame::StreamHeader {
                        stream_id,
                        offset,
                        length,
                        fin,
                    } => {
                        let stream = match self.streams.get_mut(stream_id) {
                            // Only retransmit data if the stream is not closed
                            // or stopped.
                            Some(v) if !v.send.is_stopped() => v,

                            // Data on a closed stream will not be retransmitted
                            // or acked after it is declared lost, so update
                            // tx_buffered and qlog.
                            _ => {
                                self.tx_buffered =
                                    self.tx_buffered.saturating_sub(length);

                                qlog_with_type!(QLOG_DATA_MV, self.qlog, q, {
                                    let ev_data = EventData::DataMoved(
                                        qlog::events::quic::DataMoved {
                                            stream_id: Some(stream_id),
                                            offset: Some(offset),
                                            length: Some(length as u64),
                                            from: Some(DataRecipient::Transport),
                                            to: Some(DataRecipient::Dropped),
                                            ..Default::default()
                                        },
                                    );

                                    q.add_event_data_with_instant(ev_data, now)
                                        .ok();
                                });

                                continue;
                            },
                        };

                        let was_flushable = stream.is_flushable();

                        let empty_fin = length == 0 && fin;

                        stream.send.retransmit(offset, length);

                        // If the stream is now flushable push it to the
                        // flushable queue, but only if it wasn't already
                        // queued.
                        //
                        // Consider the stream flushable also when we are
                        // sending a zero-length frame that has the fin flag
                        // set.
                        if (stream.is_flushable() || empty_fin) && !was_flushable
                        {
                            let priority_key = Arc::clone(&stream.priority_key);
                            self.streams.insert_flushable(&priority_key);
                        }

                        self.stream_retrans_bytes += length as u64;
                        p.stream_retrans_bytes += length as u64;

                        self.retrans_count += 1;
                        p.retrans_count += 1;

                        #[cfg(feature = "multipath")]
                        {
                            self.pending_reinjection_path =
                                Some(p.path_id);
                        }
                    },

                    frame::Frame::ACK { .. } => {
                        pkt_space.ack_elicited = true;
                    },

                    frame::Frame::ResetStream {
                        stream_id,
                        error_code,
                        final_size,
                    } => {
                        self.streams
                            .insert_reset(stream_id, error_code, final_size);
                    },

                    frame::Frame::StopSending {
                        stream_id,
                        error_code,
                    } =>
                    // We only need to retransmit the STOP_SENDING frame if
                    // the stream is still active and not FIN'd. Even if the
                    // packet was lost, if the application has the final
                    // size at this point there is no need to retransmit.
                        if let Some(stream) = self.streams.get(stream_id) {
                            if !stream.recv.is_fin() {
                                self.streams
                                    .insert_stopped(stream_id, error_code);
                            }
                        },

                    // Retransmit HANDSHAKE_DONE only if it hasn't been acked at
                    // least once already.
                    frame::Frame::HandshakeDone if !self.handshake_done_acked => {
                        self.handshake_done_sent = false;
                    },

                    #[cfg(feature = "multipath")]
                    frame::Frame::PathAbandon { path_id, .. } => {
                        mp_abandon_lost.push(path_id);
                    },

                    #[cfg(feature = "multipath")]
                    frame::Frame::PathStatusAvailable { path_id, seq_num } |
                    frame::Frame::PathStatusBackup { path_id, seq_num } => {
                        mp_status_lost.push((path_id, seq_num));
                    },

                    #[cfg(feature = "multipath")]
                    frame::Frame::PathsBlocked { .. } => {
                        mp_paths_blocked_lost = true;
                    },

                    #[cfg(feature = "multipath")]
                    frame::Frame::MaxPathId { path_id } => {
                        // §4.6: MAX_PATH_ID frames SHOULD be retransmitted
                        // when lost, unless a more recent MAX_PATH_ID
                        // frame has been sent (or the value was
                        // acknowledged) in the meantime.
                        if Some(path_id) == self.mp_max_path_id_sent &&
                            !self.mp_max_path_id_acked
                        {
                            self.mp_max_path_id_pending = Some(path_id);
                        }
                    },

                    #[cfg(feature = "multipath")]
                    frame::Frame::PathCidsBlocked { .. } => {
                        mp_cids_blocked_lost = true;
                    },

                    frame::Frame::MaxStreamData { stream_id, .. } => {
                        if self.streams.get(stream_id).is_some() {
                            self.streams.insert_almost_full(stream_id);
                        }
                    },

                    frame::Frame::MaxData { .. } => {
                        self.should_send_max_data = true;
                    },

                    frame::Frame::MaxStreamsUni { .. } => {
                        self.should_send_max_streams_uni = true;
                    },

                    frame::Frame::MaxStreamsBidi { .. } => {
                        self.should_send_max_streams_bidi = true;
                    },

                    frame::Frame::NewConnectionId { seq_num, .. } => {
                        self.ids.mark_advertise_new_scid_seq(seq_num, true);
                    },

                    frame::Frame::RetireConnectionId { seq_num } => {
                        // Deferred below when multipath is enabled: the
                        // legacy CID space belongs to path 0, which may
                        // have been abandoned in the meantime, but
                        // `self.paths` cannot be queried from inside this
                        // loop. Mirrors the PATH_RETIRE_CONNECTION_ID
                        // handling.
                        #[cfg(feature = "multipath")]
                        legacy_retire_dcid_lost.push(seq_num);

                        #[cfg(not(feature = "multipath"))]
                        self.ids.mark_retire_dcid_seq(seq_num, true)?;
                    },

                    #[cfg(feature = "multipath")]
                    frame::Frame::PathNewConnectionId {
                        path_id,
                        seq_num,
                        ..
                    } => {
                        // Only re-advertise the SCID if it is still in the
                        // per-path pool: the peer may have retired it in
                        // the meantime.
                        if self.ids.mp_get_scid(path_id, seq_num).is_ok() {
                            self.ids.mp_mark_advertise_new_scid(
                                path_id, seq_num, true,
                            );
                        }
                    },

                    #[cfg(feature = "multipath")]
                    frame::Frame::PathRetireConnectionId { path_id, seq_num } => {
                        // Deferred below: paths abandoned in the meantime
                        // have their connection IDs implicitly retired and
                        // must not emit PATH_RETIRE_CONNECTION_ID frames
                        // (draft-21 §3.4), but `self.paths` cannot be
                        // queried from inside this loop.
                        mp_retire_dcid_lost.push((path_id, seq_num));
                    },

                    frame::Frame::Ping {
                        mtu_probe: Some(failed_probe),
                    } =>
                        if let Some(pmtud) = p.pmtud.as_mut() {
                            trace!("pmtud probe dropped: {failed_probe}");
                            pmtud.failed_probe(failed_probe);
                        },

                    _ => (),
                }
            }
        }

        // Apply PATH_ABANDON / PATH_STATUS lost state updates deferred from
        // inside the lost-frames loop (to avoid nested mutable borrows of
        // self.paths).
        #[cfg(feature = "multipath")]
        for mp_path_id in mp_abandon_lost {
            // PATH_ABANDON SHOULD be repeated if lost (draft-21 §4.2). If
            // the path state was already deleted (retention window
            // expired), the retransmission is carried at the connection
            // level instead.
            let mut handled = false;

            for (_, p) in self.paths.iter_mut() {
                if p.path_id == mp_path_id {
                    if !p.mp_path_abandon_acked {
                        p.mp_path_abandon_pending = true;
                    }
                    handled = true;
                    break;
                }
            }

            if !handled &&
                self.paths.is_abandoned_path_id(mp_path_id) &&
                !self.mp_abandon_queue.iter().any(|&(id, _)| id == mp_path_id)
            {
                self.mp_abandon_queue.push((
                    mp_path_id,
                    multipath::frames::PATH_ABANDON_NO_ERROR,
                ));
            }
        }
        #[cfg(feature = "multipath")]
        for (mp_path_id, seq_num) in mp_status_lost {
            for (_, p) in self.paths.iter_mut() {
                if p.path_id == mp_path_id {
                    // Only re-arm for the loss of the *latest* PATH_STATUS
                    // frame; a superseded status frame must not be
                    // retransmitted (the rebuilt frame always carries the
                    // current status and sequence number anyway).
                    if seq_num == p.mp_path_status_seq_num &&
                        !p.mp_path_status_acked
                    {
                        p.mp_path_status_pending = true;
                    }
                    break;
                }
            }
        }
        #[cfg(feature = "multipath")]
        for (mp_path_id, seq_num) in mp_retire_dcid_lost {
            // Abandoned path IDs have their connection IDs implicitly
            // retired: no PATH_RETIRE_CONNECTION_ID is emitted for them
            // (draft-21 §3.4).
            if self.paths.is_abandoned_path_id(mp_path_id) {
                continue;
            }

            // Skip paths currently in their post-abandon retention window
            // as well: their DCID pool has already been dropped.
            if self
                .paths
                .iter()
                .any(|(_, p)| p.path_id == mp_path_id && p.mp_closing)
            {
                continue;
            }

            self.ids.mp_mark_retire_dcid(mp_path_id, seq_num, true)?;
        }
        #[cfg(feature = "multipath")]
        for seq_num in legacy_retire_dcid_lost {
            // The legacy CID space belongs to path 0: once it is
            // abandoned (or in its retention window) its connection IDs
            // are implicitly retired and no legacy RETIRE_CONNECTION_ID
            // is re-queued for them (draft-21 §3.4), mirroring the
            // PATH_RETIRE_CONNECTION_ID gate above.
            if self.mp_path_zero_abandoned() {
                continue;
            }

            self.ids.mark_retire_dcid_seq(seq_num, true)?;
        }

        // Re-arm lost PATHS_BLOCKED / PATH_CIDS_BLOCKED frames only if the
        // blocking condition still holds (the frames are one-shot and carry
        // a point-in-time value, so they are rebuilt from current state
        // rather than retransmitted verbatim).
        #[cfg(feature = "multipath")]
        if mp_paths_blocked_lost || mp_cids_blocked_lost {
            match self.mp_select_new_path_id() {
                outcome @ MpNewPathId::Exhausted if mp_paths_blocked_lost =>
                    self.mp_queue_blocked_signal(outcome),

                outcome @ MpNewPathId::NoCid { .. } if mp_cids_blocked_lost =>
                    self.mp_queue_blocked_signal(outcome),

                _ => (),
            }
        }

        self.check_tx_buffered_invariant();

        // PTO scaling the closing period armed when a CONNECTION_CLOSE /
        // APPLICATION_CLOSE frame is sent below. Computed up front (the
        // sending path is mutably borrowed at that point): the largest
        // PTO among all paths with multipath (draft-21 §2.6), the
        // sending path's PTO otherwise.
        #[cfg(feature = "multipath")]
        let mp_closing_pto = if is_closing && self.multipath_enabled {
            Some(self.paths.max_pto())
        } else {
            None
        };

        #[cfg(not(feature = "multipath"))]
        let mp_closing_pto: Option<Duration> = None;

        let is_app_limited = self.delivery_rate_check_if_app_limited();
        let n_paths = self.paths.len();
        let path = self.paths.get_mut(send_pid)?;
        let flow_control = &mut self.flow_control;
        let pkt_space = &mut self.pkt_num_spaces[epoch];
        let crypto_ctx = &mut self.crypto_ctx[epoch];
        let pkt_num_manager = &mut self.pkt_num_manager;

        let mut left = if let Some(pmtud) = path.pmtud.as_mut() {
            // Limit output buffer size by estimated path MTU.
            cmp::min(pmtud.get_current_mtu(), b.cap())
        } else {
            b.cap()
        };

        // Task 16: Per-path packet number space for multipath.
        // When multipath is enabled and we are sending an Application Data
        // (Short header) packet, use the per-path counter instead of the
        // shared connection-level counter.  Only activate when there are
        // multiple paths so that single-path (initial) operation continues
        // to use the shared counter (which the receiver can decode without
        // per-path state).
        //
        // n_paths was computed before the mutable borrow of `path` so
        // the borrow checker permits its use here.
        //
        // `use_per_path_pn` tracks whether the per-path counter was used so
        // the post-send shared counter increment can be skipped.
        #[cfg(feature = "multipath")]
        let (pn, use_per_path_pn) = if self.multipath_enabled &&
            pkt_type == Type::Short &&
            n_paths > 1
        {
            // Grab the per-path packet number and increment it immediately so
            // the post-send increment of `self.next_pkt_num` is skipped.
            let per_path_pn = path.mp_next_pkt_num;
            path.mp_next_pkt_num += 1;
            (per_path_pn, true)
        } else {
            if pkt_num_manager.should_skip_pn(self.handshake_completed) {
                pkt_num_manager.set_skip_pn(Some(self.next_pkt_num));
                self.next_pkt_num += 1;
            };
            (self.next_pkt_num, false)
        };

        #[cfg(not(feature = "multipath"))]
        let (pn, use_per_path_pn) = {
            if pkt_num_manager.should_skip_pn(self.handshake_completed) {
                pkt_num_manager.set_skip_pn(Some(self.next_pkt_num));
                self.next_pkt_num += 1;
            };
            (self.next_pkt_num, false)
        };

        let largest_acked_pkt =
            path.recovery.get_largest_acked_on_epoch(epoch).unwrap_or(0);
        let pn_len = packet::pkt_num_len(pn, largest_acked_pkt);

        // The AEAD overhead at the current encryption level.
        let crypto_overhead = crypto_ctx.crypto_overhead().ok_or(Error::Done)?;

        let dcid_seq = path.active_dcid_seq.ok_or(Error::OutOfIdentifiers)?;

        // Paths opened by consuming a per-path CID (draft-21 §3.1) resolve
        // their Connection IDs from their path ID's own pools; other paths
        // keep resolving from the legacy pools.
        #[cfg(feature = "multipath")]
        let dcid = if path.mp_per_path_cids {
            ConnectionId::from_ref(
                self.ids.mp_get_dcid(path.path_id, dcid_seq)?.cid.as_ref(),
            )
        } else {
            ConnectionId::from_ref(self.ids.get_dcid(dcid_seq)?.cid.as_ref())
        };

        #[cfg(not(feature = "multipath"))]
        let dcid =
            ConnectionId::from_ref(self.ids.get_dcid(dcid_seq)?.cid.as_ref());

        let scid = if let Some(scid_seq) = path.active_scid_seq {
            #[cfg(feature = "multipath")]
            let scid_entry = if path.mp_per_path_cids {
                self.ids.mp_get_scid(path.path_id, scid_seq)?
            } else {
                self.ids.get_scid(scid_seq)?
            };

            #[cfg(not(feature = "multipath"))]
            let scid_entry = self.ids.get_scid(scid_seq)?;

            ConnectionId::from_ref(scid_entry.cid.as_ref())
        } else if pkt_type == Type::Short {
            ConnectionId::default()
        } else {
            return Err(Error::InvalidState);
        };

        let hdr = Header {
            ty: pkt_type,

            version: self.version,

            dcid,
            scid,

            pkt_num: 0,
            pkt_num_len: pn_len,

            // Only clone token for Initial packets, as other packets don't have
            // this field (Retry doesn't count, as it's not encoded as part of
            // this code path).
            token: if pkt_type == Type::Initial {
                self.token.clone()
            } else {
                None
            },

            versions: None,
            key_phase: self.key_phase,
        };

        hdr.to_bytes(&mut b)?;

        let hdr_trace = if log::max_level() == log::LevelFilter::Trace {
            Some(format!("{hdr:?}"))
        } else {
            None
        };

        let hdr_ty = hdr.ty;

        #[cfg(feature = "qlog")]
        let qlog_pkt_hdr = self.qlog.streamer.as_ref().map(|_q| {
            qlog::events::quic::PacketHeader::with_type(
                hdr.ty.to_qlog(),
                Some(pn),
                Some(hdr.version),
                Some(&hdr.scid),
                Some(&hdr.dcid),
            )
        });

        // Calculate the space required for the packet, including the header
        // the payload length, the packet number and the AEAD overhead.
        let mut overhead = b.off() + pn_len + crypto_overhead;

        // We assume that the payload length, which is only present in long
        // header packets, can always be encoded with a 2-byte varint.
        if pkt_type != Type::Short {
            overhead += PAYLOAD_LENGTH_LEN;
        }

        // Make sure we have enough space left for the packet overhead.
        match left.checked_sub(overhead) {
            Some(v) => left = v,

            None => {
                // We can't send more because there isn't enough space available
                // in the output buffer.
                //
                // This usually happens when we try to send a new packet but
                // failed because cwnd is almost full. In such case app_limited
                // is set to false here to make cwnd grow when ACK is received.
                path.recovery.update_app_limited(false);
                return Err(Error::Done);
            },
        }

        // Make sure there is enough space for the minimum payload length.
        if left < PAYLOAD_MIN_LEN {
            path.recovery.update_app_limited(false);
            return Err(Error::Done);
        }

        let mut frames: SmallVec<[frame::Frame; 1]> = SmallVec::new();

        let mut ack_eliciting = false;
        let mut in_flight = false;
        let mut is_pmtud_probe = false;
        let mut has_data = false;

        // Whether or not we should explicitly elicit an ACK via PING frame if we
        // implicitly elicit one otherwise.
        let ack_elicit_required = path.recovery.should_elicit_ack(epoch);

        let header_offset = b.off();

        // Reserve space for payload length in advance. Since we don't yet know
        // what the final length will be, we reserve 2 bytes in all cases.
        //
        // Only long header packets have an explicit length field.
        if pkt_type != Type::Short {
            b.skip(PAYLOAD_LENGTH_LEN)?;
        }

        packet::encode_pkt_num(pn, pn_len, &mut b)?;

        let payload_offset = b.off();

        let cwnd_available =
            path.recovery.cwnd_available().saturating_sub(overhead);

        let left_before_packing_ack_frame = left;

        // Create ACK frame.
        //
        // When we need to explicitly elicit an ACK via PING later, go ahead and
        // generate an ACK (if there's anything to ACK) since we're going to
        // send a packet with PING anyways, even if we haven't received anything
        // ACK eliciting.
        if pkt_space.recv_pkt_need_ack.len() > 0 &&
            (pkt_space.ack_elicited || ack_elicit_required) &&
            (!is_closing ||
                (pkt_type == Type::Handshake &&
                    self.local_error
                        .as_ref()
                        .is_some_and(|le| le.is_app))) &&
            path.can_send(mp)
        {
            #[cfg(not(feature = "fuzzing"))]
            let ack_delay = pkt_space.largest_rx_pkt_time.elapsed();

            #[cfg(not(feature = "fuzzing"))]
            let ack_delay = ack_delay.as_micros() as u64 /
                2_u64
                    .pow(self.local_transport_params.ack_delay_exponent as u32);

            // pseudo-random reproducible ack delays when fuzzing
            #[cfg(feature = "fuzzing")]
            let ack_delay = rand::rand_u8() as u64 + 1;

            let frame = frame::Frame::ACK {
                ack_delay,
                ranges: pkt_space.recv_pkt_need_ack.clone(),
                ecn_counts: None, // sending ECN is not supported at this time
            };

            // When a PING frame needs to be sent, avoid sending the ACK if
            // there is not enough cwnd available for both (note that PING
            // frames are always 1 byte, so we just need to check that the
            // ACK's length is lower than cwnd).
            if pkt_space.ack_elicited || frame.wire_len() < cwnd_available {
                // ACK-only packets are not congestion controlled so ACKs must
                // be bundled considering the buffer capacity only, and not the
                // available cwnd.
                if push_frame_to_pkt!(b, frames, frame, left) {
                    pkt_space.ack_elicited = false;
                }
            }
        }

        // Generate PATH_ACK frames for all paths when multipath is enabled.
        // PATH_ACK frames for any path can be sent on any path.
        #[cfg(feature = "multipath")]
        if self.multipath_enabled && pkt_type == Type::Short {
            // Collect per-path ACK info into locals to avoid borrow
            // conflicts with push_frame_to_pkt! (which borrows `b`).
            // The ranges are cloned — same pattern as the regular ACK
            // (line ~4649) — because they must persist for retransmission
            // if the PATH_ACK is lost.
            let ack_delay_exponent =
                self.local_transport_params.ack_delay_exponent as u32;
            let mp_ack_infos: SmallVec<
                [(usize, u64, u64, ranges::RangeSet); 4],
            > = self
                .paths
                .iter()
                .filter(|(_, p)| {
                    p.app_pkt_num_space.recv_pkt_need_ack.len() > 0 &&
                        p.app_pkt_num_space.ack_elicited
                })
                .map(|(pid, p)| {
                    #[cfg(not(feature = "fuzzing"))]
                    let delay = {
                        let elapsed =
                            p.app_pkt_num_space.largest_rx_pkt_time.elapsed();
                        elapsed.as_micros() as u64 /
                            2_u64.pow(ack_delay_exponent)
                    };
                    #[cfg(feature = "fuzzing")]
                    let delay = rand::rand_u8() as u64 + 1;
                    (
                        pid,
                        p.path_id,
                        delay,
                        p.app_pkt_num_space.recv_pkt_need_ack.clone(),
                    )
                })
                .collect();

            for (pid, mp_path_id, mp_ack_delay, mp_ranges) in mp_ack_infos {
                let frame = frame::Frame::PathAck {
                    path_id: mp_path_id,
                    ack_delay: mp_ack_delay,
                    ranges: mp_ranges,
                    ecn_counts: None,
                };

                if push_frame_to_pkt!(b, frames, frame, left) {
                    self.paths
                        .get_mut(pid)
                        .unwrap()
                        .app_pkt_num_space
                        .ack_elicited = false;
                }
            }
        }

        // Generate PATH_ABANDON frames for paths that are closing.
        #[cfg(feature = "multipath")]
        if self.multipath_enabled && pkt_type == Type::Short {
            let abandon_paths: SmallVec<[(usize, u64, u64); 2]> = self
                .paths
                .iter()
                .filter(|(_, p)| p.mp_path_abandon_pending)
                .map(|(i, p)| (i, p.path_id, p.mp_path_abandon_error_code))
                .collect();

            for (pid, mp_path_id, mp_error_code) in abandon_paths {
                let frame = frame::Frame::PathAbandon {
                    path_id: mp_path_id,
                    error_code: mp_error_code,
                };

                if push_frame_to_pkt!(b, frames, frame, left) {
                    let p = self.paths.get_mut(pid).unwrap();
                    p.mp_path_abandon_pending = false;
                    p.mp_path_abandon_sent = true;
                    ack_eliciting = true;
                    in_flight = true;
                }
            }

            // Generate PATH_ABANDON frames queued at the connection level:
            // echoes for path IDs without a live path and retransmissions
            // for paths whose state was already deleted (draft-21 §3.4).
            let mut qi = 0;
            while qi < self.mp_abandon_queue.len() {
                let (mp_path_id, mp_error_code) = self.mp_abandon_queue[qi];

                let frame = frame::Frame::PathAbandon {
                    path_id: mp_path_id,
                    error_code: mp_error_code,
                };

                if push_frame_to_pkt!(b, frames, frame, left) {
                    self.mp_abandon_queue.remove(qi);
                    ack_eliciting = true;
                    in_flight = true;
                } else {
                    qi += 1;
                }
            }

            let status_paths: SmallVec<
                [(usize, u64, path::PathAppStatus, u64); 2],
            > = self
                .paths
                .iter()
                .filter(|(_, p)| p.mp_path_status_pending)
                .map(|(i, p)| {
                    (i, p.path_id, p.app_status, p.mp_path_status_seq_num)
                })
                .collect();

            for (pid, mp_path_id, status, seq_num) in status_paths {
                let frame = match status {
                    path::PathAppStatus::Available =>
                        frame::Frame::PathStatusAvailable {
                            path_id: mp_path_id,
                            seq_num,
                        },
                    path::PathAppStatus::Backup =>
                        frame::Frame::PathStatusBackup {
                            path_id: mp_path_id,
                            seq_num,
                        },
                };

                if push_frame_to_pkt!(b, frames, frame, left) {
                    self.paths.get_mut(pid).unwrap().mp_path_status_pending =
                        false;
                    ack_eliciting = true;
                    in_flight = true;
                }
            }

            // Generate PATHS_BLOCKED / PATH_CIDS_BLOCKED frames if a path
            // opening attempt was blocked (draft-ietf-quic-multipath-21,
            // Section 3.2.1). One-shot: the pending flag is cleared once
            // the frame is built, and re-armed on loss only if the
            // blocking condition still holds.
            if let Some(max_path_id) = self.mp_paths_blocked_pending {
                let frame = frame::Frame::PathsBlocked {
                    path_id: max_path_id,
                };

                if push_frame_to_pkt!(b, frames, frame, left) {
                    self.mp_paths_blocked_pending = None;
                    ack_eliciting = true;
                    in_flight = true;
                }
            }

            if let Some((mp_path_id, seq_num)) = self.mp_path_cids_blocked_pending
            {
                let frame = frame::Frame::PathCidsBlocked {
                    path_id: mp_path_id,
                    seq_num,
                };

                if push_frame_to_pkt!(b, frames, frame, left) {
                    self.mp_path_cids_blocked_pending = None;
                    ack_eliciting = true;
                    in_flight = true;
                }
            }

            // Generate a MAX_PATH_ID frame if the application raised the
            // local maximum path ID limit (draft-ietf-quic-multipath-21,
            // Section 4.6). One-shot: the pending flag is cleared once
            // the frame is built, and re-armed on loss only when no more
            // recent MAX_PATH_ID frame was sent in the meantime.
            if let Some(mp_max_path_id) = self.mp_max_path_id_pending {
                let frame = frame::Frame::MaxPathId {
                    path_id: mp_max_path_id,
                };

                if push_frame_to_pkt!(b, frames, frame, left) {
                    self.mp_max_path_id_pending = None;

                    // The pending value can only grow, so the frame just
                    // built always carries the most recent value.
                    self.mp_max_path_id_sent = Some(mp_max_path_id);
                    self.mp_max_path_id_acked = false;

                    ack_eliciting = true;
                    in_flight = true;
                }
            }
        }

        // Limit output packet size by congestion window size.
        left = cmp::min(
            left,
            // Bytes consumed by ACK frames.
            cwnd_available.saturating_sub(left_before_packing_ack_frame - left),
        );

        let mut challenge_data = None;

        if pkt_type == Type::Short {
            // Create PMTUD probe.
            //
            // In order to send a PMTUD probe the current `left` value, which was
            // already limited by the current PMTU measure, needs to be ignored,
            // but the outgoing packet still needs to be limited by
            // the output buffer size, as well as the congestion
            // window.
            //
            // In addition, the PMTUD probe is only generated when the handshake
            // is confirmed, to avoid interfering with the handshake
            // (e.g. due to the anti-amplification limits).
            if let Ok(active_path) = self.paths.get_active_mut() {
                let should_probe_pmtu = active_path.should_send_pmtu_probe(
                    self.handshake_confirmed,
                    self.handshake_completed,
                    out_len,
                    is_closing,
                    frames.is_empty(),
                );

                if should_probe_pmtu {
                    if let Some(pmtud) = active_path.pmtud.as_mut() {
                        let probe_size = pmtud.get_probe_size();
                        trace!(
                        "{} sending pmtud probe pmtu_probe={} estimated_pmtu={}",
                        self.trace_id,
                        probe_size,
                        pmtud.get_current_mtu(),
                    );

                        left = probe_size;

                        match left.checked_sub(overhead) {
                            Some(v) => left = v,

                            None => {
                                // We can't send more because there isn't enough
                                // space available in the output buffer.
                                //
                                // This usually happens when we try to send a new
                                // packet but failed because cwnd is almost full.
                                //
                                // In such case app_limited is set to false here
                                // to make cwnd grow when ACK is received.
                                active_path.recovery.update_app_limited(false);
                                return Err(Error::Done);
                            },
                        }

                        let frame = frame::Frame::Padding {
                            len: probe_size - overhead - 1,
                        };

                        if push_frame_to_pkt!(b, frames, frame, left) {
                            let frame = frame::Frame::Ping {
                                mtu_probe: Some(probe_size),
                            };

                            if push_frame_to_pkt!(b, frames, frame, left) {
                                ack_eliciting = true;
                                in_flight = true;
                            }
                        }

                        // Reset probe flag after sending to prevent duplicate
                        // probes in a single flight.
                        pmtud.set_in_flight(true);
                        is_pmtud_probe = true;
                    }
                }
            }

            let path = self.paths.get_mut(send_pid)?;
            // Create PATH_RESPONSE frame if needed.
            // We do not try to ensure that these are really sent.
            while let Some(challenge) = path.pop_received_challenge() {
                let frame = frame::Frame::PathResponse { data: challenge };

                if push_frame_to_pkt!(b, frames, frame, left) {
                    ack_eliciting = true;
                    in_flight = true;
                } else {
                    // If there are other pending PATH_RESPONSE, don't lose them
                    // now.
                    break;
                }
            }

            // Create PATH_CHALLENGE frame if needed.
            if path.validation_requested() {
                // TODO: ensure that data is unique over paths.
                let data = rand::rand_u64().to_be_bytes();

                let frame = frame::Frame::PathChallenge { data };

                if push_frame_to_pkt!(b, frames, frame, left) {
                    // Let's notify the path once we know the packet size.
                    challenge_data = Some(data);

                    ack_eliciting = true;
                    in_flight = true;
                }
            }

            if let Some(key_update) = crypto_ctx.key_update.as_mut() {
                key_update.update_acked = true;
            }
        }

        let path = self.paths.get_mut(send_pid)?;

        if pkt_type == Type::Short && !is_closing {
            // Create NEW_CONNECTION_ID frames as needed.
            while let Some(seq_num) = self.ids.next_advertise_new_scid_seq() {
                let frame = self.ids.get_new_connection_id_frame_for(seq_num)?;

                if push_frame_to_pkt!(b, frames, frame, left) {
                    self.ids.mark_advertise_new_scid_seq(seq_num, false);

                    ack_eliciting = true;
                    in_flight = true;
                } else {
                    break;
                }
            }

            // Create PATH_NEW_CONNECTION_ID frames as needed
            // (draft-ietf-quic-multipath-21, Section 4.4).
            #[cfg(feature = "multipath")]
            if self.multipath_enabled {
                while let Some((mp_path_id, seq_num)) =
                    self.ids.mp_next_advertise_new_scid()
                {
                    let frame =
                        self.ids.mp_get_path_new_connection_id_frame_for(
                            mp_path_id, seq_num,
                        )?;

                    if push_frame_to_pkt!(b, frames, frame, left) {
                        self.ids.mp_mark_advertise_new_scid(
                            mp_path_id, seq_num, false,
                        );

                        ack_eliciting = true;
                        in_flight = true;
                    } else {
                        break;
                    }
                }
            }
        }

        // HANDSHAKE_DONE must only go on the active migration path.
        if pkt_type == Type::Short && !is_closing && path.active() {
            // Create HANDSHAKE_DONE frame.
            // self.should_send_handshake_done() but without the need to borrow
            if self.handshake_completed &&
                !self.handshake_done_sent &&
                self.is_server
            {
                let frame = frame::Frame::HandshakeDone;

                if push_frame_to_pkt!(b, frames, frame, left) {
                    self.handshake_done_sent = true;

                    ack_eliciting = true;
                    in_flight = true;
                }
            }
        }

        // Flow-control and stream-management frames can go on any
        // sendable path.
        if pkt_type == Type::Short && !is_closing && path.can_send(mp) {
            // Create MAX_STREAMS_BIDI frame.
            if self.streams.should_update_max_streams_bidi() ||
                self.should_send_max_streams_bidi
            {
                let frame = frame::Frame::MaxStreamsBidi {
                    max: self.streams.max_streams_bidi_next(),
                };

                if push_frame_to_pkt!(b, frames, frame, left) {
                    self.streams.update_max_streams_bidi();
                    self.should_send_max_streams_bidi = false;

                    ack_eliciting = true;
                    in_flight = true;
                }
            }

            // Create MAX_STREAMS_UNI frame.
            if self.streams.should_update_max_streams_uni() ||
                self.should_send_max_streams_uni
            {
                let frame = frame::Frame::MaxStreamsUni {
                    max: self.streams.max_streams_uni_next(),
                };

                if push_frame_to_pkt!(b, frames, frame, left) {
                    self.streams.update_max_streams_uni();
                    self.should_send_max_streams_uni = false;

                    ack_eliciting = true;
                    in_flight = true;
                }
            }

            // Create DATA_BLOCKED frame.
            if let Some(limit) = self.blocked_limit {
                let frame = frame::Frame::DataBlocked { limit };

                if push_frame_to_pkt!(b, frames, frame, left) {
                    self.blocked_limit = None;
                    self.data_blocked_sent_count =
                        self.data_blocked_sent_count.saturating_add(1);

                    ack_eliciting = true;
                    in_flight = true;
                }
            }

            // Create MAX_STREAM_DATA frames as needed.
            for stream_id in self.streams.almost_full() {
                let stream = match self.streams.get_mut(stream_id) {
                    Some(v) => v,

                    None => {
                        // The stream doesn't exist anymore, so remove it from
                        // the almost full set.
                        self.streams.remove_almost_full(stream_id);
                        continue;
                    },
                };

                // Autotune the stream window size, but only if this is not a
                // retransmission (on a retransmit the stream will be in
                // `self.streams.almost_full()` but it's `almost_full()`
                // method returns false.
                if stream.recv.almost_full() {
                    stream.recv.autotune_window(now, path.recovery.rtt());
                }

                let frame = frame::Frame::MaxStreamData {
                    stream_id,
                    max: stream.recv.max_data_next(),
                };

                if push_frame_to_pkt!(b, frames, frame, left) {
                    let recv_win = stream.recv.window();

                    stream.recv.update_max_data(now);

                    self.streams.remove_almost_full(stream_id);

                    ack_eliciting = true;
                    in_flight = true;

                    // Make sure the connection window always has some
                    // room compared to the stream window.
                    flow_control.ensure_window_lower_bound(
                        (recv_win as f64 * CONNECTION_WINDOW_FACTOR) as u64,
                    );
                }
            }

            // Create MAX_DATA frame as needed.
            if flow_control.should_update_max_data() &&
                flow_control.max_data() < flow_control.max_data_next()
            {
                // Autotune the connection window size. We only tune the window
                // if we are sending an "organic" update, not on retransmits.
                flow_control.autotune_window(now, path.recovery.rtt());
                self.should_send_max_data = true;
            }

            if self.should_send_max_data {
                let frame = frame::Frame::MaxData {
                    max: flow_control.max_data_next(),
                };

                if push_frame_to_pkt!(b, frames, frame, left) {
                    self.should_send_max_data = false;

                    // Commits the new max_rx_data limit.
                    flow_control.update_max_data(now);

                    ack_eliciting = true;
                    in_flight = true;
                }
            }

            // Create STOP_SENDING frames as needed.
            for (stream_id, error_code) in self
                .streams
                .stopped()
                .map(|(&k, &v)| (k, v))
                .collect::<Vec<(u64, u64)>>()
            {
                let frame = frame::Frame::StopSending {
                    stream_id,
                    error_code,
                };

                if push_frame_to_pkt!(b, frames, frame, left) {
                    self.streams.remove_stopped(stream_id);

                    ack_eliciting = true;
                    in_flight = true;
                }
            }

            // Create RESET_STREAM frames as needed.
            for (stream_id, (error_code, final_size)) in self
                .streams
                .reset()
                .map(|(&k, &v)| (k, v))
                .collect::<Vec<(u64, (u64, u64))>>()
            {
                let frame = frame::Frame::ResetStream {
                    stream_id,
                    error_code,
                    final_size,
                };

                if push_frame_to_pkt!(b, frames, frame, left) {
                    self.streams.remove_reset(stream_id);

                    ack_eliciting = true;
                    in_flight = true;
                }
            }

            // Create STREAM_DATA_BLOCKED frames as needed.
            for (stream_id, limit) in self
                .streams
                .blocked()
                .map(|(&k, &v)| (k, v))
                .collect::<Vec<(u64, u64)>>()
            {
                let frame = frame::Frame::StreamDataBlocked { stream_id, limit };

                if push_frame_to_pkt!(b, frames, frame, left) {
                    self.streams.remove_blocked(stream_id);
                    self.stream_data_blocked_sent_count =
                        self.stream_data_blocked_sent_count.saturating_add(1);

                    ack_eliciting = true;
                    in_flight = true;
                }
            }

            // Create RETIRE_CONNECTION_ID frames as needed.
            let retire_dcid_seqs = self.ids.retire_dcid_seqs();

            for seq_num in retire_dcid_seqs {
                // The sequence number specified in a RETIRE_CONNECTION_ID frame
                // MUST NOT refer to the Destination Connection ID field of the
                // packet in which the frame is contained. Paths that consumed
                // a per-path CID (draft-21 §3.1) carry a DCID from their path
                // ID's own pool, which can never collide with a legacy
                // sequence number.
                #[cfg(feature = "multipath")]
                let check_collision = !path.mp_per_path_cids;
                #[cfg(not(feature = "multipath"))]
                let check_collision = true;

                if check_collision {
                    let dcid_seq =
                        path.active_dcid_seq.ok_or(Error::InvalidState)?;

                    if seq_num == dcid_seq {
                        continue;
                    }
                }

                let frame = frame::Frame::RetireConnectionId { seq_num };

                if push_frame_to_pkt!(b, frames, frame, left) {
                    self.ids.mark_retire_dcid_seq(seq_num, false)?;

                    ack_eliciting = true;
                    in_flight = true;
                } else {
                    break;
                }
            }

            // Create PATH_RETIRE_CONNECTION_ID frames as needed
            // (draft-ietf-quic-multipath-21, Section 4.5).
            #[cfg(feature = "multipath")]
            if self.multipath_enabled {
                let mp_retire_dcid_seqs = self.ids.mp_retire_dcid_seqs();

                for (mp_path_id, seq_num) in mp_retire_dcid_seqs {
                    // Like RETIRE_CONNECTION_ID, the sequence number MUST
                    // NOT refer to the Destination Connection ID of the
                    // packet in which the frame is contained. The carrying
                    // packet's DCID comes from the sending path's pool: the
                    // legacy pool (path ID 0), unless the path consumed a
                    // per-path CID (draft-21 §3.1).
                    let carrying_path_id = if path.mp_per_path_cids {
                        path.path_id
                    } else {
                        0
                    };

                    if mp_path_id == carrying_path_id {
                        let dcid_seq =
                            path.active_dcid_seq.ok_or(Error::InvalidState)?;

                        if seq_num == dcid_seq {
                            continue;
                        }
                    }

                    let frame = frame::Frame::PathRetireConnectionId {
                        path_id: mp_path_id,
                        seq_num,
                    };

                    if push_frame_to_pkt!(b, frames, frame, left) {
                        self.ids
                            .mp_mark_retire_dcid(mp_path_id, seq_num, false)?;

                        ack_eliciting = true;
                        in_flight = true;
                    } else {
                        break;
                    }
                }
            }
        }

        // Create CONNECTION_CLOSE frame. Try to send this only on the active
        // path, unless it is the last one available.
        if path.active() || n_paths == 1 {
            if let Some(conn_err) = self.local_error.as_ref() {
                if conn_err.is_app {
                    // Create ApplicationClose frame.
                    if pkt_type == Type::Short {
                        let frame = frame::Frame::ApplicationClose {
                            error_code: conn_err.error_code,
                            reason: conn_err.reason.clone(),
                        };

                        if push_frame_to_pkt!(b, frames, frame, left) {
                            let pto = mp_closing_pto
                                .unwrap_or_else(|| path.recovery.pto());
                            self.draining_timer = Some(now + (pto * 3));

                            ack_eliciting = true;
                            in_flight = true;
                        }
                    }
                } else {
                    // Create ConnectionClose frame.
                    let frame = frame::Frame::ConnectionClose {
                        error_code: conn_err.error_code,
                        frame_type: 0,
                        reason: conn_err.reason.clone(),
                    };

                    if push_frame_to_pkt!(b, frames, frame, left) {
                        let pto = mp_closing_pto
                            .unwrap_or_else(|| path.recovery.pto());
                        self.draining_timer = Some(now + (pto * 3));

                        ack_eliciting = true;
                        in_flight = true;
                    }
                }
            }
        }

        // Create CRYPTO frame.
        if crypto_ctx.crypto_stream.is_flushable() &&
            left > frame::MAX_CRYPTO_OVERHEAD &&
            !is_closing &&
            path.active()
        {
            let crypto_off = crypto_ctx.crypto_stream.send.off_front();

            // Encode the frame.
            //
            // Instead of creating a `frame::Frame` object, encode the frame
            // directly into the packet buffer.
            //
            // First we reserve some space in the output buffer for writing the
            // frame header (we assume the length field is always a 2-byte
            // varint as we don't know the value yet).
            //
            // Then we emit the data from the crypto stream's send buffer.
            //
            // Finally we go back and encode the frame header with the now
            // available information.
            let hdr_off = b.off();
            let hdr_len = 1 + // frame type
                octets::varint_len(crypto_off) + // offset
                2; // length, always encode as 2-byte varint

            if let Some(max_len) = left.checked_sub(hdr_len) {
                let (mut crypto_hdr, mut crypto_payload) =
                    b.split_at(hdr_off + hdr_len)?;

                // Write stream data into the packet buffer.
                let (len, _) = crypto_ctx
                    .crypto_stream
                    .send
                    .emit(&mut crypto_payload.as_mut()[..max_len])?;

                // Encode the frame's header.
                //
                // Due to how `OctetsMut::split_at()` works, `crypto_hdr` starts
                // from the initial offset of `b` (rather than the current
                // offset), so it needs to be advanced to the
                // initial frame offset.
                crypto_hdr.skip(hdr_off)?;

                frame::encode_crypto_header(
                    crypto_off,
                    len as u64,
                    &mut crypto_hdr,
                )?;

                // Advance the packet buffer's offset.
                b.skip(hdr_len + len)?;

                let frame = frame::Frame::CryptoHeader {
                    offset: crypto_off,
                    length: len,
                };

                if push_frame_to_pkt!(b, frames, frame, left) {
                    ack_eliciting = true;
                    in_flight = true;
                    has_data = true;
                }
            }
        }

        // The preference of data-bearing frame to include in a packet
        // is managed by `self.emit_dgram`. However, whether any frames
        // can be sent depends on the state of their buffers. In the case
        // where one type is preferred but its buffer is empty, fall back
        // to the other type in order not to waste this function call.
        let mut dgram_emitted = false;
        let dgrams_to_emit = max_dgram_len.is_some();
        let stream_to_emit = self.streams.has_flushable();

        let mut do_dgram = self.emit_dgram && dgrams_to_emit;
        let do_stream = !self.emit_dgram && stream_to_emit;

        if !do_stream && dgrams_to_emit {
            do_dgram = true;
        }

        // Create DATAGRAM frame.
        if (pkt_type == Type::Short || pkt_type == Type::ZeroRTT) &&
            left > frame::MAX_DGRAM_OVERHEAD &&
            !is_closing &&
            path.can_send(mp) &&
            do_dgram
        {
            if let Some(max_dgram_payload) = max_dgram_len {
                while let Some(len) = self.dgram_send_queue.peek_front_len() {
                    let hdr_off = b.off();
                    let hdr_len = 1 + // frame type
                        2; // length, always encode as 2-byte varint

                    if (hdr_len + len) <= left {
                        // Front of the queue fits this packet, send it.
                        match self.dgram_send_queue.pop() {
                            Some(data) => {
                                // Encode the frame.
                                //
                                // Instead of creating a `frame::Frame` object,
                                // encode the frame directly into the packet
                                // buffer.
                                //
                                // First we reserve some space in the output
                                // buffer for writing the frame header (we
                                // assume the length field is always a 2-byte
                                // varint as we don't know the value yet).
                                //
                                // Then we emit the data from the DATAGRAM's
                                // buffer.
                                //
                                // Finally we go back and encode the frame
                                // header with the now available information.
                                let (mut dgram_hdr, mut dgram_payload) =
                                    b.split_at(hdr_off + hdr_len)?;

                                dgram_payload.as_mut()[..len]
                                    .copy_from_slice(&data);

                                // Encode the frame's header.
                                //
                                // Due to how `OctetsMut::split_at()` works,
                                // `dgram_hdr` starts from the initial offset
                                // of `b` (rather than the current offset), so
                                // it needs to be advanced to the initial frame
                                // offset.
                                dgram_hdr.skip(hdr_off)?;

                                frame::encode_dgram_header(
                                    len as u64,
                                    &mut dgram_hdr,
                                )?;

                                // Advance the packet buffer's offset.
                                b.skip(hdr_len + len)?;

                                let frame =
                                    frame::Frame::DatagramHeader { length: len };

                                if push_frame_to_pkt!(b, frames, frame, left) {
                                    ack_eliciting = true;
                                    in_flight = true;
                                    dgram_emitted = true;
                                    self.dgram_sent_count =
                                        self.dgram_sent_count.saturating_add(1);
                                    path.dgram_sent_count =
                                        path.dgram_sent_count.saturating_add(1);
                                }
                            },

                            None => continue,
                        };
                    } else if len > max_dgram_payload {
                        // This dgram frame will never fit. Let's purge it.
                        self.dgram_send_queue.pop();
                    } else {
                        break;
                    }
                }
            }
        }

        // Create a single STREAM frame for the first stream that is flushable.
        //
        if (pkt_type == Type::Short || pkt_type == Type::ZeroRTT) &&
            left > frame::MAX_STREAM_OVERHEAD &&
            !is_closing &&
            path.can_send(mp) &&
            !dgram_emitted
        {
            while let Some(priority_key) = self.streams.peek_flushable() {
                let stream_id = priority_key.id;
                let stream = match self.streams.get_mut(stream_id) {
                    // Avoid sending frames for streams that were already stopped.
                    //
                    // This might happen if stream data was buffered but not yet
                    // flushed on the wire when a STOP_SENDING frame is received.
                    Some(v) if !v.send.is_stopped() => v,
                    _ => {
                        self.streams.remove_flushable(&priority_key);
                        continue;
                    },
                };

                let stream_off = stream.send.off_front();

                // Encode the frame.
                //
                // Instead of creating a `frame::Frame` object, encode the frame
                // directly into the packet buffer.
                //
                // First we reserve some space in the output buffer for writing
                // the frame header (we assume the length field is always a
                // 2-byte varint as we don't know the value yet).
                //
                // Then we emit the data from the stream's send buffer.
                //
                // Finally we go back and encode the frame header with the now
                // available information.
                let hdr_off = b.off();
                let hdr_len = 1 + // frame type
                    octets::varint_len(stream_id) + // stream_id
                    octets::varint_len(stream_off) + // offset
                    2; // length, always encode as 2-byte varint

                let max_len = match left.checked_sub(hdr_len) {
                    Some(v) => v,
                    None => {
                        let priority_key = Arc::clone(&stream.priority_key);
                        self.streams.remove_flushable(&priority_key);

                        continue;
                    },
                };

                let (mut stream_hdr, mut stream_payload) =
                    b.split_at(hdr_off + hdr_len)?;

                // Write stream data into the packet buffer.
                let (len, fin) =
                    stream.send.emit(&mut stream_payload.as_mut()[..max_len])?;

                // Encode the frame's header.
                //
                // Due to how `OctetsMut::split_at()` works, `stream_hdr` starts
                // from the initial offset of `b` (rather than the current
                // offset), so it needs to be advanced to the initial frame
                // offset.
                stream_hdr.skip(hdr_off)?;

                frame::encode_stream_header(
                    stream_id,
                    stream_off,
                    len as u64,
                    fin,
                    &mut stream_hdr,
                )?;

                // Advance the packet buffer's offset.
                b.skip(hdr_len + len)?;

                let frame = frame::Frame::StreamHeader {
                    stream_id,
                    offset: stream_off,
                    length: len,
                    fin,
                };

                if push_frame_to_pkt!(b, frames, frame, left) {
                    ack_eliciting = true;
                    in_flight = true;
                    has_data = true;
                }

                let priority_key = Arc::clone(&stream.priority_key);
                // If the stream is no longer flushable, remove it from the queue
                if !stream.is_flushable() {
                    self.streams.remove_flushable(&priority_key);
                } else if stream.incremental {
                    // Shuffle the incremental stream to the back of the
                    // queue.
                    self.streams.remove_flushable(&priority_key);
                    self.streams.insert_flushable(&priority_key);
                }

                #[cfg(feature = "fuzzing")]
                // Coalesce STREAM frames when fuzzing.
                if left > frame::MAX_STREAM_OVERHEAD {
                    continue;
                }

                break;
            }
        }

        // Alternate trying to send DATAGRAMs next time.
        self.emit_dgram = !dgram_emitted;

        // If no other ack-eliciting frame is sent, include a PING frame
        // - if PTO probe needed; OR
        // - if we've sent too many non ack-eliciting packets without having
        // sent an ACK eliciting one; OR
        // - the application requested an ack-eliciting frame be sent.
        if (ack_elicit_required || path.needs_ack_eliciting) &&
            !ack_eliciting &&
            left >= 1 &&
            !is_closing
        {
            let frame = frame::Frame::Ping { mtu_probe: None };

            if push_frame_to_pkt!(b, frames, frame, left) {
                ack_eliciting = true;
                in_flight = true;
            }
        }

        if ack_eliciting && !is_pmtud_probe {
            path.needs_ack_eliciting = false;
            path.recovery.ping_sent(epoch);
        }

        if !has_data &&
            !dgram_emitted &&
            cwnd_available > frame::MAX_STREAM_OVERHEAD
        {
            path.recovery.on_app_limited();
        }

        if frames.is_empty() {
            // When we reach this point we are not able to write more, so set
            // app_limited to false.
            path.recovery.update_app_limited(false);
            return Err(Error::Done);
        }

        // When coalescing a 1-RTT packet, we can't add padding in the UDP
        // datagram, so use PADDING frames instead.
        //
        // This is only needed if
        // 1) an Initial packet has already been written to the UDP datagram,
        // as Initial always requires padding.
        //
        // 2) this is a probing packet towards an unvalidated peer address.
        if (has_initial || !path.validated()) &&
            pkt_type == Type::Short &&
            left >= 1
        {
            let frame = frame::Frame::Padding { len: left };

            if push_frame_to_pkt!(b, frames, frame, left) {
                in_flight = true;
            }
        }

        // Pad payload so that it's always at least 4 bytes.
        if b.off() - payload_offset < PAYLOAD_MIN_LEN {
            let payload_len = b.off() - payload_offset;

            let frame = frame::Frame::Padding {
                len: PAYLOAD_MIN_LEN - payload_len,
            };

            #[allow(unused_assignments)]
            if push_frame_to_pkt!(b, frames, frame, left) {
                in_flight = true;
            }
        }

        let payload_len = b.off() - payload_offset;

        // Fill in payload length.
        if pkt_type != Type::Short {
            let len = pn_len + payload_len + crypto_overhead;

            let (_, mut payload_with_len) = b.split_at(header_offset)?;
            payload_with_len
                .put_varint_with_len(len as u64, PAYLOAD_LENGTH_LEN)?;
        }

        trace!(
            "{} tx pkt {} len={} pn={} {}",
            self.trace_id,
            hdr_trace.unwrap_or_default(),
            payload_len,
            pn,
            AddrTupleFmt(path.local_addr(), path.peer_addr())
        );

        #[cfg(feature = "qlog")]
        let mut qlog_frames: SmallVec<
            [qlog::events::quic::QuicFrame; 1],
        > = SmallVec::with_capacity(frames.len());

        for frame in &mut frames {
            trace!("{} tx frm {:?}", self.trace_id, frame);

            qlog_with_type!(QLOG_PACKET_TX, self.qlog, _q, {
                qlog_frames.push(frame.to_qlog());
            });
        }

        qlog_with_type!(QLOG_PACKET_TX, self.qlog, q, {
            if let Some(header) = qlog_pkt_hdr {
                // Qlog packet raw info described at
                // https://datatracker.ietf.org/doc/html/draft-ietf-quic-qlog-main-schema-00#section-5.1
                //
                // `length` includes packet headers and trailers (AEAD tag).
                let length = payload_len + payload_offset + crypto_overhead;
                let qlog_raw_info = RawInfo {
                    length: Some(length as u64),
                    payload_length: Some(payload_len as u64),
                    data: None,
                };

                let send_at_time =
                    now.duration_since(q.start_time()).as_secs_f64() * 1000.0;

                let ev_data =
                    EventData::PacketSent(qlog::events::quic::PacketSent {
                        header,
                        frames: Some(qlog_frames),
                        raw: Some(qlog_raw_info),
                        send_at_time: Some(send_at_time),
                        ..Default::default()
                    });

                q.add_event_data_with_instant(ev_data, now).ok();
            }
        });

        let aead = match crypto_ctx.crypto_seal {
            Some(ref mut v) => v,
            None => return Err(Error::InvalidState),
        };

        #[cfg(feature = "multipath")]
        let written = if use_per_path_pn {
            packet::encrypt_pkt_mp(
                &mut b,
                pn,
                path.path_id as u32,
                pn_len,
                payload_len,
                payload_offset,
                None,
                aead,
            )?
        } else {
            packet::encrypt_pkt(
                &mut b,
                pn,
                pn_len,
                payload_len,
                payload_offset,
                None,
                aead,
            )?
        };

        #[cfg(not(feature = "multipath"))]
        let written = packet::encrypt_pkt(
            &mut b,
            pn,
            pn_len,
            payload_len,
            payload_offset,
            None,
            aead,
        )?;

        let sent_pkt_has_data = if path.recovery.gcongestion_enabled() {
            has_data || dgram_emitted
        } else {
            has_data
        };

        let sent_pkt = recovery::Sent {
            pkt_num: pn,
            frames,
            time_sent: now,
            time_acked: None,
            time_lost: None,
            size: if ack_eliciting { written } else { 0 },
            ack_eliciting,
            in_flight,
            delivered: 0,
            delivered_time: now,
            first_sent_time: now,
            is_app_limited: false,
            tx_in_flight: 0,
            lost: 0,
            has_data: sent_pkt_has_data,
            is_pmtud_probe,
        };

        if in_flight && is_app_limited {
            path.recovery.delivery_rate_update_app_limited(true);
        }

        // Only advance the shared packet number counter when we are NOT using
        // the per-path counter (which was already incremented above).
        if !use_per_path_pn {
            self.next_pkt_num += 1;
        }

        let handshake_status = recovery::HandshakeStatus {
            has_handshake_keys: self.crypto_ctx[packet::Epoch::Handshake]
                .has_keys(),
            peer_verified_address: self.peer_verified_initial_address,
            completed: self.handshake_completed,
        };

        self.on_packet_sent(send_pid, sent_pkt, epoch, handshake_status, now)?;

        let path = self.paths.get_mut(send_pid)?;
        qlog_with_type!(QLOG_METRICS, self.qlog, q, {
            path.recovery.maybe_qlog(q, now);
        });

        // Record sent packet size if we probe the path.
        if let Some(data) = challenge_data {
            path.add_challenge_sent(data, written, now);
        }

        self.sent_count += 1;
        self.sent_bytes += written as u64;
        path.sent_count += 1;
        path.sent_bytes += written as u64;

        if self.dgram_send_queue.byte_size() > path.recovery.cwnd_available() {
            path.recovery.update_app_limited(false);
        }

        path.max_send_bytes = path.max_send_bytes.saturating_sub(written);

        // On the client, drop initial state after sending an Handshake packet.
        if !self.is_server && hdr_ty == Type::Handshake {
            self.drop_epoch_state(packet::Epoch::Initial, now);
        }

        // (Re)start the idle timer if we are sending the first ack-eliciting
        // packet since last receiving a packet.
        if ack_eliciting && !self.ack_eliciting_sent {
            if let Some(idle_timeout) = self.idle_timeout() {
                self.idle_timer = Some(now + idle_timeout);
            }
        }

        if ack_eliciting {
            self.ack_eliciting_sent = true;
        }

        Ok((pkt_type, written))
    }

}
