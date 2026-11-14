# P2P Protocol

## P2P Messages

#### WARNING: This document is still in progress and has not yet been reviewed by any of the core Mwc developers.

* All fields are serialized in Big-Endian byte order unless otherwise specified.
* Variable-length strings (VAR_STR) are encoded in UTF8, and are preceded with a uint64 indicating their lengths.

### Message Types

The current message IDs in `p2p/src/msg.rs::Type` are below. Gaps are intentional; do not renumber messages. `TorAddress` is reserved and unused.

| ID | Message |
| --- | --- |
| 0 | `Error` |
| 1 | `Hand` |
| 2 | `Shake` |
| 3 | `Ping` |
| 4 | `Pong` |
| 5 | `GetPeerAddrs` |
| 6 | `PeerAddrs` |
| 7 | `GetHeaders` |
| 8 | `Header` |
| 9 | `Headers` |
| 10 | `GetBlock` |
| 11 | `Block` |
| 12 | `GetCompactBlock` |
| 13 | `CompactBlock` |
| 14 | `StemTransaction` |
| 15 | `Transaction` |
| 16 | `TxHashSetRequest` |
| 17 | `TxHashSetArchive` |
| 18 | `BanReason` |
| 19 | `GetTransaction` |
| 20 | `TransactionKernel` |
| 23 | `TorAddress` |
| 24 | `StartPibdSyncRequest` |
| 25 | `GetOutputBitmapSegment` |
| 26 | `OutputBitmapSegment` |
| 27 | `GetOutputSegment` |
| 28 | `OutputSegment` |
| 29 | `GetRangeProofSegment` |
| 30 | `RangeProofSegment` |
| 31 | `GetKernelSegment` |
| 32 | `KernelSegment` |
| 33 | `HasAnotherArchiveHeader` |
| 34 | `PibdSyncState` |
| 35 | `StartHeadersHashRequest` |
| 36 | `StartHeadersHashResponse` |
| 37 | `GetHeadersHashesSegment` |
| 38 | `OutputHeadersHashesSegment` |

The layouts for message IDs 19, 20 and 23–38, and their shared segment structures, follow the current serializers in [p2p/src/msg.rs](../../p2p/src/msg.rs). The older message layouts remain an early protocol draft and omit some current capability/version-dependent fields, including onion proofs and coinbase-binding openings. Use the Rust `Writeable`/`Readable` implementations and negotiated protocol version for wire compatibility.

### Message structure

All P2P messages follow a generic message structure as follows.

| Size | Name    | Data Type       | Description/Comments                                                              |
|------|---------|-----------------|-----------------------------------------------------------------------------------|
| 2    | Magic   | uint8[2]        | Magic number used to identify Mwc packets. Mainnet `{0x0D, 0x4D}`, Floonet `{0x11, 0x24}`, other/test contexts `{0x15, 0x13}`.    |
| 1    | Type    | MessageTypeEnum | Identifier of the packet content.                                                 |
| 8    | Length  | uint64          | The total length of the message. This will not include the header size (11 bytes).|
| ?    | Payload | uint8[]         | The actual data.                                                                  |

TODO: Provide example

### Common structures

##### SocketAddress

| Size | Name            | Data Type          | Description/Comments                                        |
|------|-----------------|--------------------|-------------------------------------------------------------|
| 1    | IPAddressFamily | uint8              | Identifies the IP address family. 0 = IPv4, 1 = IPv6.       |
| 4/16 | IPAddress       | uint8[4]/uint16[8] | The IP address. 4 octets for IPv4 or 8 hexadecets for IPv6. |
| 2    | Port            | uint16             | The TCP/IP port number.                                     |

##### CapabilitiesMask

| Value | Name              | Description                                                                |
|-------|-------------------|----------------------------------------------------------------------------|
| 0x00  | Unknown           | We don't know (yet) what the peer can do.                                  |
| 0x01  | Full History      | Full archival node, has the whole history without any pruning.             |
| 0x02  | TxHashSet History | Can provide block headers and the TxHashSet for some recent-enough height. |
| 0x04  | Peer List         | Can provide a list of healthy peers.                                       |
| 0x06  | Fast Sync Node    | Both "TxHashSet History" and "Peer List"                                   |
| 0x07  | Full Node         | "Full History", "TxHashSet History", and "Peer List"                       |

##### TransactionBody

| Size | Name    | Data Type  | Description/Comments                                                     |
|------|---------|------------|--------------------------------------------------------------------------|
| ?    | Inputs  | TxInput[]  | List of inputs spent by the transaction.                                 |
| ?    | Outputs | TxOutput[] | List of outputs the transaction produces.                                |
| ?    | Kernels | TxKernel[] | List of kernels that make up this transaction (usually a single kernel). |

##### CompactBlockBody

| Size | Name        | Data Type  | Description/Comments                                                                    |
|------|-------------|------------|-----------------------------------------------------------------------------------------|
| ?    | FullOutputs | TxOutput[] | List of full outputs - specifically the coinbase output(s).                             |
| ?    | FullKernels | TxKernel[] | List of full kernels - specifically the coinbase kernel(s).                             |
| ?    | KernelIds   | ShortId[]  | List of transaction kernels, excluding those in the full list. Each ShortId is 6 bytes. |

##### TxInput

##### TxOutput

##### TxKernel

Used as the leaf type in `KernelSegment`. Fields are serialized in the following order; feature data depends on the negotiated protocol version.

| Size | Name | Data Type | Description/Comments |
|------|------|-----------|----------------------|
| 1 | Features | uint8 | `0` = Plain, `1` = Coinbase, `2` = HeightLocked, `3` = NoRecentDuplicate. |
| ? | FeatureData | uint8[] | Variant-specific fields described below. |
| 33 | Excess | Commitment | Pedersen commitment to the kernel excess. |
| 64 | ExcessSignature | uint8[64] | Aggregate signature in the binary consensus format (`R.x` followed by `s`). |

For protocol version 2 and later, `FeatureData` contains:

| Features | Size | Fields in wire order |
|----------|------|----------------------|
| Plain | 8 | Fee (`uint64`). |
| Coinbase | 0 | No additional fields. |
| HeightLocked | 16 | Fee (`uint64`), LockHeight (`uint64`). |
| NoRecentDuplicate | 10 | Fee (`uint64`), RelativeHeight (`uint16`). Requires NRD to be enabled. |

For protocol versions 0–1, `FeatureData` always occupies 16 bytes: an 8-byte fee followed by 8 bytes of height data. Coinbase uses zeroes for both fields; Plain uses zeroes for height data; HeightLocked uses a `uint64` height; NoRecentDuplicate uses six zero bytes followed by its `uint16` relative height. Kernel hashing also uses this fixed-width feature encoding. See [KernelFeatures and TxKernel](../../core/src/core/transaction.rs) and the [signature serializer](../../core/src/ser.rs).

##### ProofOfWork

| Size | Name              | Data Type  | Description/Comments                                            |
|------|-------------------|------------|-----------------------------------------------------------------|
| 8    | TotalDifficulty   | uint64     | Total accumulated difficulty since genesis block.               |
| 4    | ScalingDifficulty | uint32     | Difficulty scaling factor between the different proofs of work. |
| 8    | Nonce             | uint64     | Nonce increment used to mine the block.                         |
| 1    | EdgeBits          | uint8      | Power of 2 used for the size of the cuckoo graph.               |
| 336  | ProofNonces       | uint64[42] | The cuckoo proof nonces.                                        |

##### Hash

| Size | Name | Data Type | Description/Comments |
|------|------|-----------|----------------------|
| 32 | Bytes | uint8[32] | Raw 32-byte hash, without a length prefix or hexadecimal text encoding. |

##### SegmentIdentifier

Identifies a subtree in an MMR (Merkle Mountain Range) or PMMR (prunable MMR).

| Size | Name | Data Type | Description/Comments |
|------|------|-----------|----------------------|
| 1 | Height | uint8 | Segment tree height; capacity is `2^Height` leaves. |
| 8 | Index | uint64 | Zero-based segment index. The first leaf index is `Index * 2^Height`. |

The identifier occupies 9 bytes. The last segment can contain fewer leaves than its capacity. For the output bitmap, each leaf is a 1,024-bit bitmap chunk.

##### SegmentRequest

| Size | Name | Data Type | Description/Comments |
|------|------|-----------|----------------------|
| 32 | BlockHash | Hash | Archive block hash for bitmap/output/range-proof/kernel requests; header-checkpoint MMR root for `GetHeadersHashesSegment`. |
| 9 | Identifier | SegmentIdentifier | Requested segment. |

The payload occupies 41 bytes.

##### `SegmentResponse<T>`

| Size | Name | Data Type | Description/Comments |
|------|------|-----------|----------------------|
| 32 | BlockHash | Hash | Identifies the archive or header-checkpoint root associated with the segment. |
| ? | Segment | `Segment<T>` | Segment with leaves of type `T`. |

##### `Segment<T>`

| Size | Name | Data Type | Description/Comments |
|------|------|-----------|----------------------|
| 9 | Identifier | SegmentIdentifier | Identifies this segment. |
| 8 | HashCount | uint64 | Number of supplied subtree hashes (`H`). |
| 8 * H | HashPositions | uint64[H] | One-based PMMR positions, strictly increasing. |
| 32 * H | Hashes | Hash[H] | Hashes corresponding to `HashPositions`, in the same order. |
| 8 | LeafCount | uint64 | Number of supplied leaves (`L`). |
| 8 * L | LeafPositions | uint64[L] | One-based PMMR positions, strictly increasing. |
| ? | LeafData | T[L] | Leaves corresponding to `LeafPositions`, in the same order. Each leaf uses its type's serializer. |
| ? | Proof | SegmentProof | Merkle proof connecting the segment to its MMR root. |

Positions and their values are serialized as separate arrays, in the order above. The wire positions are one-based; the in-memory segment positions are zero-based. Counts are bounded by `READ_VEC_SIZE_LIMIT`, with further segment-size and proof validation during synchronization. See [segment serialization](../../core/src/core/pmmr/segment.rs).

##### SegmentProof

| Size | Name | Data Type | Description/Comments |
|------|------|-----------|----------------------|
| 8 | HashCount | uint64 | Number of proof hashes (`P`), at most 129. |
| 32 * P | Hashes | Hash[P] | Proof hashes in the order expected by the MMR proof verifier. |

##### OutputIdentifier

The leaf type in `OutputSegment`.

| Size | Name | Data Type | Description/Comments |
|------|------|-----------|----------------------|
| 1 | Features | uint8 | `0` = Plain, `1` = Coinbase. |
| 33 | Commitment | Commitment | Pedersen commitment to the output. |

Each identifier occupies 34 bytes. Range proofs are transferred separately through `RangeProofSegment`. See [OutputIdentifier](../../core/src/core/transaction.rs).

##### RangeProof

The leaf type in `RangeProofSegment`.

| Size | Name | Data Type | Description/Comments |
|------|------|-----------|----------------------|
| 8 | Length | uint64 | Number of proof bytes (`N`), bounded by `MAX_PROOF_SIZE` (675 bytes with the current `bullet-proof-sizing` dependency feature). |
| N | Proof | uint8[N] | The proof bytes, without padding. |

This is the [network RangeProof encoding](../../core/src/ser.rs). The fixed-size `RangeProofPmmr` encoding is used for on-disk storage.

##### BitmapSegment

The output bitmap uses its own compact encoding, defined in [bitmap_accumulator.rs](../../chain/src/txhashset/bitmap_accumulator.rs).

| Size | Name | Data Type | Description/Comments |
|------|------|-----------|----------------------|
| 9 | Identifier | SegmentIdentifier | Identifies the segment of bitmap chunks. |
| 2 | BlockCount | uint16 | Number of encoded bitmap blocks (`B`), at least one. |
| ? | Blocks | BitmapBlock[B] | Consecutive bitmap blocks. All except the final block contain 64 chunks. |
| ? | Proof | SegmentProof | Merkle proof for the reconstructed bitmap segment. |

The total decoded chunk count must fit the identifier's capacity and the configured PIBD message limits.

##### BitmapBlock

A block contains up to 65,536 bits, grouped into 1,024-bit chunks.

| Size | Name | Data Type | Description/Comments |
|------|------|-----------|----------------------|
| 1 | ChunkCount | uint8 | Number of chunks (`C`), from 1 to 64 within a `BitmapSegment`. |
| 1 | Mode | uint8 | `0` = Raw, `1` = Positive, `2` = Negative. |
| ? | Data | uint8[] | Mode-specific payload below. |

| Mode | Data fields in wire order | Meaning |
|------|---------------------------|---------|
| Raw | `uint8[128 * C]` | Packed bits, most-significant bit first in each byte. Length follows from `ChunkCount`. |
| Positive | Count (`uint16`), Indices (`uint16[Count]`) | Start with all bits clear and set the listed bit indices. |
| Negative | Count (`uint16`), Indices (`uint16[Count]`) | Start with all bits set and clear the listed bit indices. |

Sparse indices are zero-based within the block, strictly increasing, and less than `1024 * C`. The canonical encoding uses Positive when fewer than 4,096 bits are set, otherwise Negative when fewer than 4,096 bits are clear, otherwise Raw. Sparse counts therefore range from 0 to 4,095.

### Messages

##### Error

| Size | Name    | Data Type | Description/Comments                         |
|------|---------|-----------|----------------------------------------------|
| 4    | Code    | uint32    | Error Code. TODO: Determine possible values. |
| ?    | Message | VAR_STR   | Slightly more user-friendly message          |

##### Hand

| Size | Name            | Data Type        | Description/Comments                                                                       |
|------|-----------------|------------------|--------------------------------------------------------------------------------------------|
| 4    | Version         | uint32           | Protocol version of the sender.                                                            |
| 1    | Capabilities    | CapabilitiesMask | Bitmask representing the capabilities of the sender.                                       |
| 8    | Nonce           | uint64           | Randomly generated for each handshake to help detect connections to yourself.              |
| 8    | TotalDifficulty | uint64           | Total difficulty accumulated by the sender. Used to check whether sync may be needed.      |
| 7/19 | SenderAddress   | SocketAddress    | Network address of the sender. 7 bytes for IPv4 or 19 bytes for IPv6.                      |
| 7/19 | ReceiverAddress | SocketAddress    | Network address of the receiver. 7 bytes for IPv4 or 19 bytes for IPv6.                    |
| ?    | UserAgent       | VAR_STR          | Name and version of the software. Example: "MW/MWC 0.1.2"                                 |
| 32   | Hash            | uint8[32]        | Genesis block of the current chain. Testnet1/2/3 and mainnet all have a different genesis. |

##### Shake

| Size | Name            | Data Type        | Description/Comments                                                                       |
|------|-----------------|------------------|--------------------------------------------------------------------------------------------|
| 4    | Version         | uint32           | Protocol version of the sender.                                                            |
| 1    | Capabilities    | CapabilitiesMask | Bitmask representing the capabilities of the sender.                                       |
| 8    | Nonce           | uint64           | Randomly generated for each handshake to help detect connections to yourself.              |
| 8    | TotalDifficulty | uint64           | Total difficulty accumulated by the sender. Used to check whether sync may be needed.      |
| ?    | UserAgent       | VAR_STR          | Name and version of the software. Example: "MW/MWC 0.1.2"                                 |
| 32   | Hash            | uint8[32]        | Genesis block of the current chain. Testnet1/2/3 and mainnet all have a different genesis. |

##### Ping

| Size | Name            | Data Type | Description/Comments                                                                                |
|------|-----------------|-----------|-----------------------------------------------------------------------------------------------------|
| 8    | TotalDifficulty | uint64    | Total difficulty accumulated by the sender. Used to check whether sync may be needed.               |
| 8    | Height          | uint64    | Total block height accumulated by the sender. See: https://github.com/mimblewimble/grin/issues/1779 |

##### Pong

| Size | Name            | Data Type | Description/Comments                                                                                |
|------|-----------------|-----------|-----------------------------------------------------------------------------------------------------|
| 8    | TotalDifficulty | uint64    | Total difficulty accumulated by the sender. Used to check whether sync may be needed.               |
| 8    | Height          | uint64    | Total block height accumulated by the sender. See: https://github.com/mimblewimble/grin/issues/1779 |

##### GetPeerAddrs

| Size | Name         | Data Type        | Description/Comments                   |
|------|--------------|------------------|----------------------------------------|
| 1    | Capabilities | CapabilitiesMask | The capabilities the peer should have. |

##### PeerAddrs

| Size | Name  | Data Type       | Description/Comments                                                      |
|------|-------|-----------------|---------------------------------------------------------------------------|
| 4    | Size  | uint32_t        | The number of peer addresses received.                                    |
| ?    | Peers | SocketAddress[] | Peer addresses that match the criteria from the GetPeerAddresses request. |

##### GetHeaders

| Size | Name   | Data Type | Description/Comments                                             |
|------|--------|-----------|------------------------------------------------------------------|
| 1    | Size   | uint8_t   | The number of headers being requested.                           |
| ?    | Hashes | Hash[]    | The 32-byte Blake2b hashes of the block headers being requested. |

##### Header

| Size | Name              | Data Type      | Description/Comments                                                           |
|------|-------------------|----------------|--------------------------------------------------------------------------------|
| 2    | Version           | uint16         | The version of the block.                                                      |
| 8    | Height            | uint64         | Height of this block since the genesis block (height 0).                       |
| 8    | Timestamp         | int64          | Timestamp at which the block was built.                                        |
| 32   | Previous          | Hash           | Blake2b hash of the block previous to this in the chain.                       |
| 32   | PreviousRoot      | Hash           | Merklish root of all the commitments in the previous block's TxHashSet.        |
| 32   | OutputRoot        | Hash           | Merklish root of all the commitments in the TxHashSet.                         |
| 32   | RangeProofRoot    | Hash           | Merklish root of all range proofs in the TxHashSet.                            |
| 32   | KernelRoot        | Hash           | Merklish root of all transaction kernels in the TxHashSet.                     |
| 32   | TotalKernelOffset | BlindingFactor | Total accumulated sum of kernel offsets since genesis block.                   |
| 8    | OutputMMRSize     | uint64         | Total size of the output Merkle Mountain Range(MMR) after applying this block. |
| 8    | KernelMMRSize     | uint64         | Total size of the kernel MMR after applying this block.                        |
| 178  | ProofOfWork       | ProofOfWork    | Proof of work and related.                                                     |

##### Headers

| Size | Name    | Data Type     | Description/Comments                                                     |
|------|---------|---------------|--------------------------------------------------------------------------|
| 2    | Size    | uint16_t      | The number of headers received.                                          |
| ?    | Headers | BlockHeader[] | The headers matching the hashes provided in the GetBlockHeaders request. |

##### GetBlock

| Size | Name      | Data Type | Description/Comments                           |
|------|-----------|-----------|------------------------------------------------|
| 32   | BlockHash | Hash      | The Blake2b hash of the block being requested. |

##### Block

| Size | Name   | Data Type       | Description/Comments                                                 |
|------|--------|-----------------|----------------------------------------------------------------------|
| 405  | Header | BlockHeader     | The block header.                                                    |
| ?    | Body   | TransactionBody | The block transaction containing the inputs, outputs, and kernel(s). |

##### GetCompactBlock

| Size | Name      | Data Type | Description/Comments                                   |
|------|-----------|-----------|--------------------------------------------------------|
| 32   | BlockHash | Hash      | The Blake2b hash of the compact block being requested. |

##### CompactBlock

| Size | Name   | Data Type        | Description/Comments                                                 |
|------|--------|------------------|----------------------------------------------------------------------|
| 405  | Header | BlockHeader      | The header with metadata and commitments to the rest of the data.    |
| 8    | Nonce  | uint64           | Nonce for connection specific short_ids.                             |
| ?    | Body   | CompactBlockBody | Container for out_full, kern_full and kern_ids in the compact block. |

##### StemTransaction

| Size | Name   | Data Type       | Description/Comments                                                |
|------|--------|-----------------|---------------------------------------------------------------------|
| 32   | Offset | BlindingFactor  | The kernel "offset" k2.                                             |
| ?    | Body   | TransactionBody | The transaction body containing the inputs, outputs, and kernel(s). |

##### Transaction

| Size | Name   | Data Type       | Description/Comments                                                |
|------|--------|-----------------|---------------------------------------------------------------------|
| 32   | Offset | BlindingFactor  | The kernel "offset" k2.                                             |
| ?    | Body   | TransactionBody | The transaction body containing the inputs, outputs, and kernel(s). |

##### TxHashSetRequest

| Size | Name      | Data Type | Description/Comments                                                  |
|------|-----------|-----------|-----------------------------------------------------------------------|
| 32   | BlockHash | Hash      | Blake2b hash of the block for which the TxHashSet should be provided. |
| 8    | Height    | uint64    | Height of the corresponding block.                                    |

##### TxHashSetArchive

The response to a TxHashSetRequest. Includes a zip stream of the archive after the message body.

| Size | Name      | Data Type | Description/Comments                                            |
|------|-----------|-----------|-----------------------------------------------------------------|
| 32   | BlockHash | Hash      | Blake2b hash of the block for which the txhashset are provided. |
| 8    | Height    | uint64    | Height of the corresponding block.                              |
| 8    | Bytes     | uint64    | Size in bytes of the archive.                                   |


##### BanReason

| Size | Name      | Data Type        | Description/Comments    |
|------|-----------|------------------|-------------------------|
| 4    | BanReason | ReasonForBanEnum | The reason for the ban. |


##### GetTransaction

Message ID 19. Requests a transaction from the peer's transaction pool by kernel hash. A matching transaction is returned as `Transaction` (ID 15); if it is unavailable, the peer sends no response.

| Size | Name | Data Type | Description/Comments |
|------|------|-----------|----------------------|
| 32 | KernelHash | Hash | Hash of a kernel belonging to the requested transaction. |

##### TransactionKernel

Message ID 20. Announces a transaction using a kernel hash. Peers advertising `TX_KERNEL_HASH` receive this announcement and can request the transaction with `GetTransaction`.

| Size | Name | Data Type | Description/Comments |
|------|------|-----------|----------------------|
| 32 | KernelHash | Hash | Announced kernel hash. |

##### TorAddress

Message ID 23 is reserved for backward compatibility. The current node decodes and skips this message. Its writer is compiled only for tests.

| Size | Name | Data Type | Description/Comments |
|------|------|-----------|----------------------|
| 8 | Length | uint64 | Byte length of the address (`N`). |
| N | Address | uint8[N] | UTF-8 onion address, validated and normalized by `canonical_onion_v3`. |

##### StartPibdSyncRequest

Message ID 24 starts discovery of a PIBD (Partial Initial Block Download) snapshot. The payload is `ArchiveHeaderData`, occupying 40 bytes. A matching archive produces `PibdSyncState`; an archive mismatch produces `HasAnotherArchiveHeader`.

| Size | Name | Data Type | Description/Comments |
|------|------|-----------|----------------------|
| 32 | BlockHash | Hash | Requested archive block hash. |
| 8 | Height | uint64 | Height of that archive block. |

The bitmap, output, range-proof and kernel requests below use `PIBD_HIST` peers. For the sequence of requests, root selection and validation, see [chain synchronization](../chain/chain_sync.md#pibd-state-synchronization).

##### GetOutputBitmapSegment

Message ID 25. Requests a segment of the snapshot's unspent-output bitmap. Uses the 41-byte `SegmentRequest` layout.

| Size | Name | Data Type | Description/Comments |
|------|------|-----------|----------------------|
| 32 | BlockHash | Hash | Archive block hash. |
| 9 | Identifier | SegmentIdentifier | Requested bitmap segment. |

##### OutputBitmapSegment

Message ID 26. Response to `GetOutputBitmapSegment`, serialized as `OutputBitmapSegmentResponse`.

| Size | Name | Data Type | Description/Comments |
|------|------|-----------|----------------------|
| 32 | BlockHash | Hash | Archive block hash. |
| ? | Segment | BitmapSegment | Compressed bitmap blocks and their Merkle proof. |

##### GetOutputSegment

Message ID 27. Requests an output PMMR segment. Uses the 41-byte `SegmentRequest` layout.

| Size | Name | Data Type | Description/Comments |
|------|------|-----------|----------------------|
| 32 | BlockHash | Hash | Archive block hash. |
| 9 | Identifier | SegmentIdentifier | Requested output segment. |

##### OutputSegment

Message ID 28. Response to `GetOutputSegment`. `OutputSegmentResponse` wraps a `SegmentResponse<OutputIdentifier>` and adds no bytes of its own.

| Size | Name | Data Type | Description/Comments |
|------|------|-----------|----------------------|
| 32 | BlockHash | Hash | Archive block hash. |
| ? | Segment | `Segment<OutputIdentifier>` | Output identifiers, subtree hashes and Merkle proof. |

##### GetRangeProofSegment

Message ID 29. Requests a range-proof PMMR segment. Uses the 41-byte `SegmentRequest` layout.

| Size | Name | Data Type | Description/Comments |
|------|------|-----------|----------------------|
| 32 | BlockHash | Hash | Archive block hash. |
| 9 | Identifier | SegmentIdentifier | Requested range-proof segment. |

##### RangeProofSegment

Message ID 30. Response to `GetRangeProofSegment`, using `SegmentResponse<RangeProof>`.

| Size | Name | Data Type | Description/Comments |
|------|------|-----------|----------------------|
| 32 | BlockHash | Hash | Archive block hash. |
| ? | Segment | `Segment<RangeProof>` | Range-proof leaves, subtree hashes and Merkle proof. |

##### GetKernelSegment

Message ID 31. Requests a kernel MMR segment. Uses the 41-byte `SegmentRequest` layout.

| Size | Name | Data Type | Description/Comments |
|------|------|-----------|----------------------|
| 32 | BlockHash | Hash | Archive block hash. |
| 9 | Identifier | SegmentIdentifier | Requested kernel segment. |

##### KernelSegment

Message ID 32. Response to `GetKernelSegment`, using `SegmentResponse<TxKernel>`.

| Size | Name | Data Type | Description/Comments |
|------|------|-----------|----------------------|
| 32 | BlockHash | Hash | Archive block hash. |
| ? | Segment | `Segment<TxKernel>` | Kernel leaves, subtree hashes and Merkle proof. |

##### HasAnotherArchiveHeader

Message ID 33. Reports the archive available at the serving peer when a PIBD or header-hash request targets a different archive/root. Uses the same 40-byte `ArchiveHeaderData` layout as `StartPibdSyncRequest`.

| Size | Name | Data Type | Description/Comments |
|------|------|-----------|----------------------|
| 32 | BlockHash | Hash | Hash of the peer's available archive block. |
| 8 | Height | uint64 | Height of that archive block. |

This response can follow either discovery request or any of the segment requests. Other serving failures can leave a request unanswered; the downloader handles retries and timeouts.

##### PibdSyncState

Message ID 34. Successful response to `StartPibdSyncRequest`, occupying 72 bytes.

| Size | Name | Data Type | Description/Comments |
|------|------|-----------|----------------------|
| 32 | HeaderHash | Hash | Archive block hash. |
| 8 | HeaderHeight | uint64 | Archive block height. |
| 32 | OutputBitmapRoot | Hash | MMR root of the snapshot's unspent-output bitmap. |

##### StartHeadersHashRequest

Message ID 35. Requests the header-checkpoint MMR root for an archive height from a `HEADERS_HASH` peer. The payload is `HashHeadersData`, occupying 8 bytes.

| Size | Name | Data Type | Description/Comments |
|------|------|-----------|----------------------|
| 8 | ArchiveHeight | uint64 | Requested archive height. |

The response is `StartHeadersHashResponse` when the height matches, or `HasAnotherArchiveHeader` when the peer serves a different archive height.

##### StartHeadersHashResponse

Message ID 36. Successful response to `StartHeadersHashRequest`, occupying 40 bytes.

| Size | Name | Data Type | Description/Comments |
|------|------|-----------|----------------------|
| 8 | ArchiveHeight | uint64 | Archive height covered by this header-checkpoint MMR. |
| 32 | HeadersRootHash | Hash | Root of the MMR containing checkpoint header hashes. |

The checkpoint MMR contains every 512th header hash, starting at genesis. See [header synchronization](../chain/chain_sync.md#header-hashes-and-parallel-bootstrap).

##### GetHeadersHashesSegment

Message ID 37. Requests a header-checkpoint hash segment. Uses `SegmentRequest`, occupying 41 bytes. Its `BlockHash` field carries the checkpoint MMR root returned by `StartHeadersHashResponse`.

| Size | Name | Data Type | Description/Comments |
|------|------|-----------|----------------------|
| 32 | BlockHash | Hash | Header-checkpoint MMR root. |
| 9 | Identifier | SegmentIdentifier | Requested header-hash segment. |

##### OutputHeadersHashesSegment

Message ID 38. Response to `GetHeadersHashesSegment`, serialized as `HeadersHashSegmentResponse`.

| Size | Name | Data Type | Description/Comments |
|------|------|-----------|----------------------|
| 32 | HeadersRootHash | Hash | Header-checkpoint MMR root. |
| 32 | BlockHash | Hash | Root repeated as the first field of the nested `SegmentResponse<Hash>`. |
| ? | Segment | `Segment<Hash>` | Checkpoint-hash leaves, subtree hashes and Merkle proof. |

Both hash fields are present on the wire. The current sender sets both to the requested checkpoint root. Each leaf in this segment is a 32-byte `Hash`.

The request/response behavior above follows [p2p/src/protocol.rs](../../p2p/src/protocol.rs); the send methods are in [p2p/src/peer.rs](../../p2p/src/peer.rs).

## Protocol Versions and Capabilities

### Capabilities

Any feature that users will have the ability to disable should be implemented as a new capability (See CapabilitiesMask above). This includes things like archive mode/full history.

### Protocol Version

Any change to the p2p protocol that is not toggled by the addition of a new capability should result in an increase in protocol version (See Hand & Shake messages above). This includes any addition or removal of a field or entire message, or any backward-incompatible behavior change to an existing field or message. When interacting with peers on an older protocol version, backward compatibility must be maintained, so the newer node should follow the rules of the older protocol version.

##### Phasing out old peers

To reduce the long-term complexity of the code, we can periodically bump the "major" protocol version. Although the protocol version is just a uint32, we can consider every increase by 1000 a new "major" protocol version. We can then gracefully phase out stubborn peers that refuse to upgrade by only supporting 1 major protocol version in the past. Here's what this would look like in practice:

* Peers with a protocol version in the range [0-999] should be able to interact with any peer in the range [0-1999].
* Peers with a protocol version in the range [1000-1999] should be able to interact with any peer in the range [0-2999].
* Peers with a protocol version in the range [2000-2999] should be able to interact with any peer in the range [1000-3999].

Determining when to increase the "major" version is left up to the discretion of the developers. Care must be taken to ensure we are not increasing too quickly however, as any major bump could result in the inability to connect to certain older peers.
