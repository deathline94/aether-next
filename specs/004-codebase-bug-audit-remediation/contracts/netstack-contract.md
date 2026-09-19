# Contract: Netstack TX Flush Ordering

## Overview
Specifies the packet queueing and preservation semantics for `flush_tx` in `aether/src/netstack.rs`.

## Invariants
1. **FIFO Sequence Integrity**:
   Given a sequence of outbound IP datagrams $[P_1, P_2, \dots, P_n]$ produced by smoltcp, all packets sharing the same 5-tuple (flow) must be delivered to `outbound_tx` in the identical order.
2. **ACK Prioritization Without Inversion**:
   Packets $\le 128$ bytes may be scheduled ahead of bulk data packets ($> 128$ bytes), but:
   - All bulk packets in `deferred` must maintain their mutual relative ordering: $i < j \implies \text{Order}(P_i) < \text{Order}(P_j)$.
   - In the event of a `TrySendError::Full(P_k)`, the packet $P_k$ and all un-transmitted `deferred` packets must be restored to the head of `s.device.tx` such that the next flush cycle pops $P_k$ first, followed by the remaining `deferred` packets in their original order.
3. **Queue Reconstitution Invariant**:
   ```rust
   // When outbound_tx is full on pkt from deferred:
   deferred.push_front(pkt);
   while let Some(d) = deferred.pop_back() {
       s.device.tx.push_front(d);
   }
   ```
   This guarantees that if `deferred` contained $[D_1, D_2, D_3]$ and $D_1$ failed with `Full`:
   `deferred.push_front(D_1)` makes it $[D_1, D_2, D_3]$.
   Popping from back yields $D_3$, pushed to front of `tx`: $[D_3]$.
   Popping $D_2$, pushed to front of `tx`: $[D_2, D_3]$.
   Popping $D_1$, pushed to front of `tx`: $[D_1, D_2, D_3]$.
   The resulting `tx` queue head is $[D_1, D_2, D_3]$ — perfectly preserving FIFO order!
