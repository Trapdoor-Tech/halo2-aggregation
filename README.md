## Overview

This crate is designed to aggregate [`Halo2`](https://github.com/zcash/halo2.git) proofs into one single proof.

- [x] a circuit that can check if a proof is valid using vk.
  - we used the simple-example as the test case which covers custom gate.
- [ ] put transcripts in public inputs.
- [ ] get more performance data, including #(columns), #(rows), #(Rotations)
- [ ] porting SHA256 gadget from SHA256 example.
- [ ] a circuit that can verify many kinds of proofs.

### APIs that needed from [`halo2`](https://github.com/zcash/halo2.git)

### APIs that needed from [`halo2wrong`](https://github.com/appliedzkp/halo2wrong.git)