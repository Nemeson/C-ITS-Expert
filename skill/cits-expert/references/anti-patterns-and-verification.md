# Anti-Patterns & Verification Gates Reference

## 1. Prohibited Rationalizations ("The Hallucination Traps")

During past development cycles, AI agents generated synthetic data to make tests pass or simulate features. This table provides explicit, binding counters against each temptation:

| Rationalization / Excuse | Real-World Consequence | Binding Rule |
| :--- | :--- | :--- |
| *"I will add a sine wave to simulate GNSS drift for the UI demo."* | The diagnostic report falsely certifies sensor conformity and GLOSA compliance to audit teams. | **PROHIBITED.** If real trajectory data is unavailable, display "No GNSS comparison data available". |
| *"I will calculate the signal group as `(laneId % 4) + 1`."* | Signal aspects will be arbitrarily mapped to the wrong physical traffic movements. | **PROHIBITED.** Signal groups MUST be resolved strictly via MAPEM `connectsTo[].signalGroup`. |
| *"I will synthesize a 90s cycle loop so the Gantt chart looks active."* | SPATEM conformance rules (yellow time, red-yellow duration, max cycle) can never trigger. | **PROHIBITED.** Leave `spat_groups` empty (`[]`) until real SPATEM messages are decoded. |
| *"I will verify using only synthetic unit-test fixtures."* | Critical link-layer encapsulations (DLT 127 Radiotap, nanosecond PCAPs) will fail in production. | **PROHIBITED.** Every parser must be tested against real capture bytes from field drives. |
| *"Firmware timestamp is an epoch integer, so I will write it directly."* | Creates PCAP files with timestamps dated in the year 1970. | **PROHIBITED.** Firmware timestamps MUST be anchored against host wall-clock time. |

---

## 2. The Verification Pyramid for C-ITS Software

```
                     / \
                    /   \
                   / E2E \    5% (Visual Regression, Real PCAP Replay)
                  /-------\
                 /  Prop   \   10% (Hypothesis: Randomized corrupted bytes)
                /-----------\
               / Integration \  15% (Multi-fragment MAPEM, SREM<->SSEM 4-tuple)
              /---------------\
             /    Unit Tests   \ 70% (Bitstream decoding, DLT unwrap, Scales)
            /-------------------\
```

### Mandatory Verification Fixtures
A C-ITS test suite is incomplete unless it tests against:
1. **At least one DLT 127 Radiotap PCAP** with QoS Data and LLC/SNAP headers.
2. **At least one multi-fragment MAPEM capture** with segmented `layerID`s.
3. **At least one nanosecond-resolution PCAP** (`0xa1b23c4d`).
4. **At least one real SREM/SSEM interaction** verifying 4-tuple correlation.
