# Release 7.0.0

## Release Highlights

Release 7.0.0 address audit comments/issues that was found with AI code review. Also, because code changes affect 
performance, the node sync process was optimized by using all available CPU cores.

Atri (Tor) is upgraded to the latest version.

The normal mwc-node CPU and memory footprint should not change much. Mwc-node still light for CPU usage and has low memory 
footprint.  

## Addressed audit comments

### Common issues

Here we list the issues that was addressed almosy on all crates.

- Possible data overflow. Switched to a checked/saturated math oprations where we can't proof that regular math is safe.
- Safe data types conversions. Switched to checked data types conversions if data can be lost/changed because of conversion.

### secp256k1-zkp

**Summary of the changes:**
- Updated functional documented contracts to match real code and behavior.
- Update functional interfaces and propagate errors.
- Validate input parameters.
- Propagate errors from called fucntions.
- Clean up the temporary buffers/variables that could contain sensitive data.
- Stop using memset for clean up, because this call can be optimized in release build. 

**README.md** : 
- add MacOS all-features build/test subsection

**contrib/lax_der_privatekey_parsing.c** 
- add DER private-key export length hardening and bounds checks; precompute required output size, validate caller buffer size, serialize public key once via API, and use its returned 
  length in both compressed/uncompressed paths to prevent overflow/malformed output sizing on export.

**contrib/lax_der_privatekey_parsing.h** clarify `ec_privkey_export_der` contract by making `privkeylen` an in/out length parameter, documenting it.

**include/secp256k1.h** 
- clarify `secp256k1_context_clone` return value with `NULL on error` and remove `SECP256K1_ARG_NONNULL(1)` on the clone prototype.
- change callback user context parameter from `const void*` to `void*` in both `secp256k1_context_set_illegal_callback` and `secp256k1_context_set_error_callback` signatures to match callback typing expectations.
- tighten `secp256k1_ec_pubkey_serialize` return contract to `1 on success, 0 on failure`.
- tighten `secp256k1_ecdsa_signature_serialize_der` return contract to include well-formed signature requirement.
- tighten `secp256k1_ecdsa_signature_serialize_compact` return contract to `1` only for well-formed signature objects.
- update `secp256k1_ecdsa_signature_normalize` return contract to distinguish malformed signatures (`0`) from already-normalized (`1`) vs normalized-now (`2`).
- change `ndata` in `secp256k1_ecdsa_sign` from `const void*` to `void*` for callback payload compatibility.
- add side-channel/security caveat to `secp256k1_ec_pubkey_tweak_add` about secret-dependent control flow/table lookups when tweak is secret.
- add side-channel/security caveat to `secp256k1_ec_pubkey_tweak_mul` about secret-dependent control flow/table lookups when tweak is secret.
- clarify `secp256k1_ec_privkey_tweak_inv` returns `0` when input is zero or out of range, and `1` otherwise.

**include/secp256k1_aggsig.h** 
- clarify `secp256k1_aggsig_sign_single` nonce behavior by documenting that `secnonce32` is generated from the seed when NULL, and that `pubnonce_total` is ignored when `secnonce32` is NULL.

**include/secp256k1_bulletproofs.h** 
- clarify aggregate verification wording to state it uses generators from `value_gen` and that the verifier expects `value_gen` as an array of generators, removing ambiguity in generator selection for multi-proof checks.
- update single-proof rewind API docs and prototype for stronger UX/validation: `min_value` is now pointer-based (`const uint64_t *`) to allow `NULL` for all-zeroes, add required `blind_gen` to explicitly pass the commitment blinding generator, and add optional `private_nonce` (with extra description for taux/mu validation) to support private-factor consistency checks.
- tighten aggregate prove docs by stating `private_nonce` is needed for multi-party flows.

**include/secp256k1_commitment.h** 
- tighten `secp256k1_pedersen_commitment_serialize` return contract to explicitly distinguish success (`1`) from validation failure (`0`), rather than documenting unconditional success.

**include/secp256k1_generator.h** 
- tighten `secp256k1_generator_serialize` return contract to distinguish validation failure (`0`) from success (`1`) instead of documenting unconditional success.

**include/secp256k1_recovery.h** 
- clarify `secp256k1_ecdsa_recoverable_signature_convert` return contract to require a well-formed input signature, returning `1` on success and `0` on malformed recoverable signatures.
- clarify `secp256k1_ecdsa_recoverable_signature_serialize_compact` return contract to require a well-formed recoverable signature, returning `1` on success and `0` on malformed input.

**include/secp256k1_schnorrsig.h** 
- clarify `secp256k1_schnorrsig_sign` `ndata` usage by documenting that when using default `secp256k1_nonce_function_bipschnorr`, `ndata` must be NULL or a 32-byte auxiliary value mixed into nonce derivation.

**include/secp256k1_surjectionproof.h** 
- clarify return behavior in error cases by documenting `secp256k1_surjectionproof_n_used_inputs` returns `0` on error and `secp256k1_surjectionproof_serialized_size` now has explicit error-return text (`0` on failure).

**include/secp256k1_whitelist.h** 
- reduce `SECP256K1_WHITELIST_MAX_N_KEYS` from `256` to `255`. Reason: whitelist signatures encode n_keys in one byte.

**src/bench.h** 
- add an explicit comment that `gettimeofday` return value is ignored, clarifying intent for audit/lint review.

**src/bench_bulletproof.c**
- align rangeproof `value` storage with API integer width by switching from `size_t` to `uint64_t` in data structures and allocations, preventing format/type mismatches with bulletproof routines that expect 64-bit values.
- document lossy conversions in benchmark
- update `secp256k1_bulletproof_rangeproof_rewind` calls with extra params and switch returned value/output buffers to `uint64_t` (`v`) to match the API contract.
- replace label formatting to correctly print `size_t` values, improving output correctness across platforms.
- add CHECKs after creating context, scratch space, and generators to fail early if core cryptographic resources are not initialized.

**src/bench_ecmult.c** 
- wrap `ecmult_multi` invocation with `CHECK` in benchmark loop so failed multiscalar multiplications stop execution instead of silently continuing with invalid outputs.
- wrap `secp256k1_ecmult` expected-output precomputation in `CHECK` to treat scalar-multiplication setup failures as hard errors.
- add explicit invalid-argument handling in `main` argument parser to emit an error and `abort()` for unrecognized benchmark back-end options instead of using default path with stale state.
- wrap `secp256k1_ge_set_all_gej_var` with `CHECK` so affine conversion failures are detected early.

**src/bench_internal.c**  
- wrap previously unchecked setup and loop operations in `CHECK(...)`, specifically `secp256k1_fe_set_b32`, `secp256k1_scalar_split_lambda`, `secp256k1_scalar_inverse_var`, and `secp256k1_fe_inv_var`, to hard-fail on invalid conversion or scalar/field operation outcomes.
- harden `bench_field_sqrt` by initializing a quadratic-residue input, calling `secp256k1_fe_sqrt(&r, &x)` with `CHECK`, normalizing each root, and writing the final value back to `data->fe_x` so the benchmark no longer ignores sqrt failures. Note, benchmark logic was changed so sqrt must be sucessfull.
- update `bench_group_jacobi_var` to use the new error-out-parameter form of `secp256k1_gej_has_quad_y_var` and assert `err == 0` before continuing.
- update `bench_ecmult_wnaf` to the new error-returning API (`secp256k1_ecmult_wnaf(..., &err)`) and enforce `CHECK(err == 0)`.
- update `bench_wnaf_const` to the new error-returning API (`secp256k1_wnaf_const(..., &err)`) and enforce `CHECK(err == 0)`.
- in `bench_num_jacobi`, check `secp256k1_scalar_get_num`/`secp256k1_scalar_order_get_num` success and switch `secp256k1_num_jacobi` to `err`-return style, failing hard on non-zero error.

**src/bench_rangeproof.c** 
- add a benchmark-only security disclaimer comment above setup to document that benchmark code is outside normal security requirements.
- in the benchmark loop, explicitly ignore rangeproof verification status and add comments before intentionally mutating proof bytes, acknowledging low-security benchmark behavior and that mutated proofs invalidate previous checks.

**src/bench_schnorrsig.c**
- skip context randomization in benchmark `main` with a security-noting comment that high-security guarantees are intentionally not required for benchmark execution.

**src/bench_sign.c** 
- switch benchmark signature serialization from DER to compact output by using a 64-byte buffer and `secp256k1_ecdsa_signature_serialize_compact`, removing DER-length handling, and add an explicit benchmark-only comment that context randomization is intentionally skipped.

**src/bench_verify.c** 
- add a benchmark-only security comment clarifying that randomization is intentionally skipped in this benchmark due to non-production security requirements.
- guard OpenSSL benchmark startup with a null check on `EC_GROUP_new_by_curve_name`, only run `ecdsa_verify_openssl` when the group is allocated, free the group on success, and print a warning on failure.
 
**src/bench_whitelist.c** 
- add benchmark-only comments clarifying deterministic private-key generation is intentionally repeatable across runs and context randomization is intentionally skipped since the benchmark is non-production code.
 
**src/ecdsa_impl.h** 
- in `secp256k1_ecdsa_sig_verify`, add explicit error checks for `secp256k1_scalar_inverse_var` and `secp256k1_ecmult`; return `0` on failure.
- in `secp256k1_ecdsa_sig_verify` validate `secp256k1_fe_set_b32` return and abort verification with `0` when `sigr` bytes cannot be represented as a field element.
- in `secp256k1_ecdsa_sig_sign`, check `secp256k1_ecmult_gen` return and return `0` when nonce-point generation fails, avoiding use of an unset result point.
**src/eckey_impl.h** 
- add a clarification comment before `secp256k1_eckey_pubkey_serialize` that `size` is output-size only and that callers must allocate 33 or 65-byte output buffers themselves.
- in `secp256k1_eckey_pubkey_tweak_add`, fail fast when `secp256k1_ecmult` returns failure and return `0` before the infinity check, instead of continuing with a possibly invalid intermediate point.
- in `secp256k1_eckey_pubkey_tweak_mul`, check `secp256k1_ecmult` return and return `0` immediately on failure to prevent using unset results from failed scalar multiplication.
**src/ecmult.h** 
- change internal APIs to return status codes: `secp256k1_ecmult_context_build` now returns `int` and `secp256k1_ecmult` now returns `int` with an added success/failure contract comment.

**src/ecmult_const.h** 
- change `secp256k1_ecmult_const` API from `void` to `int` and document its return contract (`1` on success, `0` on failure).

**src/ecmult_const_impl.h** 
- replace debug-time `VERIFY_CHECK`/`VERIFY_SETUP` assertions in `ECMULT_CONST_TABLE_GET_GE` with runtime input validation and early `return 0` failures.
- extend `secp256k1_wnaf_const` with an `int *err` out-parameter and return-type status path. Add bailout when an error is already set, propagate failures through the shared error flag.

**src/ecmult_const_impl.h**
- change `secp256k1_ecmult_const` to return status `int`, propagate split and WNAF errors.
- add explicit success return (`return 1`) to complete the new status-based contract of `secp256k1_ecmult_const`.

**src/ecmult_gen.h**
- convert internal generation context build/multiply/blind APIs to explicit `int` return contracts and document error semantics by changing `secp256k1_ecmult_gen_context_build`, 
`secp256k1_ecmult_gen`, and `secp256k1_ecmult_gen_blind` to return `1` on success and `0` on error.

**src/ecmult_gen_impl.h**
- clear generator context secret/state fields (`blind`, `initial`) during init for deterministic zero-state and safer reuse.
- convert `secp256k1_ecmult_gen_context_build` to return `int` with explicit failure cleanup; fail fast and clear context if generator point setup or batch affine conversion fails, and propagate blind-step failures.
- convert `secp256k1_ecmult_gen` to return `int` and add error propagation from `secp256k1_scalar_get_bits`; on failure clear temporaries (`add`, `gnb`) and return `0` instead of emitting potentially invalid points.
- convert `secp256k1_ecmult_gen_blind` to return `int`, replace stack clearing with `secp256k1_memclear`, make zero checks explicit for retry state, and hard-fail/cleanup if downstream `secp256k1_ecmult_gen` fails.

**src/ecmult_impl.h**
- change odd-multiple precompute helper to return status `int`, propagate `secp256k1_fe_inv_var` failures and return `1` on success.
- make `secp256k1_ecmult_context_build` return status `int`, add runtime argument checks, propagate errors.
- refactor `secp256k1_ecmult_wnaf` to status form with `int *err`, add runtime argument checks, propagate errors.
- make `secp256k1_ecmult_strauss_wnaf` and `secp256k1_ecmult` return `int`, propagate errors.
- harden `secp256k1_ecmult_strauss_batch` with point-count overflow guard, per-allocation NULL checks and deallocation on failure, callback point validity checks, and failure propagation from `secp256k1_ecmult_strauss_wnaf`.
- update fixed-window WNAF helper to accept `int *err`, propagate scalar bit extraction errors from variable getters.
- document and convert `secp256k1_ecmult_pippenger_wnaf` return contract to explicit status flow, propagate `secp256k1_wnaf_fixed` errors via local `err`, and abort on conversion failures.
- convert `secp256k1_ecmult_endo_split` to status return, fail if `secp256k1_scalar_split_lambda` fails, and return `1` on success.
- harden `secp256k1_ecmult_pippenger_batch` with point-count overflow checks, per-allocation failure rollback, callback point validity checks, split failure checks, and failure propagation.
- in `secp256k1_ecmult_multi_var_simple` and `secp256k1_ecmult_multi_var` propagate `secp256k1_ecmult` failures and reject invalid callback points.

**src/field.h**
- change `secp256k1_fe_set_int` scalar argument from signed `int` to `uint32_t` to avoid implementation-defined behavior for negative values.
- extend `secp256k1_fe_is_quad_var` with an `int *err` out-parameter so callers can distinguish invalid/error states from residue checks.
- make `secp256k1_fe_inv_var` return an `int` status so callers can detect failures instead of assuming success.
- make `secp256k1_fe_inv_all_var` return an `int` status for failures, enabling full error propagation through caller chains.

**src/field_10x26_impl.h**
- in `secp256k1_fe_verify`, enforce magnitude bounds before computing `m` (magnitude checks moved before use), making invalid field-state handling explicit and preventing potential unchecked intermediate use.
- harden `secp256k1_fe_set_int` by using `uint32_t` input plus explicit `VERIFY_CHECK` bounds checks (`a >= 0`, `a <= 0x3FFFFFF`) before assigning field limbs.
- replace `secp256k1_fe_clear` looped limb-zeroing with `secp256k1_memclear` for deterministic zeroing behavior.
- add explicit preconditions in `secp256k1_fe_negate` (`0 <= m <= 31`) to avoid unsafe magnitude range before arithmetic checks.
- harden `secp256k1_fe_cmov`, `secp256k1_fe_storage_cmov` with runtime selector validation (`flag` is 0/1) and normalize the selector to a boolean mask source.

**src/field_5x52_impl.h**
- moving magnitude validation before computing derived magnitude `m` in `secp256k1_fe_verify`, and keeping verify checks explicit for overflow safety.
- change `secp256k1_fe_set_int` input type from signed `int` to `uint32_t`, and add explicit runtime range checks (`a >= 0`, `a <= 0x3FFFFFF`) before assignment.
- replace manual limb zeroing in `secp256k1_fe_clear` with `secp256k1_memclear` for deterministic clearing of field data.
- add selector-safe magnitude checks in `secp256k1_fe_negate` (`0 <= m <= 31`) and enforce non-negative multiplier precondition in `secp256k1_fe_mul_int`, matching the new invariant checks in this backend.
- harden constant-time conditional move APIs (`secp256k1_fe_cmov`, `secp256k1_fe_storage_cmov`) by validating `flag` is 0 or 1 and normalizing it to boolean form before generating masks.

**src/field_impl.h**
- change inversion and quadratic residue APIs to explicit status flows. `secp256k1_fe_inv_var` now returns `int`, checks zero input before inversion, and returns 0/1 instead of `void`;
- `secp256k1_fe_inv_all_var` now returns `int`, returns success for empty input, propagates failures
- `secp256k1_fe_is_quad_var` now takes `int *err`, bails out immediately on existing errors, propagates num-jacobi error state, and in non-num build normalizes `a` before `fe_sqrt`.

**src/gen_context.c**
- add a comment clarifying that generated artifacts are validated manually, so this utility intentionally skips runtime error reporting paths.
- wrap `secp256k1_ecmult_gen_context_build` with `CHECK(...)` to hard-fail if precomputed generator context creation fails before emitting the static context file.

**src/group.h**
- update return value to int for `secp256k1_ge_set_all_gej_var`, so caller can detect the errors.
- add extar parameter `err` to `secp256k1_gej_has_quad_y_var`, so caller can detect the errors.

**src/group_impl.h**
- change `secp256k1_ge_set_gej_var`,`secp256k1_ge_set_all_gej_var` from `void` to status-returning `int`, returning `1` on success. Propagating errors.
- harden `secp256k1_gej_is_valid_var` by rejecting Jacobian points with `z == 0`, preventing zero-denominator identity-collision checks from passing as valid points.
- extend `secp256k1_gej_has_quad_y_var` to carry an `int *err` error pointer, preserve prior error state, and return `0` when an error is already present or occurs during quadraticity checking.

**src/hash_impl.h**
- add an explicit stream-size assumption comment above `secp256k1_sha256_write`.
- remove per-word state clearing from the digest output loop and replace it with explicit cleanup of hash state and temporary buffers via `secp256k1_memclear`.
- switch HMAC key-block cleanup in `secp256k1_hmac_sha256_initialize`, `secp256k1_hmac_sha256_finalize`, RFC6979 from `memset` to `secp256k1_memclear` for deterministic clearing.
- change `now` in RFC6979 output generation from `int` to `size_t` so block-copy sizing matches `outlen` width safely.

**src/modules/aggsig/Makefile.am.include**
- remove the `USE_BENCHMARK` block that defined and linked `bench_aggsig`

**src/modules/aggsig/main_impl.h**
- in multiple functions add error propagations, return falure statuses, validate points, use cleanp with secp256k1_memclear, clean RNG state.

**src/modules/aggsig/tests_impl.h**
- add a dedicated 32-byte message scratch buffer (`msg2`) for deterministic signature reproducibility checks in single-signature tests.
- update invalid aggregate context creation assertions
- add a deterministic single-sign regression that mutates a copied message (`msg2`) and reuses the same seed to confirm resulting signatures are identical in the first 32 bytes and valid for the modified message, documenting deterministic nonce behavior.

**src/modules/bulletproofs/inner_product_impl.h**
- enforce caller-controlled vector length validation in `secp256k1_bulletproof_innerproduct_proof_length`, reducing unsafe length-driven behavior.
- at `secp256k1_bulletproof_inner_product_verify_impl` validate `vec_len`, add verifier overflow/alloc guards for `n_proofs`, allocated context pointers.
- update other functions with error propagations

**src/modules/bulletproofs/main_impl.h**
- add generator-size overflow guard during generator set construction, change generator generation/loading paths to explicit failure checks with cleanup, and validate caller-supplied blinding generator before storing it in the generator bundle.
- harden single-proof verify with overflow checks, allocation failure handling, commit parsing validation, and value-generator validity checks so malformed inputs fail safely before verification.
- expand multi-proof verify signature and argument validation, add overflow checks, require non-NULL proofs/commitments, and validate scratch/commit/value-generator allocations and loads for every proof before calling into verify implementation.
- update rewind API to take nullable min-value pointer plus explicit blinding generator; validate blinding generator before calling unwind impl and route optional private nonce through to implementation.
- strengthen proof flow with overflow checks, remove the no-blinding-factor mode, require blinding pointers, and extend value-range validation to support optional minima when nbits < 64 and a hard check for nbits == 64.
- add missing scratch allocation checks and validation for value generator and commitment loading, fail on failed multipliers/invalid points in commitment derivation, enforce non-NULL external commitments, and make temporary `t_ge` handling and pubkey save conditional on successful proof output.

**src/modules/bulletproofs/rangeproof_impl.h**
- fix min-value accumulation in verify callback to use a dedicated `mv` scalar and `uint64_t` load path.
- strengthen verifier preconditions (`n_commits`/`n_proofs` bounds, power-of-two constraints, scratch allocation failure handling) and check `secp256k1_bulletproof_update_commit`, point parsing, and scalar inversion failures before continuing.
- harden prover flow with stronger input/overflow checks, explicit status checks for scalar multiplications and point serialization, and fail-closed behavior on failed `ecmult_const`/commit updates/inverse operations.
- extend rewind API surface (`min_value` pointer, `blind_gen`, optional `private_nonce`), add load/validity checks, constant-time `mu` prefix check, and optional rewind proof commitment verification against reconstructed `pcommit` to avoid accepting invalid proofs as success.

**src/modules/bulletproofs/tests_impl.h**
- expand bulletproof test coverage around the new rangeproof API semantics and stability checks by adding null-minimum/private-nonce path coverage in prove/verify/rewind flows, 
explicit blinding-generator handling and tampered-proof checks, strict CHECK-wrapped status assertions on scalar multiplications/serializations/internal helpers, 
new infinity-point serialization/proof regressions, and wire these new tests into `run_bulletproofs_tests`.

**src/modules/bulletproofs/util.h**
- convert scalar inversion, point serialization, point deserialization, and commitment-update helpers to explicit success/failure status returns. 
- add input-validation guards for zero-length/invalid points and invalid field-element/parsing/inversion paths, and fail closed on errors instead of writing potentially malformed outputs.

**src/modules/commitment/main_impl.h**
- convert internal commitment load/save helpers to error-returning functions
- add validation and failure checks for field/point decoding and generator loading/validity
- propagate scalar mult and point save failures through all commitment creation/conversion entry points
- fail early on NULL pointer inputs in blind/sum/tally paths, and add an `ecmult_ctx` readiness check in blind-switch after validating generator arguments.

**src/modules/commitment/pedersen_impl.h**
- convert both internal Pedersen mult helpers to `int` error returns.
- propagate `secp256k1_ecmult_const` failures with early `0` returns in both value/blind paths.

**src/modules/ecdh/main_impl.h**
- clear the 32-byte result buffer before doing any secret-dependent work, then reject invalid encoded points by returning early so callers cannot observe stale output from invalid public-key parsing failures.
- propagate the `secp256k1_ecmult_const` return status to `ret` and conditionally execute compressed-point hashing only on success, replacing unconditional success reporting with fail-closed behavior.

**src/modules/ecdh/tests_impl.h**
- in `test_bad_scalar`, add an `output_zero` baseline and explicit zero-output assertions after invalid scalar failures.
- add new `test_bad_point()` covering zero-length and off-curve pubkey parse paths with callback/output validation, wire it into `run_ecdh_tests()`.

**src/modules/generator/main_impl.h**
- switch generator load/save and parse/serialize helpers to status-returning APIs with explicit decode/validity checks.
- make hash-to-curve derivation return `0` on degeneracy, inversion, or all-non-quadratic failures; and propagate conversion/multiplication/save failures in generator generation so malformed inputs or internal arithmetic failures fail-closed.

**src/modules/generator/tests_impl.h**
- update generator tests for new fail-closed behavior by asserting `shallue_van_de_woestijne` returns failure on zero-field input.
- wrapping `secp256k1_generator_load` calls in `CHECK`, adding a negative-path regression for off-curve generator loading/serialization
- extending `run_generator_tests()` to execute the new checks.

**src/modules/rangeproof/borromean_impl.h**
- replace debug-only validation patterns with runtime fail-closed checks in verify/sign flow. The change now rejects zero rings, zero-size rings, overflow-edge ring indexes and many other cases.

**src/modules/rangeproof/main_impl.h**
- harden `rangeproof_rewind`, `rangeproof_verify`, and `rangeproof_sign` by checking `secp256k1_pedersen_commitment_load` and `secp256k1_generator_load` return codes.

**src/modules/rangeproof/rangeproof_impl.h**
- change `secp256k1_rangeproof_serialize_point` to return `int` status, capture `secp256k1_fe_is_quad_var` errors via `err`, return `0` on failure, and return `1` on success.
- in rangeproof nonce derivation, propagate `secp256k1_rangeproof_serialize_point` failures from both `commit` and `genp`, and replace `memset` with `secp256k1_memclear` for deterministic cleanup.
- add explicit failure checks for `secp256k1_rangeproof_serialize_point`, `secp256k1_pedersen_ecmult`, and `secp256k1_ge_set_gej_var` in `secp256k1_rangeproof_sign_impl` before continuing.
- at `secp256k1_rangeproof_rewind_inner` fail-closed when nonce reconstruction via `secp256k1_rangeproof_genrand` fails, preventing use of invalid reconstructed internal state.
- at `secp256k1_rangeproof_verify_impl` add failure handling through verify setup by propagating `secp256k1_rangeproof_serialize_point`, `secp256k1_ecmult_const`, and `secp256k1_pedersen_ecmult` return codes.

**src/modules/rangeproof/tests_impl.h**
- in `test_borromean`, fix scalar initialization, wrap `secp256k1_ecmult_gen` in `CHECK(...)`, so malformed generator multiplication cannot be silently ignored.
- add `test_borromean_metadata_checks` to validate metadata handling in borromean signing for zero-ring, out-of-range index, zero-scalar, and ring-size boundary cases, asserting expected failure paths for invalid input combinations.
- change fixed-vector `min_value_1`/`max_value_1` locals from `size_t` to `uint64_t` in `test_rangeproof_fixed_vectors` to align with rangeproof value type expectations.
- register and run `test_borromean_metadata_checks()` in `run_rangeproof_tests`.

**src/modules/recovery/main_impl.h**
- change `secp256k1_ecdsa_recoverable_signature_load` to return a error code and add validation for malformed recoverable signatures by checking scalar overflow and invalid recovery IDs.
- harden serializable/convert entry points by checking `secp256k1_ecdsa_recoverable_signature_load` return values in `secp256k1_ecdsa_recoverable_signature_serialize_compact` and `secp256k1_ecdsa_recoverable_signature_convert`.
- strengthen recovery core checks by treating `secp256k1_fe_set_b32`, `secp256k1_scalar_inverse_var`, `secp256k1_ecmult`, and `secp256k1_ge_set_gej_var` failures.
- remove the direct null-context `VERIFY_CHECK`, keep explicit generator-context readiness via `ARG_CHECK`, and retain explicit handling for invalid signing preconditions.
- replace `memset` with `secp256k1_memclear` when scrubbing the per-signing nonce buffer, preserving fail-closed cleanup semantics.
- propagate recoverable-signature parse failures out of `secp256k1_ecdsa_recover` by zeroing output `pubkey` and returning `0`, instead of asserting valid recovery IDs/fields earlier.

**src/modules/recovery/tests_impl.h**
- extend `test_ecdsa_recovery_end_to_end` coverage with invalid recoverable signature fixtures (`invalid_sig`, `overflow`) and explicit regression checks that malformed `r` values (order overflow) and invalid `recid` data.

**src/modules/schnorrsig/main_impl.h**
- harden Schnorr sign/verify paths and batch verification with fail-closed behavior by adding explicit default nonce-domain selection (`noncealgo16`), overflow checks on secret key/nonce, failure handling for generator scalar multiplication, quad-check and pubkey serialization/parsing status checks, deterministic signature zeroing on entry, and batch-input validation.

**src/modules/schnorrsig/tests_impl.h**
- harden test edge cases for stable behavior by fixing callback-counter width (`int32_t`) and force-casting a boundary batch-count argument to `size_t` to avoid integer-width-dependent behavior in `secp256k1_schnorrsig_verify_batch`.
- add `nonce_function_bipschnorr_untagged` and route BIP vector signing checks through it.
- extend `test_schnorrsig_sign` with explicit nonce-function/aux-randomness coverage by adding passthrough, tagged and custom nonce callbacks, 
multiple deterministic signature captures (with and without aux randomness), and assertions that compare default vs explicit/tagged/passthrough behavior.

**src/modules/surjection/main_impl.h**
- add validation helpers for input-count/bitmap safety, including max-input bounds checking, bitmap mask checking for unused high bits, and precise used-input counting from serialized bitmaps.
- introduce deterministic `secp256k1_surjection_gen_nonce()` deriving nonce from blinding key, message, ring pubkeys, index, and ring size with temp scrubbing on every failure path.
- harden parse/serialize/size and used-input getters by validating bitmaps, rejecting zero/invalid bit-count proofs, and deriving serialized/signature sizes from counted used inputs instead of raw bitset width.
- gate `secp256k1_surjectionproof_initialize()` with `n_max_iterations<INT_MAX` before looping.
- harden `secp256k1_surjectionproof_generate()` with stronger zero/overflow handling, checked generator loads, checked public-key derivation/message/nonce generation, explicit failure cleanup for scalar temporaries, and fail-closed behavior when no used inputs are selected.
- harden `secp256k1_surjectionproof_verify()` by checking generator-load success and nonce/message generation before borromean verify.

**src/modules/surjection/surjection_impl.h**
- convert internal helper routines to explicit status returns, validating pubkey serialization in `secp256k1_surjection_genmessage`, returning `0` on failure.
- scrubbing deterministic and temporary buffers with `secp256k1_memclear`
- add guard in `secp256k1_surjection_compute_public_keys` to reject malformed bitmap/input-count states before array indexing.

**src/modules/surjection/tests_impl.h**
- document test-only relaxed handling assumptions, adjust zero-input initialize expectations so serialized-size failure is asserted as `0`.
- fix trailing-garbage parse test to use the mutated trailing buffer.

**src/modules/whitelist/main_impl.h**
- tighten whitelist signing/verification internals by introducing a fixed whitelist nonce-domain tag (`Whitelist-Sign-1`) for default and explicit nonce callbacks
- staging signatures in a temporary buffer and only committing on successful borromean signing, adding fail-closed cleanup (`memclear`) for sensitive/signature buffers and local scalars on failure
- hardening parse/serialize handling with strict key-count checks and buffer clearing before failure returns.

**src/modules/whitelist/Makefile.am.include**
- add `bench_whitelist_CPPFLAGS = -DSECP256K1_BUILD $(SECP_INCLUDES)` to ensure `-DSECP256K1_BUILD` and include paths are passed to the whitelist benchmark build.
- and static-link flags to the intended target by changing `bench_generator_LDFLAGS` to `bench_whitelist_LDFLAGS`.

**src/modules/whitelist/tests_impl.h**
- extend whitelist tests around end-to-end behavior by adding max-key validation, direct assertions, and safer malformed-length parse handling.
- add regression coverage for zero-tweak-privkey signing failure, infinity inputs to hash/tweak helpers. Wire these cases into the whitelist test runner.

**src/modules/whitelist/whitelist_impl.h**
- harden internal hash/tweak/key-derivation paths with fail-closed handling by rejecting infinity and invalid pubkeys early.
- propagating helper return codes, check for zero/point-at-infinity outcomes after core arithmetic.

**src/num.h**
- thread an explicit `int *err` error state through num conversion, modular inverse, comparison, arithmetic, modulus, and shift helpers to convert previously implicit 
failure behavior into explicit status signaling.

**src/num_gmp_impl.h**
- migrate GMP-backed sanity checks and serialization helpers to explicit error-first flow. `secp256k1_num_sanity` now takes `int *err`, validates null/size invariants.
- update integer parse/set and absolute arithmetic paths (`secp256k1_num_set_bin`, `secp256k1_num_add_abs`, `secp256k1_num_sub_abs`) to early-validate inputs and lengths and propagate errors.
- harden modular reduction by adding explicit validity and aliasing checks in `secp256k1_num_mod`, preventing divide-by-zero or in-place divisor/remainder use.
- convert `secp256k1_num_mod_inverse` to explicit failure mode with argument domain checks, enlarged internal scratch sizing for GMP (`2*NUM_LIMBS` paths), strict inverse-existence checks.
- convert `secp256k1_num_jacobi`/`secp256k1_num_is_one`/`secp256k1_num_cmp`/`secp256k1_num_eq` to explicit parameter validation and status signaling.
- thread `err` through `secp256k1_num_subadd`/`num_add`/`num_sub`, including cancellation-path canonicalization of zero and propagation checks after branch decisions.
- harden `secp256k1_num_shift` and `secp256k1_num_negate` with shift-range checks, full zero-result canonicalization.

**src/scalar.h**
- add `int *err` output parameters to `secp256k1_scalar_get_bits` and `secp256k1_scalar_get_bits_var` so bit extraction can signal malformed-limb errors.
- change `secp256k1_scalar_set_int` input type from `unsigned int` to `uint32_t` to make scalar-width assumptions explicit and avoid implementation-defined signed/unsigned conversion.
- add `int *err` output parameter to `secp256k1_scalar_shr_int` to propagate failure on invalid shift operations.
- convert `secp256k1_scalar_inverse_var` to return an `int` error.
- convert `secp256k1_scalar_get_num` and `secp256k1_scalar_order_get_num` to return error.
- change `secp256k1_scalar_split_lambda` to return status (`int`) and fail explicitly on split errors.
- tighten `secp256k1_scalar_mul_shift_var` documentation to enforce `shift` in `[256,512]` and convert it to a status-returning API.

**src/scalar_4x64_impl.h**
- replace manual clearing in `secp256k1_scalar_clear` with `secp256k1_memclear` for deterministic memory scrubbing.
- convert `secp256k1_scalar_get_bits` and `secp256k1_scalar_get_bits_var` to error-aware forms with `int *err`, add precondition checks for range/offset/count.
- change `secp256k1_scalar_shr_int` to accept `int *err`, short-circuit on prior errors.
- convert `secp256k1_scalar_mul_shift_var` to return `int`, harden shift validation (`256 <= shift <= 512`), and return explicit `1/0` error status.

**src/scalar_8x32_impl.h**
- replace manual limb-wise zeroing in `secp256k1_scalar_clear` with `secp256k1_memclear` for deterministic zeroization.
- convert `secp256k1_scalar_get_bits` and `secp256k1_scalar_get_bits_var` to error-aware forms with `int *err`; add runtime precondition checks for offset/count ranges.
- normalize `overflow` handling in `secp256k1_scalar_add` to `0/1` via `overflow = !!overflow` before reduction to avoid non-binary propagation states.
- change `secp256k1_scalar_shr_int` to take an error pointer, propagate and handle errors.
- convert `secp256k1_scalar_mul_shift_var` to return `int` with explicit success/failure path and validate `shift` for `256..512`.

**src/scalar_impl.h**
- convert `secp256k1_scalar_get_num` and `secp256k1_scalar_order_get_num` from `void` to `int`, add error propagation.
- convert `secp256k1_scalar_inverse_var` from `void` to `int`, fail fast for zero input in built-in mode, propagate error state.
- in the exhaustive endomorphism path, change `secp256k1_scalar_split_lambda` to return status `int` and add explicit success return.
- convert non-exhaustive `secp256k1_scalar_split_lambda` to return `int`, add runtime pointer-alias validation for output args, propagate errors.

**src/scalar_low_impl.h**
- switch `secp256k1_scalar_clear` to deterministic scrubbing via `secp256k1_memclear`.
- use fixed-width `uint32_t` inputs for scalar setters/bit masks.
- add `int *err` propagation and runtime validation to bit extraction and shift helpers.
- cast shift constants to `uint32_t` in conditional add.

**src/scratch_impl.h**
- add defensive comments for expected teardown/allocation error states, clear and reset the top scratch frame during deallocation.
- add guard for `frame == 0` in allocator entry, add overflow prechecks before alignment to hard-fail failed allocation paths instead of touching invalid scratch state.

**src/secp256k1.c**
- add `secp256k1_context_preallocated_clone_bytes()` - safety fix that avoids overallocating/miscalculating clone buffers.
- make `secp256k1_context_preallocated_clone_size()` reuse the new helper and keep clone-size accounting consistent with built contexts.
- harden `secp256k1_context_preallocated_create()` for bad inputs by rejecting `prealloc == NULL`, rejecting zero allocation size, initializing `illegal_callback`, and propagating failures.
- harden `secp256k1_context_create()` and `secp256k1_context_clone()` with explicit size/NULL checks, avoid trusting bad inputs, and return `NULL` on allocation/argument failure instead of continuing.
- change callback setters to accept mutable user data (`void*`) so callback payloads match existing callback ABI expectations.
- strengthen `secp256k1_pubkey_load()` by validating field conversion with `secp256k1_fe_set_b32()` and checking the full point validity via `secp256k1_ge_is_valid_var()`.
- convert signature decode to return a validation status and reject malformed `r/s` in DER/compact serialization and normalize paths.
- harden `secp256k1_ecdsa_verify()` to fail when signature decoding fails, preventing verification from continuing on malformed inputs.
- harden `secp256k1_nonce_function_bipschnorr()` by enforcing `counter == 0`, allowing optional 32-byte auxiliary data mixing, and preserving deterministic behavior.
- tighten `secp256k1_ecdsa_sign()` ABI and return semantics, zero nonce state with `secp256k1_memclear`, and return boolean success.
- harden `secp256k1_ec_pubkey_create()` against zero/overflow secrets and failed generator multiplication, with explicit early returns and secret clearing.
- make randomization and pubkey combination fail-closed by checking blinder return status and validating each combine input (`ctx` and each pubkey pointer plus load status).
- reject zero tweak values for `secp256k1_ec_privkey_tweak_inv()` and `secp256k1_ec_privkey_tweak_neg()` by adding zero checks to overflow gating.

**src/testrand.h**
- change `secp256k1_rands64` return type from `int64_t` to `uint64_t` so the helper’s return type matches inputs and eliminates ambiguity.

**src/testrand_impl.h**
- add test-only RNG state-reset comments and reseed hygiene in `secp256k1_rand_seed` by clearing cached random words, reseed index, and bit-buffer fields so reseeding cannot reuse stale state.
- change `secp256k1_rands64` return type to `uint64_t` and return `min + r` as unsigned arithmetic to align helper typing and avoid signed/negative ambiguity.

**src/tests.c**
- add context-size helpers (`expected_context_clone_size`), helper constants/validators for raw scalar tampering.
- strengthen `run_context_tests` with clone null-checks, context prealloc-size assertions, cloned no-precomp coverage, and CHECK-guarded generator-multiplication paths.
- convert num/scalar tests (`run_num_smalltests`, `test_num_*`, `scalar_test`, and `run_scalar_tests`) to error-state aware APIs (`int err` + return-code checks) and add `test_num_set_bin`/`test_num_mod_inverse` regression coverage.
- harden FE test helpers and field operations by propagating errors through `secp256k1_fe_inv_var`, `secp256k1_fe_inv_all_var`, `run_field_inv_var`, and related helpers; add explicit zero-input failure checks.
- harden group/ge tests (`test_ge`, `test_group_decompress`, ecmult chain/point order paths) with CHECKed conversion/multiplication flows, new invalid-point cases, and explicit invalid-output handling.
- harden WNAF and ecmult-constant/batch tests with new error-pointer APIs (`secp256k1_ecmult_wnaf`, `secp256k1_wnaf_const`, `secp256k1_ecmult_const`), status assertions, and stronger loop/type validation for regression determinism.
- extend eckey/pubkey parser and edge-case tests for off-curve key rejection, zero tweak behavior, and safer signature test control flow.
- add regression for private-key DER export undersize rejection, tighten openssl test paths with checked state reads, and validate test `main()` argument and seed-read inputs with clear errors.

**src/tests_exhaustive.c**
- update `random_fe` to skip zero field elements by requiring `!secp256k1_fe_is_zero(x)` in the generation loop before returning.
- convert previously unchecked cryptographic/test-internal calls to `CHECK(...)`-wrapped status assertions.

**src/util.h**
- change `secp256k1_callback` user-data field from `const void*` to `void*` so callback payloads remain mutable and match established callback signatures.
- update `checked_realloc` OOM detection to skip callback invocation when `size == 0`, aligning with standard `realloc(ptr, 0)` behavior and preventing false-positive allocation-failure handling.
- add `secp256k1_memclear()` helper using `volatile` byte writes, intended as a low-C-standard `memset_s`-style deterministic secret scrubber.
- adjust `secp256k1_clz64_var` for architectures where `unsigned long long` is wider than `uint64_t` and add a final bounds `VERIFY_CHECK(ret >= 0 && ret <= 63)` assertion.

### rust-secp256k1-zkp

**Summary of the changes:**
- Switch from `Rng`/`thread_rng` to secure but faillable `SysRng`.
- Make Secp256k1 non clonable and not sharable between threads because it is not thread safe by design.
- Update wrappers to be consistent with FFI.
- Handle and propagate the errors.
- Update interfaces that can leak sensitive data.

**Cargo.toml**
- enable `bullet-proof-sizing` in the default feature set and remove the obsolete `dev = ["clippy"]` feature.
- dependency cleanup/hardening.

**build.rs**
- change build script `main` to return Result, enabling fallible build steps to propagate explicit errors.
- remove the `-g` compiler flag from the native C build path for release, avoiding debug-symbol generation in release artifacts.
- make compiler discovery fallible, reported through the build script result instead of panicking.
- replace `compile("libsecp256k1.a")` with `try_compile("libsecp256k1.a")?`, so native library compilation failures propagate cleanly.

**fuzz/fuzz_targets/fuzz_aggsig.rs**
- update RNG imports from `Rng`/`thread_rng` to `TryRng` and `SysRng`.
- switch harness randomness to `SysRng` and unwrap `Secp256k1::with_caps(ContextFlag::Full)`, making context creation failure explicit instead of assuming infallible setup.
- update aggregate-signature context creation to the new `AggSigContext::new(&pks).unwrap()` API, removing the old `secp` argument and surfacing construction failures.
- unwrap the new fallible nonce-generation and random-message APIs (`generate_nonce` and `try_fill_bytes`) so setup errors fail fast during fuzz execution.
- change combined-signature verification to use the new `verify(full_sig, msg)` API and assert that verification returns `true`.

**fuzz/fuzz_targets/fuzz_ecdh.rs**
- unwrap `Secp256k1::new` and `SharedSecret::new` so errors become explicit fuzz failures instead of being hidden.

**fuzz/fuzz_targets/fuzz_sign.rs**
- unwrap `Secp256k1::new()` so context initialization failures become explicit fuzz failures instead of being hidden.

**src/aggsig.rs**
- harden `export_secnonce_single` by rejecting verify-only/no-capability contexts, generating the FFI seed with `SysRng`, zeroizing the seed after use, returning a nonce-specific error on FFI failure, constructing the returned `SecretKey` from validated bytes.
- replace the zero-prefix public-key macro with `is_valid_pubkey`, using full public-key validation.
- change `sign_single` to return `AggSigSignature`, require `pubkey_for_e` as a non-optional valid public key, reject incapable contexts, validate optional nonce public keys, use `SysRng` plus seed zeroization.
- change `verify_single` to return `Result`, use `AggSigSignature`, require a valid `pubkey_total_for_e`, reject sign-only/no-capability contexts, validate signatures and public keys before FFI, report malformed verification inputs.
- harden `verify_batch` by returning `Result`, rejecting incapable contexts and oversized batches, validating all public keys and signatures, treating length/input mismatches as failed verification, checking scratch-space allocation.
- update `add_signatures_single` to use `AggSigSignature`, reject incapable contexts, reject empty input, validate the total nonce and all input signatures, validate the combined signature after the FFI call.
- `subtract_partial_signature` for `AggSigSignature`, validate both input signatures before FFI, use zero-initialized signature outputs, validate every returned signature variant, and map unexpected FFI return values to `GenericError`.
- refactor `AggSigContext` ownership and construction by removing `Clone`, storing an owned optional full `Secp256k1` context plus participant public keys, validating participant count and keys, use `SysRng` with seed zeroization, checking for null context creation.
- change `generate_nonce` to return `Result`, validate signer index bounds, fail on a broken aggregate context, propagate failures.
- change `partial_sign` to require mutable context access, validate signer index and context state, use the owned context pointer, mark the aggregate context broken/destroyed on FFI signing failure.
- change `combine_signatures` to require mutable context access, enforce that the partial-signature count matches the participant set, propagate errors.
- change aggregate verification `verify` to use the context's stored participant set instead of caller-provided keys, return `Result`, validate the combined signature, centralize destruction through a null-checking helper used by `Drop`.
- update existing tests to cover the changes.
- add regression coverage for invalid aggregate signatures, including all-zero signatures and non-liftable x-coordinate signatures, and add compact serialization/parsing validation for `AggSigSignature`
- add direct capability tests for `export_secnonce_single`, `sign_single`, and `verify_single`, confirming which context capabilities are accepted or rejected.

**src/ecdh.rs**
- make `SharedSecret::new` return `Result`; validate the input public key before calling FFI, propagate errors.
- for `SharedSecret` replace derived `Clone`, `PartialEq`, `Eq`, and `Debug` with explicit implementations; `Debug` now redacts the secret bytes, equality is constant-time over the shared-secret bytes, and `Clone` reconstructs the wrapper from byte data.
- update all `SharedSecret` index implementations to read through `ffi::SharedSecret::as_bytes()` to keep byte access behind the explicit FFI byte-slice accessor.
- update the ECDH unit test by using `SysRng`, handling new emitted errors.
- update the benchmark by using `SysRng` and unwrap fallibles.

**src/ffi.rs**
- update `NonceFn` to match the hardened C nonce callback contract.
- make `Generator` explicitly `Clone`, remove raw array/debug helper exposure by security reasons, introduce a typed `PedersenCommitment` opaque wrapper with a zeroed FFI constructor.
- restrict `PublicKey` raw storage to crate visibility, disable serde helper generation by security reasons, make the zeroed constructor crate-private.
- disable serde helper generation for raw `Signature` and `RecoverableSignature` wrappers and remove direct raw-data/blank constructors, narrowing public construction paths for opaque signature objects.
- remove array helper and raw debug exposure from `SharedSecret` (security reasons), make `blank` safe, add explicit byte/pointer accessors, zeroize the secret bytes on drop.
- add the typed illegal-callback function binding used by public-key validation.
- align aggregate-signature and batch Schnorr FFI types with the C API.
- replace raw commitment and generator byte pointers across Pedersen commitment parse/serialize/commit/sum/tally/switch APIs with typed `PedersenCommitment`, `Generator`, and `PublicKey` pointers.
- type rangeproof commitment/generator arguments as `PedersenCommitment` and `Generator`, and change min/max outputs in verify to raw mutable pointers, matching the C API's output-parameter style.
- type bulletproof generator creation and proof creation inputs as `Generator`/`PedersenCommitment` pointers, keeping proof generation ABI calls on opaque wrapper types instead of raw byte arrays.
- type bulletproof verify and verify-multi commitment/generator arguments as opaque wrappers and make multi-proof `extra_commit_len` mutable, matching the C API's parameter mutability.
- update bulletproof rewind to the newer C ABI.

**src/key.rs**
- disable the array macro's serde/compact helper generation for `SecretKey` by security reasons, replace row debug with a redacted `Debug` implementation.
- make random secret-key generation fallible, mapping RNG failures to `SysRngFailure`, validating generated bytes through `SecretKey::from_slice` before returning them.
- harden `SecretKey::from_slice` propagating failures, distinguishing all-zero input as `ZeroSecretKey`, and copying bytes only after validity is proven.
- add constant-time `PartialEq`/`Eq` for `SecretKey`, avoiding early-exit equality comparisons on secret bytes.
- add explicit `SecretKey` serde support that serializes raw bytes but validates deserialized data before constructing a key.
- replace public `PublicKey::new` with crate-private `blank()` for internal FFI buffers, and add `pub_j_raw()` to construct the J-generator public key from the raw constant.
- harden `PublicKey::from_combination` by rejecting incapable contexts, empty input, and invalid public keys.
- expand `PublicKey::is_valid` to require a context, reject all-zero keys, add validation by serializing through FFI with illegal-callback detection, verify the serialized length, reparse the result.
- replace infallible FFI public-key conversion with `from_secp256k1_pubkey(secp, pk) -> Result<PublicKey, Error>`, validating the wrapped key before returning it.
- make `PublicKey::from_secret_key` propagate the errors instead of relying on a debug assertion and unconditional success.
- enforce canonical SEC1 encodings in `PublicKey::from_slice`, rejecting invalid sizes, bad compressed/uncompressed prefixes, and hybrid 65-byte public keys before parsing.
- make public-key serialization `serialize_vec` fallible by returning `Result`, rejecting zero keys, detecting illegal callbacks, checking FFI return status and output length.
- harden public-key add/multiply by validating `self` before FFI, preserving capability checks, and mapping FFI failures to `GenericError` instead of misreporting them as invalid secret keys.
- update public-key serde paths for propagating serialization errors through serde instead of assuming compressed serialization always succeeds.
- extend public-key parsing tests to reject hybrid SEC1 encodings, add direct `is_valid` coverage for valid, zero, and malformed non-zero FFI public keys.
- update keypair, invalid-secret, context-capability, and tweak tests to use `SysRng`, unwrap api the returns error.
- extend serde negative/positive coverage by rejecting zero secret-key input, accepting a known valid secret key, round-tripping a generated `SecretKey`, and rejecting hybrid public-key encodings.
- migrate serde round-trip, out-of-range RNG, and bad-public-key slice tests to `SysRng`, `TryRng`, `TryCryptoRng`, and fallible context creation.
- update debug and serialization tests for the new RNG traits, avoid relying on raw `SecretKey` debug output by formatting the inner byte array directly, and unwrap the new fallible public-key serialization results.
- update arithmetic, combination, inverse, negate, and hash tests to use fallible context constructors, `SysRng`, fallible key generation, and constant-time equality assertions where secret keys are compared.

**src/lib.rs**
- split the old generic `Signature` wrapper into explicit `EcdsaSignature` and `AggSigSignature` types, and add secp256k1 field-prime/aggsig `R.x` validation helpers that reject zero, out-of-range, and non-liftable x-coordinates.
- introduce a shared signature-wrapper macro for FFI pointer access and indexing, apply it to both signature types, and limit raw `AsRef<[u8]>` exposure to legacy aggsig usage.
- harden ECDSA signature parsing and serialization by adding `is_valid`, validating DER/compact parse outputs as non-zero in-range scalars.
- add the `AggSigSignature` API with blank construction, structural validation, fallible compact parsing/serialization, validated raw aggsig serialization, and validated raw-data construction so malformed or blank aggsig signatures fail closed.
- update `EcdsaSignature` serde support to use fallible context creation, fallible compact serialization/deserialization, and serde error propagation instead of assuming context and signature operations cannot fail.
- add `AggSigPartialSignature::as_ffi()` so callers can copy the FFI representation explicitly.
- harden recoverable signatures `RecoverableSignature` by adding a zeroed constructor and mutable pointer accessor, checking compact parse/serialize/convert FFI return values, returning `Result` from compact serialization and standard conversion, validating converted ECDSA signatures.
- expand `Error` with specific failure variants for zero secret keys, system RNG failure, generic secp errors, rangeproof generation, nonce export, invalid parameters, serialization, allocation, and broken aggsig contexts.
- add optional bulletproof-generator ownership to `Secp256k1`, destroy it in `Drop`, disable `Send`, `Sync`, `Clone`, and equality support.
- make context creation fallible by returning `Result`, checking null context creation, initializing bulletproof state, randomizing sign-capable contexts with `SysRng`, zeroizing the randomization seed, and mapping RNG/randomization failures to explicit errors.
- update keypair and signing APIs to require `TryCryptoRng`, propagate secret/public-key generation failures.
- harden public-key recovery and verification by validating recovered FFI public keys through the public-key wrapper, accepting only `EcdsaSignature` in `verify`, rejecting malformed signatures and public keys, mapping verification status explicitly.
- lines 969-1075: update capability/invalid-input tests for the new fallible constructors, `SysRng` RNG API, fallible public-key serialization, `PublicKey::blank`, fallible recoverable conversion.
- add a regression that zeroed ECDSA signatures are rejected before verification.

**src/macros.rs**
- split `impl_array_newtype!` into default, `no_serde`, and `no_serde_no_comp` entry points, letting security-sensitive or opaque FFI wrappers suppress serde and comparison/hash helpers.
- replace the unsafe `MaybeUninit` plus `copy_nonoverlapping` clone implementation with a direct `$thing(self.0.clone())`.
- move `Hash`, `PartialEq`, `Eq`, `PartialOrd`, and `Ord` generation into an internal `@compare` block so callers can intentionally disable comparison/hash APIs for wrappers where those operations should not be exposed.
- move serde `Deserialize`/`Serialize` generation into an internal `@serde` block, allowing the new `no_serde` forms to avoid serialization support for raw or sensitive wrapper types.
- narrow `map_vec!` input from an arbitrary expression to an identifier, making the macro contract stricter and matching direct vector variable usage.

**src/pedersen.rs**
- make `Commitment::from_vec` fallible and exact-length only, make blank commitment construction safe/internal, validate public keys before converting them to commitments, use typed FFI commitment outputs.
- harden commitment-to-public-key conversion by parsing the serialized commitment.
- make `RangeProof` equality and serde length-aware.
- replace the zero-prefix public-key macro `is_valid_pubkey` with full `PublicKey::is_valid` checks for optional multisig proof public keys.
- change `RangeProof::bytes` and `RangeProof::len` to return `Result`, add `is_valid`, and reject proof lengths above `MAX_PROOF_SIZE`.
- make `ProofMessage::from_bytes`, `truncate`, and `push` enforce `PROOF_MSG_SIZE` and return errors; redact `ProofMessage` debug output.
- guard `RangeProof` debug formatting with `is_valid` so malformed proof lengths print as invalid instead of slicing unchecked.
- switch `verify_from_commit` to `EcdsaSignature`, propagate commitment-to-public-key errors, use typed commitment parse/serialize helpers, check serialization return status, add `validate_commitment` for canonical parse/serialize validation.
- update `commit`, `commit_blind`, and `commit_value` to use typed commitment/generator FFI pointers, return `InvalidCommit` on failure instead of assuming success.
- change `verify_commit_sum` to return `Result` and propagate parse failures, update `commit_sum` to use typed commitment pointer vectors and typed serialization.
- harden blinding helpers by rejecting empty blind sums, checking native return values, validating derived secret keys, zeroizing temporary secret buffers, using typed switch-commitment generators/public key, replacing `thread_rng` nonce generation with fallible `SysRng`.
- make non-bulletproof-sizing `range_proof` fallible, add capability checks, propagate commitment parse failures.
- make non-bulletproof-sizing `verify_range_proof` reject invalid proof lengths and incapable contexts, propagate commitment parse errors.
- make non-bulletproof-sizing `rewind_range_proof` return `Result`, reject invalid proofs and incapable contexts, propagate commitment/message parsing errors.
- make `range_proof_info` return `Result`, add capability/proof-length validation, and map failed FFI info extraction to `InvalidRangeProof`.
- make `bullet_proof` require mutable context access, return `Result`, validate capabilities, use fallible message padding/truncation, use per-context shared generators, check scratch allocation, use typed generators, enforce proof length, and surface generation failure.
- harden `bullet_proof_multisig` by returning `Result`, validating step-specific pointer/nullability contracts, validating public-key inputs, propagating errors, checking final proof length.
- make `verify_bullet_proof` require mutable context access for generator ownership, reject incapable contexts and invalid proof lengths, propagate errors.
- harden `verify_bullet_proof_multi` by rejecting empty or mismatched inputs, enforcing equal valid proof lengths, validating extra-data vector length.
- extend `rewind_bullet_proof` with optional `private_nonce`, add capability and proof validation, update the FFI call to the newer typed generator/commitment ABI, check scratch allocation, build `ProofInfo` through fallible message construction.
- add `shared_generators` as a per-context lazy initializer, storing generators on `Secp256k1` instead of using the removed global `OnceLock` cache.
- update commitment parse/serialize tests for fallible context creation and typed commitments, and add coverage for `validate_commitment` rejecting malformed serialized commitments.
- update commit-sum tests to unwrap the new `Result<bool, Error>` return and keep the positive/negative tally expectations.
- add regression coverage that a blind sum producing a zero scalar returns `ZeroSecretKey` instead of yielding an invalid secret.
- update multiple tests for `SysRng`, fallible key generation, and the new fallible APIs.
- add negative-path multisig coverage for invalid commitment counts, missing private nonce, invalid step-2 public-key state, and invalid step numbers.

### easy-jsonrpc-mwc

**Summary of the changes:**
- update dependencies.
- harden types, update error messages to eliminate possibility of leaking of internal data.
- update some API responses to match JSON-RPC 2.0 contract.
- propagate errors

**Cargo.toml**
- update dependencies, using latest versions.

**examples/http_connect.rs**
- make response deserialization explicit with `.json::<Value>()`, ensuring the example parses HTTP responses as `serde_json::Value` without relying on type inference.

**examples/http_listen.rs**
- make few changes to address dependencies updates

**proc_macros/Cargo.toml**
- update dependencies, using latest versions.

**proc_macros/src/lib.rs**
- update client helper generation to use `Signature` method metadata and the newer `ToSnakeCase` trait.
- change generated argument serialization failures from a generic `ArgSerializeError` to `ArgSerializeError::from_serde` with the argument name and underlying serde error for better diagnostics.
- migrate return-type helper logic from `MethodSig.decl.output` to `Signature.output`.
- update trait method discovery from `TraitItem::Method` to `TraitItem::Fn` and `Signature`.
- change argument parse failures to use `InvalidArgs::invalid_arg_structure` with argument name, index, and a sanitized `"parsing error"` message so serde internals are not exposed to external clients.
- migrate method argument extraction to `Signature.inputs` and `FnArg::Receiver`, preserving the requirement that the first argument is an immutable `&self`.

**src/lib.rs**
- change raw request deserialization failures from JSON-RPC parse errors (`-32700`) to invalid request errors (`-32600`), matching the fact that this API receives already-parsed JSON values.
- include JSON-RPC 2.0 version metadata when returning an invalid-call response.
- reject calls whose `jsonrpc` version is not `2.0`; notifications are silently skipped, while method calls receive an invalid-request failure with JSON-RPC 2.0 response metadata.
- harden batch request handling by rejecting empty batches and batches larger than `BATCH_LEN_LIMIT`, detecting duplicate non-notification IDs, returning a single validation failure instead of processing ambiguous or excessive batches.
- extend `InvalidArgs` with `DuplicateArgumentName`, add source details to `InvalidArgStructure`.
- prevente duplicate argument names from passing in requests.
- replace random request IDs with a predictable atomic counter.
- make `Call::batch_request` fallible and validate client-side batches for empty input, excessive length, and duplicate request IDs before returning the JSON array.
- change `ArgSerializeError` from a unit/copy type into a diagnostic struct containing the argument name and source string.
- extend `InvalidResponse` with duplicate response ID, oversized batch response, empty response, and invalid JSON-RPC version cases.
- harden response parsing by rejecting empty or oversized response batches, validating JSON-RPC 2.0 on success and failure outputs, requiring numeric IDs, and detecting duplicate IDs while building the response map.

### mwc-node/mwc_crates

**Summary of the changes:**
Declare all common creates for mwc-node and mwc-wallet in this crate. Having all crates at single location helps maintain 3-rd party crates and versions.  

**Cargo.toml**
- declare all crates the mwc-node was used, except `rust-secp256k1-zkp` and `thiserror`. Group crates.

**src/lib.rs**
- reexport all owned crates.
- reexport exported crates form rust-secp256k1-zkp.

### mwc-node/util

**Summary of the changes:**
- error propagations.
- harden IO related utils.
- control data content, so attacker adjust visible data with special symbols.

**Cargo.toml**
- remove imported crates, add `mwc_crates` instead.
- add thiserror (it can't be reexported)

**src/async_runtime.rs**
- add a global initialization mutex plus `init_global_runtime`, making runtime construction an explicit fallible startup step, preserving Tokio's worker-thread environment behavior.
- change `global_runtime` to return `Result<&'static Arc<Runtime>, Error>` and report use-before-initialization.
- make `run_global_async_block` return `Result`, remove the `Send` bounds, add errors classifications.
- update the nested async-runtime regression test to initialize the global runtime explicitly.

**src/file.rs**
- add `OwnerOnlyFile` to distinguish a trusted owner-only file handle from a group/other-readable exposed file whose contents should not be trusted.
- change `delete` to use `symlink_metadata`, treat missing paths as successful deletion, remove non-directories, propagate metadata errors.
- document plaintext-copy, symlink, permission, and counter-saturation behavior for directory copies; canonicalize source and destination roots; reject overlapping copy trees; validate that an existing destination is a directory; create only missing destinations.
- add `resolved_destination_path` helper to canonicalize an existing destination or its existing parent before overlap checks.
- make `list_files` return `io::Result`, propagate IO errors.
- make `get_first_line` return `io::Result`, propagate IO errors.
- add owner-only first-line readers, including a zeroizing variant that requires owner-only file access.
- add owner-only open APIs that reject exposed files in the strict path.
- add a zeroizing whole-file reader that checks file length conversion.
- add owner-only write helpers for create-or-truncate and create-new flows, syncing file contents, cleaning up newly-created partial files on write/sync failure as best effort.
- add shared owner-only file creation entry points plus `write_all_and_sync`, parent-directory sync, parent normalization helpers used by the hardened write paths.
- add the Unix owner-only create implementation with regular-file preflight checks, rejection of group/other-writable existing files.
- add the non-Unix owner-only create fallback using portable open options and regular-file validation, leaving owner-permission enforcement to platform-specific callers.
- add a shared metadata helper that rejects symlinks and non-regular files before owner-only reads.
- add the Unix owner-only open implementation with pre-open symlink/permission classification.
- add Unix mode classification that rejects group/other-writable files.
- add the non-Unix owner-only open fallback with portable symlink and regular-file checks.

**src/hex.rs**
- change hex encoding `to_hex` from formatting-based writes with a placeholder fallback to table-based nibble conversion.
- make `from_hex` return the `Error` type instead of `String`, trim input while accepting a single optional `0x` prefix, parse ASCII byte pairs through a shared nibble decoder, report errors.
- add `decode_secret_key_hex` for fixed-length secret-key decoding into `Zeroizing<[u8; N]>`.
- add `hex_value` to centralize ASCII hex digit conversion for lowercase and uppercase input and reject invalid symbols without per-byte string parsing.
- update hex tests to unwrap successful structured results, cover new functionality and errors handling.

**src/lib.rs**
- add the crate-wide `Error` to report new supported errors.
- convert `OneTime` from panic-based initialization and borrow checks to `Result`-returning APIs.
- update base64 encoding to the current `Engine` API from the shared facade.
- add `escape_to_printable_ascii`, which escapes control and Unicode characters so user-facing/logged strings can be forced to printable ASCII.
- add regression coverage for `escape_to_printable_ascii`.

**src/logger.rs**
- bind log entry and logging config serde derives to the explicit shared serde crate, widen buffered log timestamps from `u64` to `u128` to preserve `as_millis()` without truncation.
- replace `MwcFilter` and the message-only tracing visitor with `EventVisitor` plus `SanitizingEncoder`, capturing non-message tracing fields, combining them into the emitted message, and escaping untrusted log text.
- update tracing-to-log forwarding to build a `log::Record` with mapped log level, target/module, file, and line metadata, then submit it directly to the active logger instead of re-emitting through logging macros that lost structured fields and metadata.
- make the TUI channel appender use the non-poisoning mutex path, build the `LogEntry` before sending, and return explicit append errors when the bounded TUI log channel is full or disconnected.
- change `init_logger` errors to return the `Error` type, propagate errors into new type.
- change `init_test_logger` to return `Result`, use the non-poisoning lock, sanitize test log output, propagate config/init failures.
- harden callback appender buffering by using the non-poisoning global buffer lock, trimming only while the retained buffer is above the configured size, propagating errors, switch to `checked_add` so counter overflow stops buffering cleanly.
- change callback logger initialization to return `Error`, reject repeated callback logger configuration, sanitize callback log messages, remove the deleted module-prefix filter, propagate errors.
- make buffered log reads return `Error`, propaget errors, handle empty or stale buffers explicitly, use safe arithmetic through `usize::try_from` and `checked_`.

**src/macros.rs**
- replace the panic-based `From<&[$ty]>` implementation with fallible `TryFrom<&[$ty]>`, validate the input length explicitly, copy only after validation so fixed-size newtype construction reports bad input instead of asserting.
- update `Clone` to construct directly from the cloned backing array instead of routing through slice conversion.
- switch serde deserialization and visitor trait references from crate-root reexports to direct `serde`/`std` paths.
- harden fixed-array sequence deserialization by using direct `serde` `SeqAccess`, tracking the failing element index, rejecting trailing elements with an extra `IgnoredAny` probe so deserialization enforces the exact array length.
- switch serde serialization trait references to direct `serde` paths, matching the deserialization-side dependency cleanup.

**src/ov3.rs**
- for `OnionV3Error` bind error serde derives to the shared serde crate and add `InvalidOnionV3Address`.
- remove derived serde from `OnionV3Address` and make `from_bytes` fallible; raw 32-byte inputs now must parse as an Ed25519 verifying key and pass canonical/weak-key validation before onion address object is constructed.
- update private-key conversion to the current Dalek `SigningKey`/`VerifyingKey` API, reject weak derived public keys, run the shared public-key validation path, return only validated verifying-key bytes.
- change `to_ed25519` to return a Dalek `VerifyingKey`, classify parse failures as invalid onion addresses, validate the stored key bytes before returning the public key to callers.
- make `to_ov3_str` public, replace manual SHA3/base32 checksum construction with `tor_hsservice::HsId` formatting through `DispUnredacted`.
- add `validate_pk` to reject weak or non-canonical compressed Edwards public keys.
- replace derived `OnionV3Address` serde with manual serialization/deserialization, preventing invalid address state from entering through serde.
- harden hex public-key parsing by using exact `[u8; 32]` conversion.
- replace custom uppercase/base32/checksum onion parsing with normalized Tor `HsId::from_str` parsing; trim/lowercase input, keep support for `http://` and `https://`, accept hostnames with or without `.onion`.

**src/rate_counter.rs**
- replace wall-clock epoch-millisecond imports with `VecDeque` support and monotonic `Duration`/`Instant` timing, eliminating system-time conversion and clock-adjustment dependence in rate-window calculations.
- change `Entry` timestamps from `u64` epoch milliseconds to `Instant`, initialize entries with `Instant::now`.
- store recent entries in a `VecDeque`, add the `RATE_ENTRIES_LIMIT` cap, preparing bounded FIFO eviction instead of vector front removal.
- remove the `inc_quiet` API, truncate before adding a new entry.
- remove the `millis_since_epoch` helper because rate timing now uses `Instant` directly.

**src/secp_static.rs**
- replace the single lazy-static `Arc<Mutex<Secp256k1>>` commitment context with four thread-local cached contexts for `None`, `Full`, `VerifyOnly`, and `Commit` capabilities, avoiding cross-thread secp256k1 context sharing and global mutex contention.
- add `create_context` to centralize capability-specific context construction.
- add the shared immutable `with_context` helper, borrowing the cached thread-local context when available and falling back to a temporary context.
- add the shared mutable `with_context_mut` helper with the same cached-error propagation and temporary-context fallback when the thread-local context is already borrowed.
- replace `static_secp_instance`, which locked the global context, for all types of the contexts.
- fix `commit_to_zero_value` to construct a zero commitment from a full `PEDERSEN_COMMITMENT_SIZE` zero-byte buffer, replacing the previous one-byte vector that could produce malformed commitment data.
- add a regression test proving nested immutable and mutable commitment-context access succeeds by using the temporary-context fallback during reentrant thread-local borrows.

**tests/file.rs**
- update the directory-copy regression to unwrap the new fallible `file::list_files` API.
- add tests to cover the new and updated functionality in files.

### mwc-node/keychain

**Summary of the changes:**
- error propagations.
- multiple refactors to achieve safer implementation, so we could pass the audit.

**Cargo.toml**
- remove imported crates, add `mwc_crates` instead.
- add thiserror (it can't be reexported)

**src/base58.rs**
- add `InvalidData` plus `DataOverflow` variants for `Error`.
- make raw base58 decoding return `Zeroizing<Vec<u8>>`, switch to checked multiplication/addition, harden decode digit processing by using checked table bounds (`>=`), build the decoded output in a zeroizing vector.
- make base58check decoding return `Zeroizing<Vec<u8>>`.
- make UTF-8 base58 encoding fallible, calculate output capacity and leading-zero counts with checked arithmetic.
- make string encoding return `Result`.
- propagate fallible encoding through formatter.
- update tests to use `mwc_util::from_hex`, address all changes done for this API.

**src/extkey_bip32.rs**
- stop using the generated `ChainCode` debug/show implementation and replace it with a redacted `Debug` formatter, preventing chain-code bytes from being exposed in logs or diagnostics.
- at `BIP32Hasher` make BIP32 HMAC append/finalize operations fallible, make changes to support that.
- add an explicit child-number limit plus custom serde wrapper, validate child indexes during serialization/deserialization and `TryFrom<ChildNumber> for u32`, report out-of-range values.
- add `DataOverflow`, `ChildNumberOutOfRange`, and `SeedLengthOutOfRange` variants to the `Error`.
- validate master seed length against the BIP32 16-64 byte range, propagate fallible hasher operations, zeroize HMAC output, use fallible child-number and chain-code construction.
- add fallible `ExtendedPrivKey::to_base58`, validating the child number and propagating Base58Check encoding errors instead of relying on an infallible formatter.
- harden private child derivation and private-key fingerprinting by validating child-number conversion, propagating public-key serialization and HMAC errors, zeroizing derived HMAC material, checking depth increments for overflow, using fallible chain-code/fingerprint construction.
- make `from_private` propagate errors, reject network mismatches before producing an extended public key.
- reject public derivation when the hasher network does not match the extended public key, validate normal child indexes, propagate public-key serialization and HMAC errors, and build returned chain codes through fallible conversion.
- replace the former `Display`-based extended-key serialization path with explicit `to_base58` plus hardened parsing.
- add regression tests for rejecting extended public keys encoded with private or unknown network versions, rejecting malformed master-key metadata, and failing Base58 serialization for invalid child numbers.

**src/keychain.rs**
- add `MaskedMasterKey`, `MasterKeyState`, an integrity-tag helper, XOR masking helper, store masked secret bytes in zeroizing memory, redact sensitive debug fields, reject unmasking with an invalid mask instead of blindly toggling key bytes.
- store the master as explicit masked/unmasked state, expose the master key through a fallible accessor that reports `KeychainMasked`.
- make `from_seed` and `from_mnemonic` take a caller-provided secp context.
- propagate fallible key-path construction for root and derived identifiers.
- reject invalid path depths before indexing path data, derive from the unmasked master only, and route switch blinding through the supplied secp context.
- make commitment creation use the caller's secp context and the updated fallible key-derivation path instead of the removed keychain-owned secp instance.
- harden `blind_sum` construction by rejecting masked keychains, checking positive/negative vector capacity arithmetic, propagating invalid key-path and blinding-factor errors, returning an explicit zero blinding factor when the secp sum resolves to `ZeroSecretKey`.
- update key-derivation tests to shared secp/RNG imports 
- add masked-keychain regression coverage for masked access failures.
- add blind-sum regressions for zero-sum results, positive-only factors, and negative-only factors so edge cases return stable `BlindingFactor` values.

**src/mnemonic.rs**
- at `Error` remove the invalid mnemonic word from `BadWord` errors so caller input is not echoed, and add explicit invalid-passphrase and data-overflow variants.
- at `search ` zeroize the searched word copy, use safe convertion with `u16::try_from`, stop returning the rejected word in `BadWord`.
- split mnemonic parsing into `mnemonic_words` plus `to_entropy_from_words`, keep parsed words and word indexes in zeroizing buffers, preserve word-count validation before decoding.
- replace unchecked checksum-mask and entropy-length arithmetic with checked shifts, checked multiplication/subtraction, checked `u8` conversion; store decoded entropy in a zeroizing vector.
- harden mnemonic bit unpacking by using checked index arithmetic, bounds-checked entropy access, use checked increments.
- make `from_entropy` return `Zeroizing<String>`, use checked checksum-mask, checksum-shift, and word-count arithmetic, zeroize the hash buffer, keep generated word indexes in zeroizing storage.
- harden entropy/checksum bit packing into word indexes with checked shifts, bounds-checked index access, documented bounded word-index shifts, and checked location increments.
- replace unchecked word-list indexing with `WORDS.get`, keep the selected words in zeroizing storage, and return the mnemonic string as a zeroizing value.
- simplify `to_seed` to a fixed `&str` passphrase API returning `Zeroizing<[u8; 64]>`, reject non-ASCII passphrases, canonicalize mnemonic whitespace, zeroize salt and seed buffers, propagate PBKDF2 output errors.
- add regression tests coverage proving extra spaces, tabs, and newlines decode to the same entropy and seed as canonical mnemonic whitespace.
- update the random round-trip test to the newer RNG API.

**src/types.rs**
- update `Error`: make BIP32 errors convert through `#[from]`, add masked-keychain, invalid-mask, data-overflow, invalid-depth, and invalid-length variants, replace deprecated secp `description()` formatting with the current display path.
- make serialized-path, byte-slice, and public-key identifier construction fallible; require exact serialized lengths, reject path depths above four, validate reconstructed key paths, stop silently padding/truncating byte slices, and propagate public-key serialization errors.
- remove derived equality/zeroize-drop for `BlindingFactor`, add shared-serde binding, implement constant-time equality, and explicitly zeroize secret bytes in `Drop`.
- add a strict zeroizing blinding-factor hex decoder that trims input, accepts an optional `0x` prefix, validates length and symbols before decoding, returns sanitized errors without echoing rejected secret material.
- make blinding-factor construction fallible for slices and random generation, require exact secret-key length, use `SysRng`.
- update secret-key extraction and factor addition to use current secp error formatting, propagate errors, return the zero blinding factor when a valid sum resolves to `ZeroSecretKey`.
- store explicit blinding factors in `BlindSum` as boxed values so vector growth moves stable pointers instead of copying secret bytes.
- add max-depth constants, bind `ExtKeychainPath` serde to the shared crate path.
- update the `Keychain` trait to require caller-provided secp contexts, remove the hidden random-seed constructor and `secp()` accessor, make private-root-key access fallible.
- add regression tests for invalid blinding-factor scalars, zero-factor acceptance, sanitized hex failures, inverse-factor zero sums, and rejection of non-zero path components beyond the active depth.

**src/view_key.rs**
- update the view-key contract to track full derivation paths, make `depth` private, store the path in the crate-wide bounded path array, wrap `rewind_hash` in `Zeroizing<Vec<u8>>`, and replace derived `Debug` with a custom formatter that redacts the rewind hash.
- make `ViewKey::create` reject non-root inputs with `InvalidDepth`, build the switch public key through the public secp helper, zeroize the rewind hash, and initialize the tracked root path.
- make `ViewKey::rewind_hash` fallible by propagating public-key serialization errors, and add `depth()` plus `path()` accessors.
- validate normal child-number indexes before public derivation, propagate errors, and build the derived chain code through `TryFrom`.
- derive child view keys with fallible tweak handling, use the public generator helper for switch-key derivation, check depth increments against `MAX_DEPTH_USIZE`, update the stored path, propagate fingerprint errors.
- implement regular switch-commitment view-key support instead of returning error.
- make identifier and fingerprint calculation return `Result`, propagate public-key serialization failures, and construct fingerprints through `TryFrom` with explicit error reporting.
- add regression tests proving `Debug` redacts the rewind hash, regular switch commitments produced from view keys match keychain commitments, and derived view keys preserve the full child path.

### mwc-node/core

**Summary of the changes:**
- error propagations.
- switch to safe math and types conversions.
- validate data on serialization, deserialisation, conversions.

**Cargo.toml**
- remove imported crates, add `mwc_crates` instead.
- add thiserror (it can't be reexported)
- add `blake2` for testing of secure zeroize implementation 

**fuzz/Cargo.toml**
- add `mwc_crates` instead.

**fuzz/fuzz_targets/block_read_v1.rs**
- address functions signature changes to make fuzz test be able to run

**fuzz/fuzz_targets/block_read_v2.rs**
- address functions signature changes to make fuzz test be able to run

**fuzz/fuzz_targets/compact_block_read_v1.rs**
- address functions signature changes to make fuzz test be able to run

**fuzz/fuzz_targets/compact_block_read_v2.rs**
- address functions signature changes to make fuzz test be able to run

**fuzz/fuzz_targets/transaction_read_v1.rs**
- address functions signature changes to make fuzz test be able to run

**fuzz/fuzz_targets/transaction_read_v2.rs**
- address functions signature changes to make fuzz test be able to run

**fuzz/src/main.rs**
- address functions signature changes to make fuzz test be able to run

**src/consensus.rs**
- add a consensus `Error` enum for overflow, short history, header IO, invalid edge bits, duplicate initialization, and invalid-parameter failures
- make `reward` return `Result<u64, Error>` and replace saturating reward-plus-fee addition with checked addition.
- make `graph_weight` fallible, reject edge bits below the configured base edge bits, and use checked shift/multiply operations so invalid graph parameters or arithmetic overflow become explicit consensus errors while preserving the post-hard-fork weight behavior.
- add `IntoHeaderDifficultyInfo` so difficulty iterators can provide either direct header difficulty values or fallible results.
- make `damp` and `clamp` return `Result` and use checked math.
- make `next_difficulty` fallible, replace the caller-owned `VecDeque<HeaderDifficultyInfo>` cache with `DifficultyCache`, split calculation into `next_difficulty_from_diff_data`, propagate difficulty-data and secondary-scaling errors, use checked timestamp subtraction, accumulate difficulty in `u128`, saturate only the final overlarge difficulty to `u64::MAX - 1` to keep the chain live.
- add `validate_difficulty_data_sequence` difficulty-window validation requiring the requested height to follow the latest real header, synthetic padding to appear only before real headers, timestamps to increase strictly, and real header heights to remain contiguous.
- make `secondary_pow_scaling` return `Result`, propagate fallible damp/clamp operations, and intentionally saturate overlarge secondary scaling to `u32::MAX` when the balancing formula exceeds the return type.
- simplify how we handle epochs. Make epoch durations optional, add an explicit one-block epoch for the final reward, treat later epochs as unbounded/no-duration, return `u64::MAX` for offsets beyond bounded epochs, and guard the epoch loop increment with `overflowing_add`.
- make epoch `12` explicitly return `MWC_LAST_BLOCK_REWARD` and make all later epochs return zero reward instead of letting every fallback epoch receive the final reward.
- at `calc_mwc_block_reward` replace the hard-coded block-reward branch chain with an epoch-offset loop, add a `u64::MAX` no-reward guard, and rely on the explicit final-reward epoch plus zero-reward future epochs for long-range reward calculation.
- at `calc_mwc_block_overage` add a `u64::MAX` overage guard and replace the long hard-coded overage branch chain with a bounded epoch loop that calculates the active epoch's block count and cumulative reward from epoch offsets.
- add difficulty-data regression helpers and tests for short and overlong windows, non-contiguous real header heights, non-increasing timestamps, next-height mismatches, and valid synthetic pre-genesis padding before real headers.
- update graph-weight tests to unwrap the new fallible `graph_weight` result while preserving the existing expected weights.
- update epoch-date tests for optional durations, verify the final-reward epoch and zero-reward epoch boundaries, assert unbounded future offsets return `u64::MAX`, and assert later epoch durations return `None`.
- update block-reward tests to unwrap optional duration for the last reward block, assert multiple heights after the final reward return zero.
- add overage tests for `u64::MAX - 1` and `u64::MAX`, both with and without the genesis reward, ensuring far-future overage remains fixed at the total supply.

**src/core.rs**
- add `GenericError` and `DataOverflow` common `Error` variants so generic core diagnostics and arithmetic overflow are reported distinctly from invalid amount strings.
- at `amount_from_hr_string` replace unchecked amount accumulation with checked multiplication/addition, preventing parsed amounts from wrapping `u64`.
- make whole-MWC parsing reject empty strings and non-ASCII-digit characters before numeric parsing.
- make nano-MWC parsing `parse_nmwcs` reject more than nine fractional digits instead of truncating them, require ASCII digits only, and keep right-padding valid shorter fractional values to the fixed nano width.
- at `amount_to_hr_string` replace floating-point amount formatting with integer quotient/remainder formatting, preserving exact output for large `u64` amounts.
- expand amount parsing tests to assert the nine-digit nano width, reject signed input, missing whole-MWC values, excessive fractional precision, require explicit leading zeroes for decimal-only amounts.
- expand human-readable formatting tests with values above the exact `f64` integer range and `u64::MAX`, verifying the new integer formatter does not lose precision.

**src/core/block.rs**
- remove `Clone`, `Eq`, and `PartialEq` derives from `Error`, convert transaction, keychain, committed, and serialization variants to `#[from]` source errors; add IO, data-overflow, POW, and consensus variants, map PMMR data-overflow errors into the new block data-overflow variant.
- validate the serialized `HeaderEntry` secondary flag as a strict boolean byte (`0` or `1`) instead of accepting any non-zero value as true.
- validate timestamp precision before PMMR conversion, replace lossy timestamp casting with checked `i64` to `u64` conversion.
- add the canonical pre-POW-without-nonce length constant, add timestamp subsecond precision validation, document the safe genesis timestamp unwrap, and enforce timestamp precision before pre-POW serialization.
- make pre-POW serialization context-aware, validate supplied pre-POW hex and decoded byte lengths, reject proof/header context mismatches, use context-aware nonce/proof serialization, reject trailing bytes after reconstruction, verify the reconstructed nonce/proof match the supplied values.
- make output/kernel MMR leaf counts fallible, propagate PMMR overflow errors, replace unchecked reward/overage casts negation with checked `i64` conversions and checked negation.
- harden untrusted header reads by using checked future-time calculation, using context-aware hashes in diagnostics, propagating fallible MMR-count and transaction-weight calculations.
- update the block `Committed` implementation to return fallible commitment iterators instead of eagerly allocated `Vec<Commitment>` values.
- make duplicate reward insertion fallible, check previous-height increment for overflow, propagate fallible difficulty addition.
- make `with_reward` return `Result` and reject non-empty block bodies before adding the coinbase output and kernel.
- make total-fee calculation fallible and include NRD-kernel/header-version checks in lightweight read validation.
- at `validate` and `verify_coinbase` propagate fallible header overage, total fees, and consensus reward calculations, use those checked values during kernel-sum and coinbase verification.
- add `UntrustedBlock::as_block` so callers can inspect the validated underlying block by reference without consuming it.
- move untrusted-block lightweight validation from the raw body to the fully constructed block, so body limits, lock heights, and NRD/header-version checks all run during untrusted deserialization.

**src/core/block_sums.rs**
- replace the public-field `BlockSums` struct and implicit zero-commitment `Default` state with an explicit `Empty`/`NonEmpty` enum plus `new` and `empty` constructors.
- keep the legacy two-commitment serialization format; writing `Empty` as the zero/zero pair, rejecting zero-commitment sentinels inside `NonEmpty`, and validating both non-empty commitments before serialization.
- read raw fixed-size Pedersen commitment bytes, decode the zero/zero pair as `Empty`, validate both commitments for non-empty sums, and reject mixed zero/non-zero pairs as corrupted input.
- update the tuple `Committed` implementation to return fallible commitment iterators, omit any previous sum for `Empty`, reject invalid non-empty zero sentinels, propagate wrapped commitment-collection errors.
- add serialization regression tests coverage for the legacy empty zero-pair and non-empty two-commitment formats, plus rejection tests for mixed empty sentinels, non-empty zero sentinels, and invalid commitments on write.

**src/core/committed.rs**
- add `CommitSumChunk` to represent either a compact partial sum or the original raw commitments, preserving correctness for zero-sum chunks.
- add `wait_for_commit_sum_task`, a FIFO scoped-thread join helper that bounds concurrent work, maps crossbeam panics to committed errors, appends completed partials, and reports processed-item progress.
- add `collect_commitment_partials`, which consumes fallible commitment iterators in bounded batches, calls a caller-supplied state check before each item, keeps worker count and batch size at least one, propagates iterator/thread/sum failures.
- replace the old eager `sum_commits` vector implementation with generic `sum_commitments_parallel`, supporting fallible input streams, tail commitments, saturating progress counters, bounded worker count, zero-partial carry-forward, empty-input rejection.
- add `verify_kernel_sums_iter`, centralizing output/input/kernel verification over iterators, preserving checked overage handling, allowing stop/progress callbacks, summing UTXO and kernel streams separately, applying the kernel offset.
- change the `Committed` trait to expose fallible commitment iterators instead of vectors, remove the old `sum_kernel_excesses`/`sum_commitments` default methods, and make `verify_kernel_sums` delegate to `verify_kernel_sums_iter` with the fixed batch size and all available CPU cores.
- harden kernel-offset summing `sum_kernel_offsets` by making blinding-factor conversion fallible.
- add regression tests for the new parallel iterator path, verifying it matches direct `secp.commit_sum` output and preserves correctness when a batched partial sum is zero and must be carried forward as raw commitments.

**src/core/compact_block.rs**
- at `CompactBlockBody::init` verify the body again after sorting so context-aware ordering failures cannot be silently emitted.
- replace `Ord`-based vector sorting with context-aware hash-key/hash sorting for full outputs, full kernels, and kernel short ids, allowing sort failures to propagate instead of assuming comparison cannot fail.
- expand lightweight read validation to enforce compact-block weight limits, map oversized and overflow failures to block errors, reject non-coinbase entries in the full output/kernel lists.
- replace the generic `READ_VEC_SIZE_LIMIT` admission check with compact-block-specific read-weight validation, pass the reader context into body initialization, and report non-coinbase full entries as corrupted compact-block input during deserialization.
- replace generic write-count limits with compact-block write-weight validation using the writer context before serializing the body lengths and collections.
- generate the compact-block nonce with fallible system RNG.
- add `UntrustedCompactBlock::as_compact_block` so callers can inspect the compact block content.
- add a regression test that builds an overweight compact-block body under the automated-testing chain type and verifies lightweight validation returns `Error::TooHeavy`.

**src/core/hash.rs**
- keep `Hash` debug output as the short 12-character.
- harden `Hash::from_hex` by rejecting overlong strings before decode and rejecting decoded values that are not exactly 32 bytes.
- add a `context_id` to `HashWriter`, replace the default constructor with `HashWriter::new(context_id)`, expose `get_context_id` through the writer so hash serialization can carry the consensus/network context.
- lmake `Hashed::hash` require an explicit context id, pass it into `HashWriter`.
- add regression tests for the short display/debug formatting contract and for rejecting invalid decoded hash lengths in `Hash::from_hex`.

**src/core/id.rs**
- make `ShortId::from_bytes` return `Result`, reject empty and overlong byte slices, preserve documented zero-padding only for non-empty shortened helpers, bound `from_hex` before decoding, route decoded hex through the fallible byte constructor, and construct `zero()` directly as the fixed all-zero id.
- update the short-id ordering test for fallible constructors and context-aware hashes.

**src/core/merkle_proof.rs**
- validate Merkle proof path length before serialization and before allocating the read vector, returning read/write-specific oversized-data errors.
- add `validate_path_len`, which enforces the global vector-size limit, requires empty MMRs to have empty paths, validates `mmr_size` through PMMR peak/leaf helpers, computes the maximum tree-plus-peak path with checked arithmetic, rejects overlong paths as corrupted data.
- make `to_hex` context-aware and fallible, serializing with the caller's context id and returning explicit Merkle proof errors.
- make `from_hex` return `MerkleProofError`, preserve contextual hex/deserialization failures, deserialize with the supplied context id, reject trailing bytes after the proof.
- validate proof path shape before hashing, reject empty MMR verification, reject out-of-range or non-leaf node positions, propagate PMMR calculation failures.
- replace the recursive, proof-consuming verification helper with a non-mutating sibling-path loop that propagates PMMR family/sibling errors, performs the final root comparison without cloning or removing path entries.
- add `hash_with_mmr_index` to centralize the legacy peak-parent index rule.

**src/core/pmmr/backend.rs**
- add a typed PMMR backend `Error` enum with serialization, invalid-state, internal, data-corruption, IO, data-overflow, and unsupported-operation variants, replacing string-only diagnostics with structured errors that callers can classify.
- update `trait Backend` methods return `Result`, so errors can be propagated.
- add `append_pruned_subtree_hashes` so PIBD rebuilds can append a pruned subtree together with parent hashes built from preceding peaks.
- add `leaf_pos_iter_from` to filter from a 0-based PMMR position while preserving iterator errors.

**src/core/pmmr/pmmr.rs**
- update `trait ReadablePMMR` methods return `Result`, so errors can be propagated; propagate errors at implemented methods.
- convert `push` to return PMMR `Error`, replace unchecked position/index/peak math with checked operations, derive siblings through the fallible `family` helper, propagate backend peak lookup errors, and update PMMR size only after append succeeds.
- harden `push_pruned_subtree` by validating that the subtree range is contiguous with the current PMMR size before appending, computing parent hashes first with checked/context-aware hashing, reading sibling hashes from the underlying file.
- make prune-list reset, snapshots, and rewinds return typed errors, make leaf-position rounding fallible, reject forward rewinds as invalid state instead of only logging a warning and returning success.
- make `prune` return typed errors, reject non-leaf and out-of-range positions explicitly, propagate hash lookup and remove errors, and return the backend's actual removal result instead of always reporting success.
- expand `validate` into a typed, context-aware integrity check that rejects incomplete MMR sizes and missing peaks, safely partitions work across CPU cores with checked arithmetic, maps crossbeam panics to internal errors, validates parent hashes while distinguishing compacted children from corruption.
- make `dump` and `dump_from_file` return `Result`, use checked chunk and display-index arithmetic, propagate hash lookup failures, and keep oversized debug dumps as successful no-ops.
- update the `ReadablePMMR` implementation: return fallible accessors, treat missing non-compacted internal hashes as data corruption, suppress data for non-leaf positions, filter leaf iterators to the current PMMR size while preserving iterator errors, and cap leaf-count queries to the actual leaf count.
- add safety comments to `peak_map_height` and `peak_sizes_height` documenting why the remaining shifts and guarded subtractions are valid.
- make `peaks`, `n_leaves`, `round_up_to_leaf_pos`, and `insertion_to_pmmr_index` fallible helpers, replacing unchecked accumulation, additions, multiplications, and subtractions with checked arithmetic and contextual `DataOverflow` errors.
- make `family`, `children`, and `is_left_sibling` return typed results, validate shift widths through checked conversions, and replace unchecked parent/sibling offset math with checked add/subtract paths.
- harden `family_branch` with an out-of-range position check and checked loop arithmetic for current position, sibling offsets, and peak doubling.
- make binary-tree range and iterator helpers fallible, compute leftmost/rightmost positions with checked arithmetic and `u128` intermediate width, return fallible leaf-position iterators, and validate subtree range end calculation.

**src/core/pmmr/readonly_pmmr.rs**
- make `elements_from_pmmr_index` return `Result`, pair each returned element with its 1-based PMMR position, cap optional scan limits to the readonly PMMR size, reject invalid 1-based start indexes and oversized counts, iterate through the backend's fallible leaf-position iterator, preserve iterator/data-read failures, use checked conversion back to 1-based positions.
- clarify that the `get_last_n_insertions` scans backward for unpruned leaves, make it return `Result`, replace unchecked position subtraction with checked arithmetic, propagate errors.
- update the `ReadablePMMR` to make hash lookup fallible, report a missing non-compacted internal hash.
- make data, raw hash, peak, and data-file lookups return `Result`, keep out-of-range positions as `Ok(None)`, propagate backend failures, and explicitly suppress data-file reads for non-leaf positions.
- replace infallible leaf/index/count iterator overrides with a fallible, filters positions to the readonly PMMR size, preserves per-item iterator errors.
- make `n_unpruned_leaves_to_index` fallible and cap the requested leaf index, preventing callers from counting past the readonly PMMR view.

**src/core/pmmr/rewindable_pmmr.rs**
- make `rewind` return `Result`, propagate failures, reject attempts to move the rewindable view forward as `InvalidState`, and update `last_pos` only after the target position has been validated.

**src/core/pmmr/segment.rs**
- remove clone/equality derives from `SegmentError`, add typed invalid-MMR-size, IO, data-overflow, and PMMR source-error variants, and map PMMR data-overflow errors.
- make `SegmentIdentifier` display tolerate fallible capacity/offset calculation, convert capacity, leaf offset, unpruned size, position range, switch full-segment helpers to `Result`, reject incomplete MMR subtree boundaries and nonexistent empty segments, replace unchecked shifts, multiplication, additions, and subtractions with contextual `DataOverflow` errors.
- add consumed-position tracking plus bitmap leaf-retention and segment payload-size helpers.
- update `Segment` capacity, offset, size, and range wrappers to propagate the new fallible identifier helpers.
- make `Segment::from_parts` return `Result` and validate hash/leaf vector length matches plus strictly sorted positions at runtime instead of relying on debug-only assertions.
- relax `Segment` PMMR generic bounds through `From<T::E>` conversions, make segment creation consume fallible segment-size/range helpers, and reject zero-sized or overflowing MMR ranges before reading PMMR data.
- harden bitmap-backed segment construction by using a context-aware in-memory `VecBackend`, enforcing payload-size limits during construction, requiring retained bitmap leaves to have data, converting stored leaf elements explicitly, propagating errors, use checking arithmetic.
- apply the same checked payload accounting and fallible data reads to non-prunable segments.
- make segment-root calculation context-aware and fallible, route bitmap segments through dedicated prunable-root helpers, use fallible PMMR child/peak helpers, require both children for non-prunable roots, propagate failures directly instead of wrapping them as calculation errors.
- add prunable subtree/root reconstruction helpers that derive bitmap leaf ranges with checked PMMR arithmetic, skip fully pruned subtrees by bitmap cardinality, require proof hashes only where a sibling subtree is pruned.
- make first-unpruned-parent lookup context-aware and consumption-tracked, propagate fallible root, family-branch, leaf-count, and binary-tree range helpers, and replace unchecked parent/range arithmetic plus lossy `u32` casts with checked conversions.
- change validation to consume and return a sanitized `Segment`, validate that all supplied leaves participated in the authenticated root, pass the context id into proof validation, and drop unconsumed hash entries so peers cannot cause unproved hash data to be applied locally.
- add `checked_read_count` and use it while deserializing segment hash and leaf counts, enforcing the global vector read limit before allocation and converting 1-based serialized positions to 0-based positions with checked subtraction.
- make segment serialization check 0-based hash and leaf positions before converting them back to 1-based wire positions.
- harden `SegmentProof::generate` with checked last-position conversion, fallible family-branch and peak calculations, file-backed hash/peak reads that preserve PMMR errors, and checked filtering of left-side peaks.
- make proof root reconstruction and validation context-aware, reject incomplete MMR sizes before reconstructing, propagate fallible PMMR helpers, reject trailing proof hash data after the expected path has been consumed.
- cap serialized proof hash counts at the protocol maximum and the global read-vector limit before allocation, preventing oversized proof payloads from allocating unbounded memory.

**src/core/pmmr/vec_backend.rs**
- add `compacted`, `removed`, and `context_id` state to `VecBackend`.
- introduce `VecBackendTail` for preserving detached hash/data suffixes plus compaction/removal markers during fallible rebuilds.
- `VecBackend` expose the backend context id and change append to return typed errors while clearing stale compacted/removed markers for each newly appended hash position.
- harden pruned-subtree append `append_pruned_subtree` with checked position, length, and leaf conversions; fallible PMMR range/leaf helpers; data-capacity validation; safe hash-vector resizing; and compaction markers for subtree nodes whose hashes are intentionally absent.
- add `append_pruned_subtree_hashes` using clone-then-commit semantics so appending a pruned subtree plus derived hashes is atomic on error, and update single-hash append to clear stale compaction/removal markers.
- make hash lookups fallible, hide removed leaves and locally compacted or missing leaf hashes, propagate position overflows, add `is_compacted` so callers can distinguish expected compaction misses from data corruption.
- make data lookups fallible, suppress non-leaf data reads, replace unchecked leaf-index arithmetic with checked PMMR conversions.
- replace unimplemented `VecBackend` unpruned-leaf count methods with explicit `InternalError` results, avoiding runtime panics in audit/error paths.
- convert leaf position and leaf index iteration to fallible result iterators, filter removed/compacted/missing leaves consistently for data-backed and hash-only modes, propagate checked PMMR index math failures.
- make removal return `Result`, reject non-leaf removals, report no-op removals for already missing leaves, track logical removals separately from stored data, route rewind through tail detachment, clear removal markers for rewind bitmap positions, return explicit errors for unsupported prune-list reset and snapshot operations.
- add rewind index calculation plus `detach_tail`/`restore_tail` helpers that reject forward rewinds, preserve data/hash suffixes, validate data-mode consistency, restore compaction/removal sets so callers can roll back failed in-place rebuilds safely.
- make compaction return typed errors, use checked PMMR helper calls and checked child index conversions, ignore logically removed leaves, mark intentionally deleted hashes as compacted, preserve the top hash when all other hashes are removed, track buildable-hash deletion as expected compaction.

**src/core/transaction.rs**
- harden `FeeFields` read/write and serde paths by validating before serialization/deserialization, centralizing `validate_fee`, serializing as `u64`, and replacing unchecked `From<u32>` construction with fallible `TryFrom<u32>`.
- replace derived NRD relative-height serde with explicit validation, validate NRD height before writing and serde serialization, centralize `validate_nrd_height`, and make the maximum height a documented `u16` constant.
- bind `KernelFeatures` serde to the shared serde crate and make kernel signature-message hashing context-aware, propagating hash errors directly.
- update `Error` with duplicate input/output/kernel errors, add disabled-NRD, IO, and data-overflow errors, add a helper to map serialization duplicate errors to transaction-specific duplicate errors.
- switch kernels to `AggSigSignature`, remove hidden infallible ordering/hash implementations, make message signing and batch/single signature verification context-aware, propagate aggsig errors, make empty-kernel construction fallible with validated commitment sizing.
- remove derived `TransactionBody` equality and validate body counts/weight before binary read/write.
- update the `Committed` implementation to return fallible commitment iterators instead of eagerly allocated commitment vectors.
- make transaction-body sorting, initialization, and equality context-aware through hash-order helpers; compare outputs by output identifier so rangeproof bytes do not affect transaction identity.
- make body input/output/kernel mutators fallible, reject implicit feature-dropping conversions between full inputs and commit-only inputs, preserve hash order, return duplicate-specific errors.
- make body fee, overage, and weight calculations fallible with checked addition and checked `u64` to `i64` conversion, and propagate those errors through weight-limit validation.
- add local NRD feature-flag validation, 
- convert sorted/unique and cut-through checks to context-aware hash checks.
- add reusable transaction and compact-block count/weight validators for read and write paths, enforcing vector-size limits before allocation and mapping overflow into serialization errors.
- bind `Transaction` serde to the shared serde crate, remove infallible equality, update committed accessors to fallible iterators, add explicit context-aware transaction comparison through `eq_by_hash`.
- make transaction construction and add-input/output/kernel helpers context-aware and fallible, including an explicit `with_commit_input` path for commit-only inputs.
- make fee, overage, validation, fee-rate, accept-fee, and base-fee APIs fallible, adding checked arithmetic and NRD-enabled validation before full transaction validation.
- make aggregation context-aware, use checked length accumulation before vector allocation, convert inputs through explicit commit-wrapper helpers, run context-aware cut-through, build the aggregate transaction through fallible APIs.
- make deaggregation context-aware, compare inputs/outputs/kernels with consensus hash helpers, propagate blinding-factor secret-key conversion errors, treat zero blind sums as zero offsets, hash-sort the resulting transaction parts.
- validate Pedersen commitments before binary writing.
- bind `CommitWrapper` serde to the shared crate, remove hidden ordering traits and implicit full-input conversions, validate commitments on write, require explicit lossy conversion from full input to commit-only wrapper.
- remove derived `PartialEq` from `Inputs`, route v3 write conversion through context-aware commit-wrapper conversion, add hash equality/from-output-identifier/conversion helpers, make sorted/unique checks fallible and context-aware.
- bind output feature/output serde to the shared crate, serialize rangeproofs through the dedicated rangeproof hex helper, remove output ordering, make output equality/hash use only the identifier, expose canonical proof bytes as fallible, require mutable secp for proof verification.
- at `OutputIdentifier` remove hidden ordering traits, validate commitments on write.
- update tests for fallible secp/keychain APIs, valid aggsig signatures, context-id serialization/deserialization and short-id hashing, fallible fee construction, and `matches!` assertions for NRD and unknown-feature error paths.

**src/difficulty_cache.rs**
- introduce opaque `DifficultyCache` storage backed by a private `VecDeque<HeaderDifficultyInfo>`.
- add `reset_rolling`, converting newest-to-oldest difficulty iterator data into oldest-to-newest cache state.
- add `next_rolling_difficulty`, rebuilding the expected newest-to-oldest window from cached entries and delegating to the validated consensus difficulty calculation.
- add `push_rolling_header`, rejecting empty caches, enforcing contiguous header heights, trimming the rolling cache to the configured adjustment window.
- add `span` validation that confirms cache endpoints match the entry count before index-based reuse.
- add debug-only periodic cache equivalence checking and the fallible `difficulty_data_to_vector` setup.
- implement cache-hit reuse for the hot difficulty-data path, clearing oversized, non-contiguous, mismatched, branch-like, or hashless cache entries.
- add `difficulty_data_from_last_n`, preserving early-chain synthetic padding while making empty history, timestamp underflow, zero timestamp spacing, and synthetic timestamp subtraction explicit errors.
- add test helpers for hashed and hashless `HeaderDifficultyInfo` values with deterministic timestamps and difficulty.
- add regressions proving cache hits require block hashes and that new hashless headers are not appended to a cached window, preventing synthetic or ambiguous data from poisoning later difficulty calculations.
- add a rolling-cache regression that compares cached next-difficulty results with normal cursor-based calculation before and after pushing a validated header.
- add a regression that rejects non-contiguous rolling header pushes with `InvalidParameter`.

**src/genesis.rs**
- update error handling to match changes in API; no structural/functional changes was made.

**src/global.rs**
- bump the local protocol version from `4` to `5` and document the new onion identity proof field in `Hand` messages.
- change peer timeout, ping interval, and expiration constants from signed `i64` to unsigned `u64`, aligning them with duration-style arithmetic and avoiding signed conversion hazards.
- make `release_context_data` remove the context's global parameter entry.
- make `get_genesis_block` require a caller-provided secp context and return `Result`; mainnet/floonet use the validated secp-aware genesis constructors, while testing chains mine genesis blocks through the PoW path.
- make chain type and NRD global initialization fallible, replace duplicate-initialization panics with logged `AlreadyInitialized` errors.
- make global and local accept-fee-base initialization fallible, reject a zero fee base as `InvalidParameter`, and report duplicate global initialization with `AlreadyInitialized` instead of panicking.
- update `initial_graph_weight` for the fallible `graph_weight` API, documenting that the unwrap is safe for fixed consensus constants.
- replace saturating subtraction/casting in `max_tx_weight` with direct subtraction under that invariant, avoiding silent masking of invalid block-weight constants.
-  replace the inline `VecDeque` difficulty-window/cache implementation with an inline wrapper over `difficulty_cache::difficulty_data_to_vector`, use the opaque `DifficultyCache`, accept fallible header conversion through `IntoHeaderDifficultyInfo`, return consensus errors for invalid difficulty data.
- update header-length tests for context-aware `BinWriter`, caller-owned secp contexts, fallible `get_genesis_block`, and secp-aware fixed genesis builders, removing direct `mine_genesis_block` usage from the tests.

**src/libtx/aggsig.rs**
- require `calculate_partial_sig` callers to provide a public-key sum, return `AggSigSignature`, and pass the public-key sum directly into the aggsig challenge instead of allowing it to be omitted.
- add the signer public nonce to `verify_partial_sig`, verify the signature `R.x` bytes match that nonce before running the standard partial-signature check.
- make `sign_from_key_id` return `AggSigSignature`, require the transaction blinding public key instead of an optional value.
- update single-commitment and completed-signature verification to use `AggSigSignature`, require public-key sums, propagate `verify_single` errors, and verify completed signatures as non-partial signatures.
- make `sign_with_blinding` require a public-key sum, return `AggSigSignature`, and reject zero blinding factors before attempting to build a secret key.
- wrap `BatchSignature` around `AggSigSignature`, introduce `dual_key_coefficient`, hash canonical compressed public-key serializations instead of raw key storage when deriving dual-key coefficients, reuse that helper for dual-key signing and composite public-key construction, and verify dual-key signatures with a required public-key sum.
- update tests to the shared RNG/fallible context APIs and add regressions for canonical composite public-key derivation, public-key-sum binding in `sign_single`, zero-blinding rejection, successful partial-signature nonce matching.

**src/libtx/build.rs**
- extend transaction-builder context with a caller-owned mutable `Secp256k1` plus consensus context id so combinators can use context-aware hashing/serialization and fallible crypto APIs.
- reduce input debug logging so regular inputs no longer print values/key identifiers, limiting sensitive transaction-building details in logs.
- build output commitments and range proofs with the supplied secp context, stop logging output values/commitments, insert outputs through context-aware fallible `with_output`.
- make `partial_transaction` accept a consensus context id and mutable secp context, carry them through `Context`, derive the blind sum through the caller-provided secp instance instead of a hidden keychain context.
- make `transaction` accept a consensus context id and mutable secp context, propagate fallible kernel/excess creation.
- make `transaction_with_kernel` accept the same context id and mutable secp context.
- update tests to match functions signature changes.

**src/libtx/error.rs**
- add `DataOverflow` and `ConsensusError` variants.

**src/libtx/mod.rs**
- make `tx_fee` return `Result`, compute transaction weight and accept-fee base separately, replace unchecked fee multiplication with `checked_`.
- make `inputs_for_minimal_fee` return `Result` and propagate the errors.
- make `inputs_for_fee_points` return `Result`, convert fee to fee points with checked math, propagate the fallible result.

**src/libtx/proof.rs**
- make proof `create` validate that the supplied commitment matches the keychain-derived commitment before proving, propagate fallible errors.
- verify a proof before attempting rewind, pass the new optional private nonce parameter to `rewind_bullet_proof`, continue returning `None` only for valid-but-unowned proofs, propagate other secp failures as real errors.
- store `ProofBuilder` hashes in `Zeroizing<Vec<u8>>`, build them with `zeroizing_blake2b`, create nonce secret keys from zeroized hash buffers instead of a hidden keychain secp context.
- use fallible `ProofMessage::from_bytes`, explicitly reject path depths above four instead of clamping them, propagate invalid serialized paths, verify commitments.
- update the legacy proof builder constructor and nonce derivation to use zeroizing Blake2b output, keeping legacy root-hash cleanup while avoiding hidden crypto context access.
- reject legacy proof messages for non-depth-3 identifiers before serialization, make proof-message construction fallible, check the legacy zero header before decoding the path during ownership checks, compute expected commitments through the supplied secp context.
- harden view-key proof support by deriving rewind nonces with zeroizing Blake2b, returning explicit errors for unsupported private-nonce/message creation instead of panicking, rejecting invalid depths and malformed paths as non-owned outputs, validating the full view-key path prefix.
- update proof tests to shared RNG/secp APIs and seed-based keychain creation, restore regular-switch view-key coverage, add regressions for mismatched commitments, invalid rangeproof rewind errors, valid unowned proofs, invalid path depths, malformed path data, full view-key prefix validation, and legacy depth/header handling.

**src/libtx/reward.rs**
- reject `test_mode` in non-test builds.

**src/libtx/secp_ser.rs**
- update public-key serde to use shared secp/serde imports and `secp_static::with_none`, propagating context creation and public-key serialization/deserialization errors instead of locking the old global secp instance directly.
- change optional signature serde from generic `Signature` to validated `AggSigSignature`, serialize with fallible raw-signature bytes, require exactly 64 decoded bytes, and decode through `AggSigSignature::from_raw_data` with explicit secp context errors.
- harden optional secret-key serde by using `SECRET_KEY_SIZE`, zeroizing serialized and parsed key material, strict `decode_secret_key_hex` length checking, redacted parse errors, and fallible secret-key construction through `secp_static`.
- apply the same aggregate-signature raw-byte serialization and exact 64-byte decode checks to non-optional signatures, returning serde errors for invalid signatures or unavailable secp context.
- validate optional commitment deserialization by checking `Commitment::from_vec` and `secp.validate_commitment` before accepting parsed bytes, rejecting malformed or invalid Pedersen commitments.
- switch blinding-factor parsing to the shared serde error type and stop echoing the supplied hex value in parse errors, reducing exposure of sensitive material in diagnostics.
- trim rangeproof hex input, accept one optional `0x` prefix, reject payloads larger than `MAX_PROOF_SIZE` before decoding, and add `rangeproof_as_hex` to serialize rangeproofs through their validated byte accessor.
- harden `commitment_from_hex` by validating commitment construction and secp commitment validity instead of returning unchecked commitment bytes.
- update tests to shared RNG, serde, serde_json, and secp imports; bind derives to the shared serde crate; use `AggSigSignature`; and build test public keys, signatures, and commitments through real secp APIs.
- add regression tests for raw aggregate-signature serialization, oversized rangeproof rejection before decode, overlong signature and secret-key rejection, invalid signature serialization failures, invalid commitment rejection, and redacted optional secret-key parse errors.

**src/libtx/zeroizing_blake2b.rs**
- introduce `ZeroizingBlake2b` state with chaining words, byte counter, block buffer, buffered length, and output length, and validate output/key lengths while initializing the BLAKE2b parameter block.
- add keyed and streaming update handling that buffers partial blocks, compresses complete blocks, tracks byte counts, and zeroizes the internal block buffer after a consumed buffered block.
- finalize into `Zeroizing<Vec<u8>>`, pad the last block, copy only the requested output bytes, zeroize temporary word bytes, use checked counter addition to catch length overflow, and wipe all hash state before returning.
- add a `Drop` wipe for defensive cleanup and expose a module-private `zeroizing_blake2b` helper that scopes state creation, key setup, data update, and finalization for libtx callers.
- implement the compression function with local message/work vectors, counter and final-block flag handling, state mixing, and explicit zeroization of compression scratch arrays.
- add the BLAKE2b round and quarter-round operations with wrapping arithmetic and rotations matching the standard permutation schedule.
- add regression tests comparing generated outputs against `blake2_rfc` and RustCrypto BLAKE2b implementations across multiple output lengths, key lengths, and message sizes.

**src/macros.rs**
- remove the exported `filter_map_vec!` convenience macro, reducing unused broad helper macros in the core API.
- remove the exported `tee!` side-effect helper macro, making call sites use explicit statements instead of hiding expression execution behind a macro that returns the original identifier.
- remove the internal `hashable_ord!` macro, this avoids silently masking hash errors and keeps hash-based comparisons on explicit fallible paths.

**src/pow.rs**
- at `pow_size` handle safely found proofs data, preventing empty-proof panics and hidden failures.

**src/pow/common.rs**
- use checked math.
- validate Cuckoo parameter construction by rejecting edge bits or node bits outside the supported `2..=33` range.
- add regression tests covering short-header nonce replacement, zero proof-size rejection, and SipHash nonce arithmetic overflow handling.

**src/pow/cuckaroo.rs**
- replace the `unimplemented!()` panic in `CuckarooContext::find_cycles` with `Error::NotImplemented`.

**src/pow/cuckarood.rs**
- reject `edge_bits` values below `2` before constructing `CuckooParams`.
- replace the `unimplemented!()` panic in `CuckaroodContext::find_cycles` with `Error::NotImplemented`.
- add a proof-size bound to the cycle-following loop.

**src/pow/cuckaroom.rs**
- replace the `unimplemented!()` panic in `CuckaroomContext::find_cycles` with `Error::NotImplemented`.

**src/pow/cuckarooz.rs**
- compute `node_bits` with `checked_add`.
- replace the `unimplemented!()` panic in `CuckaroozContext::find_cycles` with `Error::NotImplemented`.

**src/pow/cuckatoo.rs**
- store visited nodes as 64-bit bitmap values, track completed solutions separately from the scratch `solutions` vector, and preserve the requested `edge_bits` in generated proofs instead of defaulting to the network minimum.
- add `zero_proof`, checked graph node sizing, and graph-initialization validation.
- rewrite graph byte-count calculation with checked multiply/add operations and contextual `DataOverflow` errors.
- validate graph initialization before edge insertion.
- make visited-node lookups 64-bit safe, change traversal depth from `u32` to `usize`, use explicit `solution_count` slots, stop traversal when the solution limit is reached, avoid proof-size truncation when comparing large sizes.
- bounds-check SipHash key lookup in `sipkey_hex` and return `InvalidConfiguration` for out-of-range indexes.
- reset the graph at the start of `find_cycles_iter`, truncate candidates by completed solution count, map solution nonce indexes through checked conversion and bounds-checked lookup, verify candidates through a filtered path, and return `NoSolution` when all candidates are invalid.
- add `filter_verified_solutions` so invalid verification candidates are treated as mining misses while non-verification errors still propagate to the caller.
- add graph-level regression tests for node-count and byte-count overflow.
- add solver-level regression tests for filtering invalid candidates.

**src/pow/error.rs**
- to `Error` add `NotImplemented`, `DataOverflow`, `SysRndError`, `ConsensusError`, and `InvalidConfiguration` variants.

**src/pow/lean.rs**
- change the stored edge bitmap to `Bitmap64` and add `full_edges` to initialize the complete `0..num_edges` range without truncating through `u32`.
- reset the full edge bitmap after changing the header/nonce so a reused miner does not carry over trimming state from the previous mining attempt.
- compute the trim threshold once, track each trimming round's starting cardinality.
- add regressions for full 64-bit edge ranges, header/nonce reset restoring trimmed edges, fixed-point trim failure reporting, and fresh Cuckatoo context initialization.

**src/pow/siphash.rs**
- document that sip algorithim does what is intended, making data overflow behavior audit-visible without changing the hashing path.

**src/pow/types.rs**
- make `Difficulty` arithmetic operators return `Result<`, use checked add/subtract/multiply/divide with contextual `DataOverflow` errors, and reject zero division results instead of silently wrapping, underflowing, overflowing, or producing an unusable difficulty.
- reject serialized zero `Difficulty` during binary reads, serde string and unsigned integer deserialization.
- make `Proof::random` fallible, use system RNG.
- add `validate_packable` and make nonce packing fallible; validate edge-bit range, packed byte length, exact proof nonce count, and nonce upper bounds before writing packed proof bytes.
- remove the `SkipPow` deserialization shortcut, always read the packed proof bytes, retain padding-bit malleability checks, and validate the reconstructed proof before returning it.
- propagate fallible nonce packing from `Proof::write` instead of writing unchecked packed bytes.
- update proof tests to the new reader/writer and shared RNG APIs, add regression coverage for zero difficulty rejection.

**src/ser.rs**
- remove `DeserializationMode`/`SkipPow` from the reader API.
- make `IteratingReader` yield `Result<T, Error>` and have `read_multi` collect fallibly.
- split deserialization into strict and permissive entry points, make the default path reject trailing bytes.
- make `BinReader` track a checked `u64` byte counter, add counted exact-read and strict end-of-input helpers, map IO errors directly.
- rework `BinReader` primitive and byte reads to use counted exact reads with bounded length-prefix handling, preventing silent byte-counter drift and oversized allocation attempts.
- remove streaming-reader deserialization mode state, expose `bytes_read`, validate length prefixes and fixed-read sizes before allocation.
- validate deserialized Pedersen commitments before accepting the bytes as a `Commitment`.
- add regression coverage for invalid and valid commitments, invalid aggregate-signature writes, strict trailing-byte rejection, oversized length prefixes and fixed reads, PMMR rangeproof padding and length handling, context-aware PMMR rangeproof hashing, vector EOF handling, zero-byte element rejection, and vector-size limits.
- read blinding-factor bytes into `Zeroizing` storage and report parse failures as `CorruptedData`, reducing sensitive material lifetime and replacing unchecked construction.
- bound rangeproof write/read lengths against `MAX_PROOF_SIZE` before serialization, allocation, or casts, and preserve the logical proof length instead of treating every decoded proof as full-size.
- introduce `RangeProofPmmr` as the fixed-size PMMR storage representation, zero-pad serialized proof buffers, reject non-zero padding on read, validate PMMR element lengths.
- replace the legacy aggregate `Signature` serialization with validated `AggSigSignature` reads and writes, rejecting malformed raw signatures instead of copying unchecked bytes.
- add context-aware hash collection helpers for sorting, inserting without duplicates, sorted/unique verification, hash equality, slice comparison, and containment, so callers can use fallible consensus-hash ordering explicitly.
- harden `Vec<T>` deserialization by detecting zero-byte element reads, rejecting partial final elements, using buffered-reader pending-data checks to distinguish clean EOF from truncation, and enforcing `READ_VEC_SIZE_LIMIT`.
- remove the custom serde serializer/deserializer for `io::ErrorKind`.

**src/stratum/connections.rs**
- add `StratumIpPoolError` with `UnknownIp`, `NoWorkers`, and `ActiveWorkers` variants so IP-pool accounting, worker deletion, and cleanup failures are reported as structured errors.
- switch connection, share, login, and ban event queues from millisecond timestamps to `Instant`, change worker counts from signed `i32` to `u32`, and add an `events_limit` field to bound per-IP scoring queues.
- require an event limit when constructing a connection, clamp it to at least `30`.
- include recent connection history in empty-entry detection and event retirement, retire all event queues by maximum age, saturate worker increments, make worker deletion fail when no workers are active, bound share/login/failure queues through `push_limited_event`.
- change pool ban thresholds and share weights to `usize`, return `u32` worker counts from profitability reporting, use `parking_lot` recursive reads and writes, make event retirement accept a `Duration` max age before removing fully empty IP entries.
- use recursive reads for ban checks, create new per-IP connection entries with a scoring-event limit derived from `ban_action_limit.saturating_mul(10)`, keep missing IPs non-banned until they have explicit accounting.
- make worker deletion and all share/login/failure reporting APIs return `Result`, propagate errors.
- make `clean_ip` fallible, reject cleanup for unknown or still-active IPs, only remove idle entries from the pool.
- add regression tests for retaining recent connection history, cleanup after connection history expires, missing or empty worker accounting errors, missing share/login/noise accounting errors, active-worker cleanup protection, and bounded scoring queues.

**tests/block.rs**
- update tests with functions signature changes (no structure/functionality changes).
- line 40 and former line 38: unwrap test logger initialization so setup failures are reported immediately instead of being ignored.
- add a regression ensuring `Block::with_reward` rejects attempts to add a reward to a non-empty block.
- add timestamp-canonicalization coverage that rejects subsecond block-header timestamps through precision validation, pre-POW writing, and PMMR element conversion.
- add compact-block serialization helpers that manually write headers, nonces, bodies.
- add compact-block body read regressions that reject non-coinbase full outputs and non-coinbase full kernels during body deserialization.
- add untrusted compact-block regressions that reject overweight body counts before payload allocation and reject non-coinbase full outputs or kernels when reading untrusted compact blocks.
- update header proof reconstruction for context-aware writing and add regressions rejecting extra pre-POW bytes, full-header pre-POW input that already includes nonce/proof data, and proof/context-id mismatches.

**tests/common.rs**
- update tests with functions signature changes (no structure/functionality changes).

**tests/consensus_automated.rs**
- update tests with functions signature changes (no structure/functionality changes).
- add `difficulty_data_to_vector_populates_opaque_cache`, which builds a reversed cursor of deterministic headers, verifies the returned difficulty window is ordered oldest-to-newest, checks the opaque cache is populated with the same entries.
- add `difficulty_data_to_vector_reuses_opaque_cache_for_next_window`, priming the cache with one full window and then verifying the next contiguous window can be produced from cached data plus the supplied cursor.
- add a deterministic `difficulty_header` helper that assigns unique hashes, monotonically increasing timestamps, and height-derived difficulties for the new cache/window tests.

**tests/consensus_mainnet.rs**
- update tests with functions signature changes (no structure/functionality changes).

**tests/core.rs**
- update tests with functions signature changes (no structure/functionality changes).
- add `transaction_deaggregation_equal_nonzero_offsets_returns_zero_offset`, covering deaggregation of a transaction against itself with a nonzero offset and requiring the result to have zero offset plus empty inputs, outputs, and kernels.

**tests/merkle_proof.rs**
- update tests with functions signature changes (no structure/functionality changes).
- add `merkle_proof_from_hex_rejects_trailing_bytes`, covering valid context-aware hex round trips and ensuring `MerkleProof::from_hex` rejects appended trailing serialized data.
- add serialization and deserialization regressions for invalid proof path lengths, expecting `CorruptedData` for structurally impossible serialized proofs and `TooLargeReadErr` for path counts above `READ_VEC_SIZE_LIMIT`.
- add verification rejection coverage for invalid nonzero MMR sizes, overlong paths, empty MMR proofs, out-of-range node positions, and internal-node positions, asserting each hardened validation path reports the expected diagnostic.

**tests/pmmr.rs**
- update tests with functions signature changes (no structure/functionality changes).
- add regressions that reject forward rewinds for both writable `PMMR` and `RewindablePMMR`, asserting the error text and verifying the PMMR size/root or rewindable view are not advanced by an invalid request.
- add missing-data regressions for PMMR reads: non-compacted internal hash misses now return `DataCorruption` through both writable and readonly views, while readonly internal-node data-file reads return `None`.
- add readonly PMMR corruption regressions for missing RHS peak hashes, missing peak hashes, missing left peak hashes, and missing Merkle-branch sibling hashes, asserting each path returns `DataCorruption` with contextual diagnostics.
- add `get_data_from_file` and `push_pruned_subtree` regressions covering internal-node data suppression, leaf-size advancement, parent combination with left siblings, non-contiguous subtree rejection without backend mutation, and parent-construction failure rollback.
- add an out-of-range prune regression that verifies invalid leaf pruning returns `InvalidState` and leaves size, root, and stored hash unchanged.
- update `elements_from_pmmr_index` coverage for the fallible readonly API, assert returned `(pmmr_pos, data)` pairs, add oversized upper-bound clamping and empty-result cases, and use fallible insertion-index helpers before pruning.

**tests/segments.rs**
- add tests to cover new segment hardening rules.
- update tests with functions signature changes (no structure/functionality changes).

**tests/transaction.rs**
- update tests with functions signature changes (no structure/functionality changes).
- extend transaction JSON round-trip coverage to reject a zero-fee kernel during deserialization, and compare round-tripped transactions with `eq_by_hash(0, ...)` instead of direct struct equality.
- add JSON deserialization regressions for invalid `KernelFeatures::Plain` fee fields, covering both zero fees and fees above the encoded mask.
- add JSON deserialization and serialization coverage for NRD relative heights, rejecting zero and over-week values while preserving a valid height through a round trip.
- add a disabled-NRD validation regression that builds an NRD transaction with caller-owned secp context and checks both lightweight read validation and full validation return `NRDKernelNotEnabled`.
- add regressions for fallible invalid-kernel hashing, duplicate output and input identifiers, lossy feature-preserving input conversion rejection, and explicit commitment-only conversion from an input.
- add invalid Pedersen commitment regressions for `CommitWrapper`, `Input`, `OutputIdentifier`, and derived `Output` serialization or hashing, ensuring malformed commitments return write/hash errors instead of being accepted.
- add duplicate-kernel insertion coverage and a zero `fee_points` rejection for `Transaction::inputs_for_fee_points`.
- add range-proof length regressions that return the canonical proof slice, reject oversized public proof lengths, fail JSON serialization without panicking, and return `TooLargeWriteErr` for oversized binary writes.
- expand fee-field coverage to reject zero fees, round-trip valid fee JSON, reject zero-fee serialization.

**tests/vec_backend.rs**
- update tests with functions signature changes (no structure/functionality changes).
- add `leaf_pos_iter_respects_pmmr_view_size`, verifying mutable and readonly PMMR views filter leaf positions and indexes to the requested PMMR size instead of exposing later backend data.
- add pruning coverage showing `leaf_pos_iter` skips a removed data-backed leaf while keeping remaining live leaf positions visible.
- add `get_hash` coverage for pruned data-backed leaves, confirming removed hashes are hidden from normal access, repeated pruning reports no-op, and file-backed hash lookup still sees the stored hash.
- add data-backed `Backend::remove` coverage for actual removal status, repeat removal and out-of-range no-ops, and explicit non-leaf rejection through a serialization error.
- add matching hash-only `Backend::remove` coverage so actual removals return true and repeated or missing removals return false.
- add regressions proving removal returns false when the leaf slot is already missing in either data-backed or hash-only storage.
- add `get_data`/`get_data_from_file` coverage that returns `None` for internal PMMR nodes while preserving leaf data reads.
- add an atomicity regression for `append_pruned_subtree`, checking that data-capacity errors leave hashes, data, and compaction markers unchanged.
- add rewind coverage for data-backed pruned leaves, verifying rewind restores hidden hash/data state and leaf-position iteration.
- add the same removed-leaf rewind restoration coverage for hash-only vector backends.
- add rewind truncation coverage confirming hash/data vectors and leaf-position iteration shrink to the requested PMMR state.
- add forward-rewind rejection regressions for both hash and data paths, asserting invalid rewinds return `InvalidState` and leave backend state unchanged.
- add hash-only leaf-position iterator regressions for missing hashes and compacted pruned-subtree hashes, ensuring only live leaf hashes are reported.

### mwc-node/store

**Summary of the changes:**
- error propagations.
- switch to safe math and types conversions.
- validate data on serialization, deserialisation, conversions.
- stop skipping and log corrupted data, convert ot errors instead.
- add PMMR rollback capability, so errors can be handled without loosing data consistency.

**Cargo.toml**
- remove imported crates, add `mwc_crates` instead.
- add thiserror (it can't be reexported)

**src/leaf_set.rs**
- split opening into `open`, `open_or_create`, and `open_impl`, only create an empty in-memory bitmap when explicitly requested, propagate missing-file errors otherwise, and validate persisted bitmap entries before accepting them.
- make snapshot copy read the candidate bitmap directly, surface missing snapshot files as `NotFound` instead of silently succeeding, validate snapshot bitmap contents before installing them.
- make pre-cutoff leaf calculations fallible, replace unchecked `u64` to `u32` casts with overflow-checked conversion, propagate prune-list errors, and return `DataOverflow`/PMMR errors instead of truncating or assuming prune checks cannot fail.
- make rewind fallible, check cutoff conversion before range removal, and filter rewind restore positions so zero entries, positions past the cutoff, and non-leaf PMMR positions cannot be reintroduced into the leaf set.
- make `add` and `remove` return `Result`, reject non-leaf PMMR positions, check one-based bitmap-position conversion for overflow, and make `remove` report whether a live leaf was actually removed.
- require the serialization context id when snapshotting, compute a context-aware header hash, use the full hex hash as the snapshot suffix, and write the optimized bitmap through `save_via_temp_file` instead of direct `File::create`/`BufWriter` output.
- make membership and count helpers fallible, return bitmap cardinality as `u64`, replace unchecked range-cardinality casts with checked conversion, validate stored bitmap entries while counting unpruned leaves.
- add persisted-bitmap validation helpers that reject zero entries and non-leaf PMMR positions with explicit invalid-data or data-corruption errors.
- add regression tests for rewind restore filtering, non-leaf add/remove rejection, remove return values, invalid persisted and snapshot bitmap entries, and full context-aware snapshot hash suffixes.

**src/lib.rs**
- harden `save_via_temp_file` by returning `InvalidInput` for empty suffixes, creating a unique same-directory temporary file instead of replacing a deterministic suffix path, cleaning up failed writes/syncs/renames with logged best-effort removal, closing the file before rename, and syncing the parent directory after replacement.
- add temporary-file support helpers for logged cleanup, collision-resistant random suffixes, normalized parent handling, parent-directory fsync, and Unix-specific replacement mode preservation with symlink replacement rejection and `0600` defaults for new files.
- add shared regular-file open helpers that reject symlinks and non-regular files before opening, use `O_NOFOLLOW` on Unix, revalidate the opened handle's file type, and document the remaining non-Unix race limitations.
- switch roaring bitmap imports to the shared facade, read bitmaps through the regular-file helper, use fallible bitmap deserialization, and reject invalid or trailing serialized bitmap data with `InvalidData`.
- add regression tests for invalid bitmap data, valid bitmap round trips, trailing-data rejection, symlink rejection on Unix, atomic temp-file replacement, preservation of preexisting deterministic temp paths, and Unix permission preservation/symlink replacement rejection.

**src/lmdb.rs**
- drop `Clone`/`Eq`/`PartialEq` from the error enum, add `DbUnavailable` and `DataOverflow`, and add helpers for not-found classification and explicit unavailable-database errors.
- replace direct `create_dir_all` setup with platform-specific LMDB directory preparation; Unix creation uses `0700`, opens with `O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC`, rejects non-directories and group/other-writable existing directories, tightens accepted permissions to owner-only.
- add checked LMDB used-size and resize-threshold helpers, including overflow diagnostics for page-size, last-page, mapsize, and threshold arithmetic.
- harden store creation by documenting the local-only `env_name` invariant, creating/opening the LMDB directory through the secure helper, using the shared LMDB facade, initializing the resize lock.
- make `open` resize-aware and idempotent, using a recursive resize read guard and returning success when the database handle is already available.
- make resize checks run under the resize read guard, calculate used bytes with checked arithmetic, avoid map-size subtraction underflow when LMDB reports used size at or above map size, compare thresholds through integer arithmetic.
- at `do_resize` compute the target map size with checked addition, explicitly leave the database unavailable if resize fails after closing the handle.
- make direct reads, existence checks, iterators, and batches resize-aware; remove caller-selected deserialization modes in favor of strict deserialization, create read/write batches with resize guards.
- build prefix iterators over the active read or write transaction instead of creating a separate store iterator, and use strict deserialization for batch `get_ser`.
- rework `PrefixIterator` to support owned read transactions plus borrowed read/write batch transactions, return `Result` items, propagate LMDB cursor and deserialization failures instead of logging and skipping corrupt records, keep the resize guard alive for owned store iterators.

**src/pmmr.rs**
- add `PMMRFileSet` to track hash, data, leaf, prune, and size file presence before opening a backend, supporting later partial-file-set validation.
- make `PMMRBackend::append` return the typed PMMR error, prevalidate data/hash sizes with checked arithmetic, compute prunable leaf positions with overflow checks, roll back buffered data/hash writes on failures or size mismatches, propagate leaf-set update errors instead of silently mutating partial state.
- expand pruned-subtree append support to include parent hashes, enforce prunable-only and contiguous range invariants, use checked hash counts and sizes, append prune-list entries exactly, roll back hash-file updates if subtree or prune-list updates fail.
- make direct hash append `append_hash` return typed errors, verify the expected hash-file size after append, roll back the unsynced hash tail on append failures or size mismatches.
- make hash/data lookups return `Result`, handle prunable and non-prunable backends separately, use checked position/shift arithmetic, report missing stored hashes or leaf data as `DataCorruption`, propagate leaf-set membership failures instead of converting all read problems to `None`.
- make leaf-position and leaf-index iteration/counting fallible, implement non-prunable iteration instead of panicking, validate stored leaf-set entries, add `leaf_pos_iter_from`, replace saturating or unchecked index math with checked PMMR conversions.
- make rewind, prune-list reset, removal, snapshot, and stats paths use typed errors; precompute rewind targets before mutating backend state, reject forward rewinds, return whether removal changed the leaf set, snapshot with the stored context id, avoid infallible size assumptions in debug stats.
- update backend construction to return PMMR errors, accept explicit variable-size metadata validation, copy context-hashed leaf snapshots before append-only files can create partial state, validate existing PMMR file sets, pass context/validation into `DataFile` opens, initialize new prunable metadata files.
- add PMMR file-set validation helpers that reject symlinks and non-regular PMMR files, distinguish empty from partial file sets, validate existing leaf/prune metadata before use, reject incomplete hash/data or prunable metadata combinations.
- make prune/compaction helpers and size accessors fallible, short-circuit compaction checks for non-prunable backends, include unsynced buffered hash changes in unpruned size, check total-shift arithmetic for overflow.
- harden compaction by returning typed errors instead of asserting, syncing before compaction, rejecting cutoffs beyond the current PMMR size, computing hash/data removal positions with checked arithmetic, rebuilding the prune list fallibly.
- make removal-position expansion fallible, propagate leaf-set, prune-list, and PMMR-family errors, and replace unchecked one-based bitmap-position casts with checked conversion helpers.
- make root-exclusion filtering fallible and report overflow when parent PMMR positions cannot fit the bitmap domain instead of truncating them.
- replace silent cleanup error discards with `CleanupStats`, count and log per-entry inspection, metadata, access-time, UTF-8, and delete failures while continuing best-effort cleanup, and keep `read_dir` failure as the only whole-operation error.

**src/prune_list.rs**
- make constructors, `open`, and cache initialization return PMMR `Result`s, reject persisted zero bitmap entries with explicit errors instead of assertions, rebuild input bitmaps through fallible append logic, distinguish `NotFound` from other bitmap read errors, and propagate cache-building failures.
- update `flush` to refresh the persisted bitmap backup after a successful save.
- add `discard`/`restore` paths that validate replacement bitmaps and rebuild caches so failed in-memory mutations can be rolled back.
- make total-shift and hash-shift lookup/building fallible, replace unchecked one-based bitmap casts and cache clamping with checked conversion/cache access, reject zero bitmap entries during rebuild, check shift heights before bit shifts.
- apply the same fallible checked-arithmetic hardening to leaf-shift lookup/building, centralize bounded shift and leaf-shift calculations, and remove the old infallible next-shift helpers.
- split subtree cleanup into a fallible planning phase and a mutation phase, using checked `bintree_leftmost`, `u32`, `usize`, range-start conversions before truncating caches or removing bitmap ranges.
- make append paths return `Result`, replace append-only assertions with internal errors, precompute bitmap/cache updates before mutating state, validate prior cache entries, use checked shift accumulation, propagate PMMR family/prune checks, add `append_exact` for imported pruned subtrees that must not roll up sibling roots.
- make prune membership/root checks fallible, replace unchecked rank/select/root conversions with overflow-checked logic, propagate `bintree_range` errors.
- make pruned-range, unpruned-position, and unpruned-leaf iterators return `Result`, reject corrupt zero positions, check range-bound increments, collect validated excluded ranges before building the unpruned iterator, guard leaf filtering against zero positions.
- add shared helpers for checked one-based bitmap position conversion, cache-rank validation, and last-bitmap-index lookup.
- add iterator completion state, replace recursive `next()` calls with an iterative loop to avoid stack exhaustion on many excluded ranges.
- add regression tests for cache/rank corruption reporting and iterative skipping of many consecutive excluded ranges.

**src/types.rs**
- add helpers to normalize serialization errors into `io::Error`, reject append-only data paths using the reserved `.tmp` extension, detect same-file data/size path aliases, open existing regular files or create new regular files without following unsafe paths, validate fixed-size element alignment without divide-by-zero or truncation.
- add `VariableSizeMetadataValidation` with `Full` and `Fast` modes so callers can choose full data-file deserialization checks or cheaper structural size-file checks when opening variable-size append-only files.
- harden append-only open by rejecting reserved temp paths, data/size file aliases including same backing files and dirty size-file state.
- initialize files through the regular-file helper, track newly created files for parent-directory sync, remap through a documented `memmap2` wrapper, compute fixed-size element counts with alignment checks, propagate size calculation errors, serialize with the context id, validate fixed-size serialized lengths before buffering.
- add full and fast variable-size metadata validators; the full path deserializes the data file and compares every generated offset/size entry, while the fast path verifies contiguous non-zero size entries cover the data file exactly.
- validate raw append input for fixed-size alignment, reject empty or over-`u16` variable-size writes, compute variable-size offsets with checked addition, and keep the size metadata synchronized with buffered writes.
- make offset calculation use checked multiplication, change rewind to return `Result`, reject forward rewinds, truncate in-buffer rewinds without touching persisted state, propagate size-file rewind failures, clear dirty buffered bytes after rewinding persisted state.
- add bounded unsynced-truncation, buffer-length, buffer-start-offset, mmap, and dirty-state helpers; so rollback and flush paths can validate metadata-derived lengths, reject persisted truncation through the buffered-only path; use checked offset arithmetic, and detect pending nested size-file state.
- rewrite flush to be retry-safe by truncating to the logical buffered start before rewriting, opening through the regular-file helper, syncing data before size metadata, syncing the parent directory for newly created files, remapping after fsync, and clearing backup state only after a successful durable write.
- update discard to restore optional rewind backup state, make reads return `Option` for missing positions, replace silent empty-slice fallbacks with explicit `UnexpectedEof`/`InvalidData` errors, use checked buffer/mmap range calculations, deserialize strictly with the stored context id.
- read temp-file and pruning inputs through regular-file helpers, write pruned data with a context-aware `BinWriter`, bound loops by file length instead of swallowing read errors, detect no-progress reads and unmatched prune positions.
- reject `replace_with_tmp` when the data or size files still have unsynced state, preventing compaction replacement from running over dirty append buffers before rebuilding variable-size metadata and reinitializing the file.
- ay `rebuild_size_file` rebuild variable-size metadata through regular-file helpers, context-aware writers, explicit file-length bounded reads, checked consumed-byte deltas, zero-size and `u16` overflow rejection, fsync of the rebuilt size temp file before replacement.
- keep the legacy remove-then-rename replacement behavior documented, release mmap/file handles before replacement, fsync the parent directory after renaming so replacement durability is not left only to the file contents sync.
- add regression tests for direct path, dot-path, and hard-link data/size alias rejection, unsynced size-file state rejection during open, and corrupt variable-size metadata that would otherwise compute a buffered truncation length beyond the actual append buffer.

**tests/lmdb.rs**
- update tests with functions signature changes (no structure/functionality changes).
- add Unix regression coverage for secure LMDB environment directories, verifying new stores create owner-only `0700` environment directories, preexisting group/other-writable directories are rejected, and symlinked environment directories fail to open.
- update `test_exists` to the explicit `mwc_store` API and add batch iterator coverage proving uncommitted writes are visible through the batch transaction while remaining hidden from the store until commit.
- add stability regressions for idempotent repeated `Store::open` calls, `DbUnavailable` not being classified as not-found, and map resizing waiting for an active batch/read transaction to release before proceeding.
- add iterator error-propagation coverage proving mapper/deserialization errors are returned to callers instead of being logged, skipped, or converted into successful iteration.

**tests/pmmr.rs**
- update tests with functions signature changes (no structure/functionality changes).
- add leaf-position and unpruned-leaf regression coverage for `leaf_pos_iter_from`, PMMR view-size-aware leaf counts, readonly PMMR leaf counts, and the leaf-index boundary used by `n_unpruned_leaves_to_index`.
- add PMMR backend open hardening tests for non-leaf leaf-set entries, missing prunable metadata, metadata-file creation before sync, leaf-set files without hash/data files, non-regular PMMR files, Unix symlink PMMR files, symlinked data files, and snapshot-copy failures that must not leave backend files behind.
- add PMMR backend regressions for non-prunable high-position read paths that bypass `u32` prune metadata, non-contiguous pruned-subtree rejection without hash growth, and repeated removal of a missing leaf returning `false`.
- add fixed-size data-file and append-only-file validation tests for partial trailing elements, retry-safe flush truncation after a partial prior write, wrong serialized element sizes, and unaligned raw-byte appends.
- add append-only path and variable-size append validation tests rejecting reserved `.tmp` persistent paths and empty raw variable-size appends without creating durable data or size bytes.
- add variable-size metadata validation coverage for rebuilding bad offsets, bad element boundaries, and zero-size entries; also cover fast validation skipping data deserialization while still rebuilding structurally bad offset metadata.
- add compaction replacement safety tests rejecting `replace_with_tmp` while fixed-size data files, rewound files, or variable-size size metadata still have unsynced state.
- add discard and rewind-buffer regressions proving unsynced rewinds restore clean buffer starts, fixed-size and variable-size rewinds can truncate inside buffered data, and rewinding to the buffer start discards later unsynced entries.
- add pruned-temp-write validation tests rejecting unconsumed prune positions, zero prune positions, and zero-byte read progress while rebuilding pruned data files.
- add PMMR mutation safety tests for failed pruned-subtree appends preserving hash size, future compaction cutoffs being rejected, unsynced pruned-subtree hashes contributing to unpruned size, and discard restoring prune-list state.
- add PMMR read and rewind regressions for missing live leaf data surfacing as `DataCorruption`, consecutive pruned leaf subtrees reading the stored sibling hash for parent construction, and forward data-file rewinds being rejected without losing existing data.
- add a Unix permission regression proving per-entry cleanup failures are reported without failing the whole directory scan.
- add test-only element types for validation edge cases, including an unreadable variable-size element, short and long fixed-size serializers, and a zero-progress reader.

**tests/prune_list.rs**
- update tests with functions signature changes (no structure/functionality changes).
- add `discard_restores_last_flushed_prune_list`, a regression proving `discard` rolls back unflushed bitmap, shift-cache, and leaf-shift-cache mutations to the last flushed prune-list state.

**tests/segment.rs**
- update tests with functions signature changes (no structure/functionality changes).
- add `segment_proof_reads_pruned_leaf_sibling_from_hash_file`, a regression that prunes one of two leaves, verifies the live hash lookup returns `None` while the hash file still contains the pruned sibling, validates a segment proof that must read that sibling hash from storage.

**tests/test_bitmap.rs**
- update tests with functions signature changes (no structure/functionality changes).

**tests/utxo_set_perf.rs**
- update tests with functions signature changes (no structure/functionality changes).

### mwc-node/config

**Summary of the changes:**
- error propagations.
- zeroize sensitive information.

**Cargo.toml**
- remove imported crates, add `mwc_crates` instead.
- add thiserror (it can't be reexported)

**src/comments.rs**
- remove generated comments for `libp2p_enabled` and `libp2p_port`, remove external Tor daemon, SOCKS proxy, and onion-service address.
- remove the generated `run_test_miner` comment block, avoiding a developer-only mining option in user-facing config output.
- change `insert_comments` to borrow the input `&str`, return `Zeroizing<String>`, drop the intermediate line vector, and allocate a zeroizing output buffer with extra capacity.

**src/config.rs**
- make default MWC path discovery fail on missing or non-absolute home directories and verify both `~/.mwc` and the chain-specific subdirectory through secure directory creation instead of unguarded `create_dir_all`.
- add platform-specific `ensure_secure_mwc_dir`; Unix creates `0700` directories, opens them with `O_DIRECTORY`, `O_NOFOLLOW`, and `O_CLOEXEC`, verifies directory type, owner, and unsafe group/other write bits, then tightens permissions to `0700`, while non-Unix keeps portable creation and directory validation.
- make current-directory config lookup return `Result` and propagate `current_dir`/`try_exists` failures instead of silently falling back to the home config path.
- replace thread-local `Alphanumeric` secret generation and plain `File::create` with `SysRng` rejection-sampled generation stored in `Zeroizing<String>`.
- harden API secret validation by opening owner-only files or rotating exposed readable secrets, rejecting oversized files, reading secret bytes into zeroized storage, requiring valid UTF-8, allowing only empty trailing lines, rotating empty/noisy/too-short secrets, preserving read/UTF-8 failures instead of blindly regenerating.
- replace chain-type-derived secret-file checks with helpers that validate the configured `api_secret_path` and `foreign_api_secret_path` from the loaded config.
- load or create the server config before checking secrets, use fallible current-directory lookup and `try_exists`, adapt setup to the now-fallible chain defaults, validate configured API secret files so custom secret paths are honored.
- make `GlobalConfig::for_chain` return `Result`, remove default `libp2p_port` assignments for Floonet and UserTesting, switch UserTesting seeding to explicit `Seeding::None`, and return `ConfigError` for `AutomatedTesting` instead of panicking.
- replace `read_to_string` and plain migration rewrites with owner-only config opening, checked length conversion, zeroized fixed-size reads, changed-size and UTF-8 validation, zeroized migration output, owner-only rewrites only when migration changed, scoped warning-level normalization, post-parse config validation.
- add shared Dandelion config validation, make serialization return `Zeroizing<String>` after validation, and write generated configs through zeroized log-level/comment processing plus owner-only file writes while documenting manual Tor key handling.
- make config migration consume and return zeroized strings with a changed flag, reject future config versions, keep legacy textual replacements in zeroized buffers, verify restored TOML equivalence before reporting a changed migration.
- narrow log-level normalization to active `stdout_log_level` and `file_log_level` fields, preserve comments, paths, and secret values, support single and double quoted values with trailing comments, and use zeroized output buffers with extra capacity for growing replacements.
- expand log-level tests to verify scoped field replacement and preservation of non-target fields and commented settings instead of whole-string global replacement.
- add test helpers for unique temporary config/secret paths and Unix owner-only permission setup.
- add API-secret regression tests for empty trailing lines, short/noisy secret rotation, group/world-readable rotation, owner-only permission repair, group/world-writable rejection, configured secret path usage, read/UTF-8 error preservation.
- add secure directory regression tests for `0700` creation, tightening existing non-writable directories, rejecting group/world-writable directories, rejecting symlinked directories on Unix.
- add owner-only config and secret file regression tests covering secret creation, config writes and permission repair, config read permission tightening/rejection, Dandelion stem-probability validation, invalid UTF-8 rejection, fixing existing secret-file permissions before rewriting.

### mwc-node/chain

**Summary of the changes:**
- error propagations.
- update rules for blocks, how we can recognize duplicated blocks.
- expand error reporting details

**Cargo.toml**
- remove imported crates, add `mwc_crates` instead.
- add thiserror (it can't be reexported)

**src/chain.rs**
- add source-peer tracking to orphan blocks, make orphan insertion fallible and context-aware, reject conflicting orphan bodies that share the same header hash, merge duplicate-block peer sources, and keep eviction/index cleanup bounded and documented.
- add robust read wrappers, durable pending-chain-operation markers, readonly PMMR discard markers, lock-invariant checks, marker cleanup, and automatic recovery paths for failed PMMR/header mutations.
- make chain initialization accept a caller-supplied secp context plus optional sync and stop state, validate genesis before opening storage, open the header PMMR with full variable-size metadata validation, recover any pending chain operation, rebuild output/kernel/spent-commitment indexes in resumable chunks, initialize the new difficulty cache and recovery flag.
- restrict internal lock/store getters to tests.
- rewrite bad-block rewind handling to distinguish header-only and full-body-chain denials, skip adjacent denied ancestors, require missing full bodies to fail safely, validate roots and sizes after rewinds, delete denied descendants with checked context-aware hashes, preserve the old header head for cleanup, mark recovery on partial failures.
- make block processing report bad-data rejections back to the adapter, use checked height arithmetic and context-aware hashes, propagate orphan-drain errors, retry single-block processing after multi-block failures.
- at `convert_block_v2` protect readonly rewinds with discard markers, make status calculation fallible, compare exact serialized block bytes before treating duplicate hashes as known, allow same-hash/different-body blocks to reach validation.
- wrap single-block, multi-block, header, and header-sync mutations in pending-operation markers, pass mutation state into pipe processing for recovery decisions, use caller-provided secp for adapter notifications.
- expose targeted orphan removal and make orphan draining best-effort but fallible, preserving peer attribution for bad child blocks while preventing stale orphan failures from invalidating an already accepted parent.
- validate `output_pos` entries against the canonical body chain, rebuild the output position index once when a stale height is detected, and verify output PMMR positions fall inside the block header's output range before returning header data.
- route transaction, input, coinbase maturity, replay, validation, root-setting, and Merkle-proof reads through robust read/readonly-marker paths, use checked next-block heights, rewind replay checks to the body head.
- harden PIBD segmenter/desegmenter setup by serializing cache misses under a write lock, validating archive headers against body-chain and header-PMMR state, building header-hash MMR data with the chain context id, returning explicit root mismatch errors, passing recovery state into desegmenters, adding stop/status-aware kernel-history validation.
- make compaction stoppable and recovery-marked, chunk historical block deletion, recheck compaction eligibility after lock acquisition, choose the compaction horizon from the canonical body chain rather than the header chain, verify body/header PMMR alignment, rebuild indexes with stop support, run historical cleanup only after the compact batch commits.
- make last-output/rangeproof/kernel and output-listing reads return `Result`, cap `last_index` to the local output PMMR size, validate output/rangeproof PMMR position alignment, and resolve block-height output bounds from the body chain with overflow and invalid-range checks.
- require chain robustness before public store/header accessors. 
- add retained spent-commitment replay-index initialization, including completeness flags, chunked clearing/saving, canonical body-window traversal from `BODY_HEAD` to `BODY_TAIL`, stale-tail repair, missing-body detection.
- make output-header lookup depend on the validated unspent-position path, add one-shot output-position index repair, replace kernel scanning with the durable kernel-position index, enforce index completeness, verify kernel excess/height consistency.
- convert current-chain membership checks to boolean robust reads, add body-chain traversal helpers, harden locator-hash reads with readonly PMMR discard markers and height validation.
- add shared helpers for PIBD reset, reset-head marker preparation, pending-operation recovery, PMMR reconciliation to DB heads, reset-head state rewinds, and output/rangeproof pairing with per-position validation.
- add helper validation for genesis context id, exact hardcoded Mainnet/Floonet genesis matching, header-PMMR genesis consistency, recoverable MMR corruption classification, genesis block-sum calculation, and saving genesis metadata.
- refactor `setup_head` to validate genesis context/hash, stage intentional body-head resets atomically, rebuild genesis MMR/prune/index state on reset, distinguish `NotFound` from other store errors, validate roots and sizes, rebuild missing block sums, mark indexes incomplete after PMMR rewinds, recover only recognized MMR data corruption by rewinding one block.
- add regression coverage for spent-commitment index completeness and retained-window gaps, orphan peer merging and conflicting-body rejection, compaction eligibility, output/rangeproof position mismatch, temporary filename validation, hardcoded production genesis validation, testing genesis PoW validation, and genesis block-sum edge cases.

**src/error.rs**
- at `Error` add `InputMismatch` plus `ReplayAttack` variants for stricter input identity and retained-spent-commitment replay detection, add incomplete kernel/spent-commitment index, IO, block migration, txhashset discard, discard-after-primary-error, and PMMR variants.
- add `ChainRestartRequired` plus `DataOverflow` to separate corruption/restart requirements from arithmetic or sizing overflow failures.
- add `EmptyMMR`, giving sync, segment, core, and PMMR edge cases precise error reporting.
- rewrite `is_bad_data` as an explicit classification table.
- add helpers for detecting txhashset discard cleanup failures and missing chain data.
- add regression tests for local-vs-remote bad-data classification, txhashset discard-after-error primary classification, and PoW overflow/invalid-configuration conversion.

**src/lib.rs**
- add the crate-level `tests` module behind `#[cfg(test)]`, keeping regression test wiring out of normal builds.

**src/linked_list.rs**
- when popping the head of a two-entry list down to `Single`, delete both old entry records before saving the single-list wrapper so stale tail-entry data cannot remain in the index.
- replace the `unimplemented!` pruning placeholder with a returned `Error::OtherErr`, preventing an unexpected panic if the not-yet-implemented prune path is reached.

**src/pibd_params.rs**
- replace wall-clock `DateTime<Utc>` timestamps with monotonic `Instant` values.
- compute per-peer block and segment request caps with saturating CPU multiplication, accept optional average latency in block and segment limit calculations, require a nonempty segment request table, keep calculated request limits bounded to at least one.
- rewrite `get_network_speed_multiplier` updates to treat missing latency as neutral, treat timeout latency as measured slow latency, use a monotonic five-second update interval with read-then-write rechecks, clamp multiplier increases/decreases for more stable PIBD request throttling.
- make `calc_mem_adequate_val2` return `Result`, reject empty value tables before indexing.
- update tests to shared imports and monotonic timing, add regression coverage for empty value-table rejection, missing-latency neutral behavior, and timeout-latency slowdown, and update the sysinfo memory refresh calls to the newer API.

**src/pipe.rs**
- add a `DifficultyCache` write guard to `BlockContext` and centralize `SKIP_POW` handling in `skip_pow`.
- add `KnownStatus` for duplicate/old-block control flow so normal duplicate outcomes can be converted to errors only when the caller needs that behavior.
- update known-block checks to return `KnownStatus` instead of immediately converting duplicate or old-block results into errors.
- harden retained spent-commitment replay checks by requiring index completeness, verifying stored index heights against canonical headers.
- refactor PoW validation to accept an explicit verifier and skip flag, distinguish invalid proofs from other verifier failures, propagate non-verification PoW errors, add parallel batch PoW checking for larger header-sync batches.
- split header validation into reusable helpers that use checked height arithmetic, complete-PMMR-size validation, fallible MMR count and weight calculations, checked total-difficulty subtraction, explicit difficulty/scaling checks.
- make block-series processing accept mutation-state tracking and a mutable secp context, use context-aware hashes and checked height arithmetic, delay exact duplicate full-block rejection until after PoW/body validation, make txhashset rollback a series-wide decision, handle missing body tail precisely.
- rewrite header-batch processing to validate contiguous input before storage mutation, use a local rolling `DifficultyCache`, detect same-hash/different-header conflicts, validate denylists and previous-header rules, advance difficulty data in memory, run PoW checks in parallel.
- add `validate_header_batch_contiguous` to reject non-contiguous header-sync batches with checked height increments and context-aware previous-header hashes.
- update single-header processing to use `KnownStatus`, explicit orphan mapping, same-hash/different-header detection, mutation-state tracking for header-PMMR changes.
- harden duplicate detection by validating stored headers before trusting known hashes, distinguishing store `NotFound` from other storage failures.
- centralize previous-header lookup so missing parents become `Orphan` while other store errors keep context, simplify `validate_header` around the shared helpers plus the guarded difficulty cache.

**src/store.rs**
- remove skip-PoW header read helpers.
- add chain-store helpers for reading, setting-if-absent, rejecting duplicate, and clearing durable pending chain-operation markers.
- add `ignore_not_found` and batch context-id helpers, add idempotent body-tail deletion, update reads to the current store API.
- deduplicate replay-index entries, bound spent lists by `READ_VEC_SIZE_LIMIT`.
- generalize boolean flag reads/writes, add completeness accessors for kernel-position, output-position, and retained spent-commitment indexes, add generic chain-marker read/write/delete helpers.
- make block migration use strict deserialization and fail on missing records, make block deletion propagate non-`NotFound` cleanup errors while tolerating idempotent misses, delete associated block sums/spent indexes explicitly, save headers with context-aware hashes.
- add the durable kernel excess-to-position index with strict iteration, per-entry deletion, full and chunked clearing, chunked clearing for retained spent-commitment replay-index rebuilds.
- make `output_pos_iter` return fallible strict-deserialization items, apply checked output-position subtraction in batch reads.
- remove batch skip-PoW header helpers, update header/block-sum/spent-index reads to the current store API, delete legacy input bitmaps during spent-index deletion, propagate corrupt spent-index errors instead of falling back, validate legacy croaring bitmaps including trailing-data rejection.
- make full-block and raw-block iterators return fallible items and deserialize blocks strictly with the store protocol version and context id.
- make `DifficultyIter` yield `Result`, read full headers, propagate header IO failures, distinguish missing history from storage errors, and report difficulty-subtraction or negative-timestamp overflow instead of silently defaulting or ending iteration.
- add serialized `ChainMarker`, `ChainOperationKind`, and versioned `PendingChainOperation` payloads for recovery of interrupted LMDB/PMMR operations, with corrupt-data errors for unknown kinds, versions, variants, and boolean fields.
- make `BoolFlag` reject noncanonical serialized values other than `0` or `1` instead of masking the low bit.
- add regression tests for noncanonical boolean flags, kernel-position index ordering and chunk cleanup, retained spent-index completeness and chunk cleanup, legacy bitmap fallback/corruption handling, and spent-commitment duplicate/oversized-list rejection.

**src/tests/chain_test_helper.rs**
- update tests with functions signature changes (no structure/functionality changes).
- rebuild the reward-bearing testing genesis through the global genesis lookup with an explicit mutable secp context, checked reward attachment, context-aware MMR-root recalculation, and PoW mining using the genesis context id and difficulty.
- add `set_genesis_mmr_roots`, which recomputes output, rangeproof, and kernel PMMR roots/sizes with context-aware `VecBackend` instances so the custom test genesis metadata is internally consistent.
- use `DifficultyCache`, and unwrap the now-fallible `next_difficulty` result instead of relying on the old `VecDeque<HeaderDifficultyInfo>` flow.

**src/tests/mine_simple_chain.rs**
- update tests with functions signature changes (no structure/functionality changes).
- add read-path regression coverage for reversed block-height PMMR ranges, clamped unspent-output listing limits, header-PMMR lookup error propagation in `locate_headers`, and locator-hash validation for heights above the sync head or missing after a rewind.
- add block-height-to-PMMR index tests proving header-only state is capped to the body chain, header forks do not drive output bounds, and corrupt body-chain predecessor links produce explicit traversal errors instead of silent bad ranges.
- add output-position and PIBD reset coverage for rebuilding a missing genesis output at height zero and preserving the genesis output's visibility after compaction plus `reset_pibd_chain`.
- add stale and missing output-position index regressions for `get_unspent` and `get_header_for_output`, including one-shot repair of stale heights, whole-index repair after multiple stale entries, and no repair when the output-position entry is absent.
- add body-chain-aware output and kernel lookup regressions, including `get_header_for_output` and `get_header_for_kernel_index` on header forks plus stale kernel-position height rejection.
- add output-position index rebuild tests that map missing outputs from the canonical body chain and return a clear error when the body head makes a missing output impossible to map.
- add invalid-block rewind tests for header-only and header-fork cases, verifying bad header-chain state is removed while the valid body head and stored body block remain intact when appropriate.
- add known-header/full-block fast-path and header-only validation regressions for same-hash mutated headers, incomplete output/kernel MMR sizes, and wrong-height headers classified as bad remote data.
- harden the negative-output test builder so the inverted test commitment remains while the placeholder rangeproof is built against a matching normal commitment, matching the stricter rangeproof validation path and returning fallible output insertion errors.

**src/tests/process_block_cut_through.rs**
- update tests with functions signature changes (no structure/functionality changes).
- add a missing-predecessor regression that corrupts a block's previous header hash, runs the internal block-series pipeline with `SKIP_POW`, and verifies the result is an `Orphan` error instead of mutating chain state or collapsing into a generic failure.
- add a readonly-PMMR recovery regression that seeds a `ResetToGenesis` pending-operation marker, performs a block-building path that reads PMMR state, and verifies the existing marker is preserved.

**src/tests/store_indices.rs**
- update tests with functions signature changes (no structure/functionality changes).

**src/tests/test_block_known.rs**
- update tests with functions signature changes (no structure/functionality changes).
- add deterministic PoW verifier helpers, including an accept-all verifier and a forced-failure verifier for genesis validation coverage.
- add a full-block duplicate regression proving a stored header hash with a different body is not accepted as a normal duplicate and is instead classified as bad data.
- add a header-sync duplicate regression that mutates a known header while preserving its context-aware hash, then verifies sync rejects the same-hash/different-header conflict with a specific error.
- add reset-to-genesis recovery coverage for a persisted `ResetToGenesis` marker plus missing txhashset files, verifying genesis MMR roots/sizes are rebuilt, the body head returns to genesis, and the pending operation marker is cleared.
- add reset-to-genesis metadata coverage that deletes the stored genesis block, confirms block and block-sum reads fail, resets to genesis, verifies both are restored, and confirms the first block can be processed again.
- add genesis context-id mismatch coverage that rejects a genesis block for the wrong chain context without creating chain data, then verifies initialization succeeds with the matching context id.
- add genesis validation regressions for invalid genesis height and invalid PoW, with assertions that rejected initialization leaves no chain directory behind.
- add production/Floonet genesis validation coverage that rejects a mutated txhashset commitment root even when PoW is accepted by the test verifier.
- add existing-chain genesis-hash mismatch coverage that rejects startup with a different genesis hash over valid stored chain data, keeps the original chain reusable, and verifies the invalid header was not persisted.

**src/tests/test_pibd_copy.rs**
- update tests with functions signature changes (no structure/functionality changes).
- add a non-ignored regression proving `HeadersRecieveCache::new` rejects a missing header-hash entry with a clear error, using a sanitized per-test directory, explicit commit-capable secp context, and context cleanup.

**src/txhashset.rs**
- add `ensure_complete_pmmr_size`, a public helper that verifies a PMMR size ends on a complete MMR boundary and rejects incomplete subtree boundaries.
- add test for complete and incomplete PMMR sizes, confirming accepted boundary sizes and `Error::InvalidMMRSize` rejection for malformed sizes.

**src/txhashset/bitmap_accumulator.rs**
- make `init` consume fallible sorted PMMR index items, reset existing state before rebuilding, 
- add checked chunk-count calculation for zero-size and overflow-safe sizing.
- harden `apply_from` by propagating iterator errors, enforcing ascending indices, comparing chunk indexes instead of multiplying potentially overflowing bounds, appending empty chunks up to the target bitmap size, using checked chunk increments.
- make `apply` validate invalidated indexes against bitmap size, rebuild from the beginning when no invalidation is provided, detach the rewound PMMR tail before mutation, restore it if padding or reapplication fails so partial accumulator updates do not persist.
- change rewinds to return a restorable `VecBackendTail`, use checked PMMR index and leaf-count helpers, preserve concrete PMMR errors from chunk appends.
- make bitmap reconstruction fallible, route leaf-position iteration and data reads through checked backend APIs, replace unchecked offset arithmetic with overflow checks.
- implement real `BitmapChunk` deserialization by reading exactly the fixed chunk byte length and validating the recovered bit length.
- add checked `BitmapSegment` block-count serialization and strict segment reads that reject empty segments, overlarge PIBD/identifier block counts, zero-chunk blocks, short non-final blocks.
- add validation helpers that derive PIBD chunk/block limits, validate block layout, reject pruned hash data in writable bitmap segments, require contiguous expected leaf positions, convert arithmetic failures into explicit data-overflow or corrupted-data errors.
- replace infallible `From` conversions between `Segment<BitmapChunk>` and `BitmapSegment` with `TryFrom`, validating leaf data, segment capacity, PMMR leaf offsets, insertion positions, chunk lengths, and block layout.
- make `BitmapBlock::new` and chunk counting fallible, replacing debug-only assumptions with checks for maximum chunk count, maximum bit length, and chunk-aligned block sizes.
- harden `BitmapBlock` writing with checked length and chunk invariants, checked positive/negative count arithmetic, bounded byte lengths, explicit serialization errors.
- harden `BitmapBlock` reading by rejecting non-canonical raw encodings, sparse counts at or above the canonical threshold, sparse counts larger than the block, out-of-range indexes, duplicate indexes, and out-of-order sparse index lists.
- add test helpers for constructing serialized bitmap segment, block, proof, and chunk-segment fixtures used by the new malformed-input regressions.
- add regression coverage for exact chunk serialization, truncated chunk reads, oversized block creation, segment read and conversion limits, empty and short non-final blocks, pruned-hash and non-contiguous leaf rejection, valid short final blocks, and invalid block write lengths.
- add accumulator regressions for final-`u64` chunk handling without boundary overflow, `init` resetting previous data, zero-size initialization clearing state, and preserving the concrete PMMR error variant on append failure.
- add malformed bitmap-block decode helpers and regressions covering out-of-range sparse indexes, over-threshold or oversized sparse counts, non-canonical negative and raw encodings, duplicate sparse indexes, and unsorted sparse indexes.

**src/txhashset/desegmenter.rs**
- add `kernel_validation_thread_range` - checked kernel-validation thread range calculation, rejecting zero worker counts and arithmetic overflow instead of relying on unchecked division and multiplication.
- add checked non-prunable segment sizing/count helpers plus robustness, recovery-flag, canonical archive-header, and pending chain-operation marker helpers, including a defensive header-PMMR lock invariant before writing durable markers.
- harden leaf-set updates by requiring robust state and a ready bitmap, wrapping txhashset mutation in a `PibdReset` pending-operation marker, clearing the marker on success, and marking init recovery required on failure.
- extract `validate_kernel_history_parallel` (parallel kernel-history validation) into a stop-aware helper with canonical archive-header checks, checked thread ranges, throttled status updates, explicit thread-start error handling, and first-error propagation across workers.
- harden `validate_complete_state` by checking robust state first, validating roots and kernel history before mutation, using canonical archive-header checks, saving context-aware block sums.
- make desired-segment selection recovery-aware and zero-request safe, use recursive locks, rely on cache receive-window APIs, return waiting/retry requests, and use checked subtraction when consuming the request budget.
- make bitmap finalization and bitmap-MMR sizing fallible, build the output bitmap from the accumulator, derive rangeproof sizing through `PMMRable`, generate output/rangeproof/kernel segment caches through checked helpers.
- harden `add_bitmap_segment` - bitmap segment intake with robust-state and root checks, explicit segment-id/window/duplicate validation, fixed lock ordering while applying bitmap chunks, recovery marking in case of failure.
- harden output, rangeproof, and kernel segment intake by validating cache eligibility before expensive authentication and again before mutation, validating segments outside the write lock for concurrency, wrapping txhashset writes in pending-operation markers and batches.
- add `sibling_expanded_bitmap` - sibling expansion and strict sizing for prunable bitmap-driven segments, rejecting out-of-range bitmap leaves, enforcing paired leaf counts for sibling coverage.
- make next-segment calculation return `Result`, validate bitmap cardinality range conversions, enforce segment data-size limits for selected segments, replace capacity, height, and cursor arithmetic with checked operations.
- make segment-list generation fallible, expand prunable bitmaps before planning segments, validate with checked arithmetic, reuse the checked non-prunable segment-height/count helpers for kernel segment planning.
- add unit tests for kernel validation range splitting and overflow, non-prunable segment sizing limits, prunable segment size validation, raw bitmap sibling expansion, out-of-range bitmap rejection, and segment size-limit failures.

**src/txhashset/headers_desegmenter.rs**
- add helpers for checked next-height arithmetic, bad-header peer attribution, and cached-run retry selection.
- make `HeaderHashesDesegmenter::new` fallible, require the chain context id, derive PMMR size and segment counts through checked helpers, reject excessive target heights, and initialize the header PMMR with context-aware storage.
- harden `add_headers_hash_segment` - header-hash segment intake with fallible segment-id/window/duplicate checks, checked leaf offsets, full segment authentication against the expected root and PMMR bounds, non-prunable PMMR enforcement, direct propagation of PMMR append errors.
- store the authenticated headers root in `HeadersRecieveCache`, seed it during construction, add cache-inclusive progress reporting for sync status, add desegmenter identity matching so cached headers are reused only for the same target/root commitment.
- reset the stored root hash with cache state, use saturating cache-window arithmetic, track cached runs safely for retry decisions, convert PMMR hash indexes with overflow checks.
- require exact header batch length, reject batches starting past the target height, validate start and next hash checkpoints, verify consecutive heights and `prev_hash` linkage with context-aware hashes before caching, allow only the terminal batch to omit a next checkpoint while bounding validation to the PIBD target.
- apply cached headers without dropping unattempted batches prematurely, truncate terminal batches above the archive target, remove stale/applied batches explicitly, fall back from bulk apply to per-batch apply with bad-data peer attribution, use checked next-height calculations when deciding whether more cached data can be applied.
- add an overflow-safe header-batch count helper used by cache-inclusive progress reporting.
- add regression coverage for desegmenter/cache identity matching, cached-run retry behavior, overflow-free batch counting, bad-batch eviction, oversized target rejection, checkpoint presence checks, internal header height/link validation, and terminal-batch checkpoint handling.

**src/txhashset/segmenter.rs**
- add checked non-prunable segment sizing helpers that validate the requested range, cap leaves to the actual MMR leaf count, include per-leaf position bytes, convert counts safely, and reject overflowing or over-limit payloads.
- add `bitmap_mmr_size`, deriving bitmap accumulator MMR size from output leaves with checked chunk-bit, leaf-count, peak, and final-size arithmetic, including the zero-output case.
- add `header_hashes_mmr_size`, deriving the header-hash MMR size from `HEADERS_PER_BATCH` with checked target-height arithmetic.
- add prunable segment scan-span validation to reject output/rangeproof out of possible range segment ids.
- expose cheap preflight validators for kernel, bitmap, output, rangeproof, and header-hash segment requests so malformed or oversized peer requests can be rejected before initializing a `Segmenter`.
- harden output segment generation with recursive locking, scan-span validation, fixed-size discovery through `OutputIdentifier::elmt_size()`, explicit failure if output identifiers are not fixed-size.
- harden rangeproof segment generation with scan-span validation, fixed-size discovery through `RangeProof::elmt_size()`, explicit failure if proofs are not fixed-size.

**src/txhashset/segments_cache.rs**
- replace the infallible segment lookup with `required_segment_idx`, making leaf-offset conversion errors propagate.
- add receive-window validation so callers can reject segments outside the active cache window.
- make `next_desired_segments` selection return `Result`, handle zero-request batches explicitly, reject a zero cache-size limit, use saturating receive-window arithmetic, propagate checked leaf offsets.
- make `is_duplicate_segment` fallible so malformed segment identifiers or required-segment offsets surface as errors.
- `apply_new_segment` require a cache-size limit when applying segments, enforce active receive-window membership before caching, stage contiguous cached segments without removing originals until the callback succeeds, clone staged segments for retry safety, retain cursor/cache state on callback failure.
- add unit tests for zero desired-segment counts, invalid cache limits, cached-run retry behavior, leaf-offset error propagation, receive-window enforcement, accepted-progress accounting, and preserving staged cache state after callback failures.

**src/txhashset/txhashset.rs**
- add kernel-PMMR version-probe error classification so v2/v1 fallback only retries expected variable-size read/deserialization failures.
- validate heights against the PMMR leaf count, propagate PMMR data-read errors.
- open output and rangeproof PMMRs with full metadata validation, open kernel PMMRs with fast metadata validation during version probing, verify candidate kernels with the chain context id, include collected candidate errors when no kernel PMMR version can be opened.
- harden read/query helpers by validating `output_pos` entries against actual PMMR data before returning unspent outputs, positions, or Merkle proofs.
- make last-N and PMMR-index listing APIs return `Result`, clamp kernel searches to the local PMMR size, propagate typed root/PMMR errors instead of wrapping them as invalid roots.
- add full and chunked kernel-position index rebuilds with progress reporting, stop-state checks, stale-index completeness tracking, leaf-only PMMR scans, checked MMR-size/header ancestry validation, and a shared NRD recent-kernel verification path that can report either build or validation status.
- rewrite output-position index rebuilding to remove stale entries, verify index keys against PMMR commitments, derive output heights from canonical body-chain MMR ranges, support progress/status updates and stop requests, mark the index complete only after all unpruned outputs are mapped.
- add shared txhashset discard helpers that preserve the primary operation error while still surfacing rollback/discard failures, preventing cleanup failures from being silently ignored.
- harden readonly, writable, and header extension wrappers by propagating discard errors, using child batches for atomic index writes, adding `extending_with_head` for callers that validate against an explicit body head, syncing each PMMR backend separately.
- make `HeaderExtension` return `Result` from height lookup and current-chain checks, construct heads with `Tip::try_from_header`, perform checked rewind-position arithmetic, propagate PMMR root errors directly.
- remove the `Committed` trait implementation from `Extension`.
- resolve spent inputs before adding new outputs, save spent-index records for later rewind recovery, store spent commitments for replay detection, update heads through fallible tip conversion.
- make input pruning fail if the paired rangeproof leaf is already pruned or missing, validate duplicate-output checks against the actual output PMMR entry, reject stale or missing `output_pos` records, return checked 1-based output positions.
- make leaf-set updates and authenticated output/rangeproof segment application fully fallible, validate all supplied segment positions are PMMR leaves, reject future leaf positions instead of silently skipping them, convert bitmap leaf indexes safely, report pruning of already-pruned leaves as invalid segment data.
- update kernel application to save the durable kernel-position index, keep NRD rule enforcement tied to the saved commit position, reject hash data in non-prunable kernel segments, require segment leaf positions to match the current kernel PMMR size.
- validate Merkle-proof output lookups against context-aware output identity, propagate PMMR proof errors directly, keep snapshot errors explicit, initialize bitmap accumulators with the chain context id and fallible leaf-index iteration.
- rewrite txhashset rewind to prove the target header is on the canonical body chain, report rewind progress, rewind blocks one at a time, prefer stored spent indexes with controlled legacy fallbacks, reconstruct missing spent-index heights when possible, restore output/kernel indexes, rewind NRD state.
- add genesis rebuild support, typed root extraction, explicit empty-genesis validation rules, MMR-size validation that only skips truly empty genesis state, typed PMMR validation for output, rangeproof, and kernel trees.
- replace the old `Committed`-trait sum path with stop-aware batched `verify_kernel_sums_iter`, add state-validation progress stages, require explicit secp context, support an empty-genesis zero-offset shortcut, keep full rangeproof/kernel-signature verification behind the existing fast-validation flag.
- make dump helpers return `Result`, harden parallel kernel-signature and rangeproof verification with checked progress accounting, throttled status updates, stop handling at batch boundaries.
- replace the legacy `zip_read`, `file_list`, and `zip_write` snapshot helpers with a result-bearing `txhashset_replace` flow that backs up the existing txhashset directory, restores it if replacement fails, reports leftover-backup cleanup failures distinctly.
- harden rewind-input bitmap calculation and NRD kernel-rule enforcement by validating that the requested rewind target is on the body chain, rejecting missing input-bitmaps and non-descending header ancestry.
- keep PMMR hash/leaf segment insertion ordering centralized while preserving the genesis-leaf skip behavior used by the hardened PIBD segment-application paths.
- add regression coverage for txhashset directory replacement and backup cleanup, kernel PMMR probe classification and v1 fallback, and empty/populated genesis root and size validation.
- add regression coverage for stale or missing `output_pos` index entries across direct position reads, Merkle proofs, extension Merkle proofs, and output application.
- add regression coverage for resolving inputs before indexing new outputs, rejecting invalid rewind targets and altered fork headers, handling missing spent-output data, reconstructing spent indexes, validating header-height lookups, strict rewind bitmap ancestry checks, bounded kernel searches, leaf-set pruning, and stop handling during rangeproof verification.
- add regression coverage for empty-genesis validation shortcuts, non-zero kernel-offset rejection, and populated-genesis kernel-sum validation.
- add PIBD segment regressions for non-leaf output/rangeproof positions, unauthenticated output/rangeproof/kernel data, future leaf positions, and hash data supplied to the non-prunable kernel PMMR.
- add regressions proving missing rangeproof leaves fail input application and extension discard, explicit extension heads can rewind against archive headers while the DB body head is still genesis, and non-genesis validation cannot use the empty-genesis shortcut.

**src/txhashset/utxo_view.rs**
- make block validation reject duplicate output commitments within the candidate block before checking those outputs against the existing output PMMR.
- make transaction validation apply the same in-transaction duplicate output commitment rejection before input validation.
- harden input validation by rejecting duplicate input commitments and duplicate resolved output positions, comparing feature-bearing inputs with context-aware serialization.
- make input position lookup use checked 1-based to 0-based conversion, propagate output PMMR read failures, report stale `output_pos` entries that point at missing PMMR data as explicit txhashset errors.
- make output validation propagate non-`NotFound` store errors and PMMR read failures, reject mismatched index entries explicitly, classify indexed-but-missing output PMMR data as a txhashset consistency error.
- make header PMMR lookup result-bearing, reject zero positions, compute context-aware header hashes, propagate header PMMR/hash errors, derive height lookup positions with fallible PMMR index arithmetic plus checked addition.
- add unit tests coverage for zero-position header lookup rejection, duplicate block/transaction output commitments with distinct identifiers, stale output-position indexes pointing to missing PMMR data, duplicate input commitments in both input encodings.

**src/types.rs**
- add `SyncStatusUpdateThrottle` to limit high-frequency sync status/UI updates.
- add `TXHASHSET_STATE_VALIDATION_STEPS` and the serializable `TxHashsetStateValidationStage` enum with stable API names, display labels, and progress units for granular txhashset state-validation reporting.
- turn `ValidatingKernelsHistory` into a counted progress state, replace the old header-validation setup state with output-index, kernel-index, and txhashset-state validation progress states, remove obsolete wall-clock `TxHashsetDownloadStats` accounting.
- add serializable `KernelPos` storage metadata, mirroring `CommitPos` for durable kernel MMR position/height indexing.
- add a default `ChainAdapter::block_rejected` callback carrying the rejected block hash.

**tests/bitmap_accumulator.rs**
- update tests with functions signature changes (no structure/functionality changes).
- add a regression proving `init` rejects out-of-order index iterators with the expected sorted-index error.
- dd coverage that `apply` rejects invalidated indexes outside the target bitmap size while leaving the accumulator root unchanged at the default root.
- add coverage `bitmap_accumulator_init_commits_empty_bitmap_size` that empty bitmap initialization commits a non-default zero-chunk root and differentiates roots for different committed bitmap sizes.
- add coverage `bitmap_accumulator_init_commits_trailing_zero_chunks` that trailing zero chunks are committed into the accumulator root even when the visible set-bit indexes are identical.
- add rollback coverage for iterator errors during `apply`, verifying both the accumulator root and reconstructed bitmap remain unchanged.
- add coverage that an empty invalidated-index list rebuilds the accumulator from the beginning.
- add rollback coverage for iterator errors when rebuilding from an empty invalidated-index list.
- add coverage that an empty invalidated-index rebuild can clear the accumulator to zero size, restoring the default root and an empty bitmap.
- add rollback coverage for out-of-order index streams during `apply`, preserving the previous root and bitmap.
- add rollback coverage for padding failures caused by iterator errors while applying to an empty accumulator.

**tests/bitmap_segment.rs**
- update tests with functions signature changes (no structure/functionality changes).

**tests/data_file_integrity.rs**
- update tests with functions signature changes (no structure/functionality changes).

**tests/mine_nrd_kernel.rs**
- update tests with functions signature changes (no structure/functionality changes).
- add `GlobalChainConfigGuard`, serializing mutations of global chain configuration. Needed because some some code runs as multythread, that is lical config doesn't work.

**tests/nrd_validation_rules.rs**
- update tests with functions signature changes (no structure/functionality changes).

**tests/store_kernel_pos_index.rs**
- update tests with functions signature changes (no structure/functionality changes).
- and add stale-entry cleanup checks after a two-entry list collapses back to `Single`.
- and add entry-deletion checks after tail pops collapse a multi-entry list to one remaining position.

**tests/test_coinbase_maturity.rs**
- update tests with functions signature changes (no structure/functionality changes).

**tests/test_get_kernel_height.rs**
- update tests with functions signature changes (no structure/functionality changes).
- add a kernel-position index completeness regression.
- add `get_header_for_kernel_index_rejects_invalid_bounds`, covering zero indexes, reversed height bounds, indexes above the head kernel MMR size.

**tests/test_header_perf.rs**
- update tests with functions signature changes (no structure/functionality changes).

**tests/test_header_weight_validation.rs**
- update tests with functions signature changes (no structure/functionality changes).
- set `output_mmr_size` to the complete but too-large PMMR boundary `63` instead of arbitrary `1_000` (1000 doens;t wok any more because it is invalid PMMR index error).

**tests/test_pibd_validation.rs**
- update tests with functions signature changes (no structure/functionality changes).

**tests/validate_blockchain.rs**
- update tests with functions signature changes (no structure/functionality changes).

### mwc-node/api

**Summary of the changes:**
- error classification and propagations.
- apply functions signature changes from parent crates.

**Cargo.toml**
- remove imported crates, add `mwc_crates` instead.
- add thiserror (it can't be reexported)

**src/auth.rs**
- store only a zeroizing SHA-256 digest of the expected Authorization header in `BasicAuthMiddleware`, zeroize constructor input after digesting, add `from_api_secret` so callers can build auth state from the basic-auth key and zeroizing API secret without retaining the full secret header.
- add `pre_body_response` for owner/basic auth middleware so CORS preflight is answered immediately, ignored URIs bypass auth, and unauthorized requests can be rejected before body processing or downstream handler execution.
- update the owner/basic auth call path to `Request<Bytes>`, return a CORS preflight response directly for `OPTIONS`, preserve ignored-URI bypass behavior, and replace direct header/string comparison with digest-based constant-time authorization checking.
- apply the same zeroizing digest storage model to `BasicAuthURIMiddleware`.
- add target-URI `pre_body_response` handling so `OPTIONS` receives CORS headers before downstream processing, matching target URIs require auth, and non-target paths continue normally.
- update target-URI middleware calls to `Request<Bytes>`, answer `OPTIONS` directly, keep non-target requests pass-through, use the shared digest/constant-time authorization helper for protected target paths.
- add a shared CORS preflight response helper.
- add helpers for SHA-256 auth digests, constructing Basic credentials from key plus zeroizing API secret, building zeroizing Authorization header values, and comparing presented credentials by digest with `ConstantTimeEq`, reducing timing leakage and raw-secret lifetime.
- add auth middleware tests covering Basic header construction, digest equivalence, CORS preflight behavior without downstream calls, pre-body unauthorized rejection, and target-URI preflight behavior.

**src/client.rs**
- update with functions signature changes (no functionality changes). Document some aspects, so auditor understand the workflow and justification. 

**src/foreign.rs**
- update with functions signature changes (no functionality changes).
- remove the public stempool size wrapper.
- remove the libp2p peer/message foreign API helpers and their imports.

**src/foreign_rpc.rs**
- update with functions signature changes (no functionality changes), update doc tests.
- replace per-request `sysinfo` allocation, CPU-sampling sleep, and direct RAM/swap division with cached process-status metrics from `process_status_cache`, improving responsiveness and avoiding local denominator handling in the RPC method.
- fix the inert commented-out doctest helper macro body with a call to the shared `json_rpc::doctest_assert_json_rpc_response`, including the foreign RPC method parameter map updated for removed stempool/libp2p methods and the narrowed `get_outputs` arguments.

**src/handlers.rs**
- update with functions signature changes (no functionality changes).
- add `NodeApiThreads` so API startup returns both the HTTP server thread and the monitor thread, allowing callers to observe monitor shutdown failures instead of losing that state.
- add a regression test proving `json_response_pretty` escapes serializer error text containing quotes, newlines, and backslashes into parseable JSON instead of returning malformed error output.

**src/handlers/blocks_api.rs**
- update with functions signature changes (no functionality changes).
- add `BlockQueryOptions`, canonical decimal height parsing, bounded hash/height error formatting, and shared query parsing through `QueryParams`, rejecting unsupported parameters and invalid decoded query data while preserving `compact`, `no_merkle_proof`, and `include_proof` behavior.
- update `HeaderHandler` to preserve internal and chain-read errors from the output-commit probe instead of treating every failure as a miss, require canonical heights, propagate errors.
- add regression tests for unavailable block error classification, overlong hash rejection, bounded invalid-input diagnostics, rejection of noncanonical numeric heights before chain access, canonical height parsing limits, supported/invalid query parsing, preservation of internal parse errors, header commitment-probe error propagation, and missing-output probe behavior.

**src/handlers/chain_api.rs**
- update with functions signature changes (no functionality changes).
- add `fast` query parsing.
- add `StopState` to `ChainCompactHandler`, call `chain.compact(stop_state)` through a shared helper, and move compaction requests to `Request<Bytes>` so compaction can honor node shutdown state.
- update `outputs_block_batch` to validate commitment query parameters, reject reversed or overflowing height ranges, cap height scans at 100 blocks, and return lookup errors instead of silently skipping failed heights.
- add `push_output_id_param` to cap `/byids` commitment counts, normalize optional `0x` prefixes for validation, and reject non-Pedersen-length commitment ids with bounded error text before lookup.
- add `push_output_commitment_param` for `/byheight` filters, enforcing the same count and length limits while parsing commitments through the serde/secp helper and returning a single bounded bad-request message for parse failures.
- add `parse_kernel_excess`, which trims input, accepts one optional `0x` prefix, enforces exact Pedersen commitment length, parses through `secp_ser`, and avoids returning raw excess values in parse errors.
- add regression tests for validation mode parsing, bounded kernel excess errors, invalid commitment parsing, missing kernel `NotFound` mapping, output commitment limits, bounded `/byids` errors, `/byheight` range caps, missing-height propagation, and invalid `/byheight` commitment rejection.

**src/handlers/peers_api.rs**
- update with functions signature changes (no functionality changes).
- add shared `is_peer_not_found_error` and `parse_peer_addr` helpers, distinguishing p2p/store missing-peer errors from other failures.
- harden `get_peers` error mapping so a specific peer miss returns `NotFound`, other peer lookup failures remain internal errors.
- add regression tests for valid canonical Onion v3 parsing and rejection of uppercase, overlong, and invalid Onion peer address inputs.

**src/handlers/pool_api.rs**
- update with functions signature changes (no functionality changes).
- introduce `pool_error_to_api_error` that classify request errors.
- add `parse_fluff_param`, accepting absent/presence, `true`/`1`, and `false`/`0` forms while rejecting invalid `fluff` values as request errors.
- add regression tests for default, presence, boolean, invalid, and duplicate `fluff` parameter handling, plus a check that internal pool errors return the generic API message without leaking backend detail.

**src/handlers/server_api.rs**
- update with functions signature changes (no functionality changes).
- make `sync_status_to_api` support all active sync phases including `initial`, `header_hash_sync`, kernel-history validation, txhashset kernel-position validation, PIBD segment download, output/kernel position index builds.
- add regression coverage for active sync-status API mappings, verifying the returned status strings and progress JSON for initial, header-hash sync, PIBD, and txhashset index-build phases.

**src/handlers/transactions_api.rs**
- update with functions signature changes (no functionality changes).
- map PMMR and coinbase-header reads through `Error::chain_read_error`, fetch coinbase headers only when needed.
- add `validate_last_txhashset_insertions`, returning a request error when `n` exceeds the 10,000 cap so oversized last-entry scans are rejected consistently.
- add regression tests for overlong commitment rejection with bounded error text, oversized `n` rejection, and validation before chain access for last-kernel requests.

**src/handlers/utils.rs**
- update with functions signature changes (no functionality changes).
- add `parse_commitment`, which trims API input, accepts one optional `0x` prefix, enforces exact Pedersen commitment hex length before parsing.
- validate that the output loaded by PMMR position matches the requested commitment.
- add regression tests for normalized commitment input, invalid commitment bytes, overlong hex, invalid hex, and double-prefixed values, verifying these paths return bounded argument errors rather than leaking raw request data or panicking.

**src/handlers/version_api.rs**
- update with functions signature changes (no functionality changes).

**src/json_rpc.rs**
- change `build_request` to accept a caller-supplied numeric request id and store it in the JSON-RPC request instead of always using `1`, preventing duplicate ids when callers need stable request/response matching.
- add a rustdoc helper, doctest handler fixture, and `DoctestJsonRpcError` type that parse doctest JSON, validate method lookup and argument shape, compare actual and expected responses, and return readable errors instead of relying on panic-only helper logic.
- validate the response JSON-RPC version before result extraction, reject malformed result payloads that are missing an object `Ok` field instead of treating missing values as `null`, surface wrapped `Err` values as method errors.
- add `format_result_error` so application-level `Err` wrappers are converted into concise human-readable method error messages for strings, tagged objects, single-item arrays, and other JSON values.
- replace manual `From`, `Display`, and `Error` implementations for `Error` with `thiserror`, add explicit `Method` and `MalformedResponse` variants.
- add regression tests covering accepted and rejected JSON-RPC versions, `into_result` version checks, wrapped method errors, and rejection of missing, null, non-object, or object-without-`Ok` result payloads.

**src/owner.rs**
- add a `StopState`, and require/pass it through `Owner::new`, enabling owner actions to honor node shutdown state.
- update with functions signature changes (no functionality changes).

**src/owner_rpc.rs**
- update with functions signature changes (no functionality changes).
- replace the commented doctest macro body with a shared JSON-RPC doctest assertion helper and owner method parameter map, making owner RPC documentation examples executable validation coverage.

**src/rest.rs**
- harden TLS private-key loading by validating key-file metadata before reading, rejecting non-regular files, enforcing owner-only permissions on Unix, bounding the read size, loading PEM data into a `Zeroizing` buffer, detecting file-size changes during read, and wiping the extra probe byte before parsing.
- parse the private key into a rustls/ring signing key, immediately zeroize the plaintext DER key, validate certificate/key consistency where rustls can determine it, and build the server config with the ring provider and a single-cert resolver.
- add startup-reporting helpers that send bind/runtime startup results back to the caller, log dropped startup receivers and startup panics, clear the shutdown sender on startup failure.
- introduce a shared `hyper-util` REST connection builder with HTTP/1 header-read timeout and HTTP/2 keepalive timeout settings.
- add bounded graceful-shutdown draining for per-connection tasks, timing out shutdown and task joins after the REST IO timeout, aborting remaining tasks when necessary.
- centralize request serving so routers can return pre-body responses before body collection, successful requests are forwarded to the router as `Request<Bytes>`.
- replace the non-TLS `Server::bind`/`make_service_fn` path with explicit `TcpListener` binding, startup-result reporting, a 256-connection semaphore, per-connection `JoinSet` tasks.
- update TLS startup to build the zeroized rustls config before spawning, bind the listener with synchronous startup reporting, enforce the same 256-connection limit and per-connection task tracking as HTTP, add TLS handshake timeouts with peer-aware logging, serve accepted TLS streams through the shared request path, and gracefully drain HTTPS connection tasks on shutdown.
- change API shutdown to consume `shutdown_sender` with `take()` instead of replacing it with a dummy sender, return `false` when signaling fails or no server is running.
- add regression tests for limited-body overflow handling, over-limit pre-body `Content-Length` rejection, invalid/overflowing/duplicate `Content-Length` handling, and `chain_read_error` mapping of invalid header heights to `NotFound`.

**src/router.rs**
- update with functions signature changes (no functionality changes).
- store route node path segments as strings instead of hashed keys, removing hash-collision risk from route registration and lookup.
- check child capacity before allocating nodes, propagate route insertion failures as `RouterError`, and ensure `add_route` registers only exact segments so wildcard routes are not reused as concrete route nodes.
- add router-level `pre_body_response` dispatch so matching middleware can return early responses before request bodies are read.
- add regression tests proving child-limit failures do not add leaked nodes and relative paths are rejected during route registration.
- add regression tests for rejecting relative lookup paths and for keeping wildcard route nodes from swallowing later exact-route registration.

**src/stratum.rs**
- harden `clean_ip` by parsing and canonicalizing the supplied IP address before touching the pool, passing the canonical address into cleanup.
- add a shared test helper that builds a `Stratum` wrapper around a fresh `StratumIpPool`.
- add coverage that invalid IP input is rejected as an argument error instead of being forwarded to the pool.
- add coverage that cleanup of an untracked canonical IP reports `NotFound`.
- add coverage that active worker IPs cannot be cleaned and that existing worker/share state remains intact after rejection.
- add coverage that an inactive tracked IP can be cleaned and then reports `NotFound` on a second cleanup attempt.

**src/types.rs**
- update with functions signature changes (no functionality changes).
- add `OutputPrintable::deserialize_with_context`, make ordinary serde deserialization fail with a clear context-required error.
- require `include_merkle_proof` flag for compact-block rendering.
- update tests for context-aware output deserialization, add coverage for invalid Merkle proofs and invalid commitments, verify short range proofs still parse while oversized proofs are rejected, and add a coinbase Merkle-proof regression that fetches the missing header through a temporary chain.

**src/web.rs**
- broaden `result_to_response` handling for internal, router, p2p, secp, IO, and chain errors.
- replace infallible `From` query parsing with fallible `from_query` and `from_query_str` constructors that manually split and decode query components, allowing malformed query strings to become request errors.
- add strict query-component decoding helpers that translate `+`, validate percent escapes, parse hex digits explicitly, and reject percent-decoded data that is not valid UTF-8.
- add regression tests for unique and duplicate query parameters, valid and invalid query decoding, JSON response headers and `nosniff`, text response header separation, hidden serialization/internal error bodies.

**tests/rest.rs**
- update with functions signature changes (no functionality changes).
- add an ephemeral localhost address helper for non-Windows tests, reducing fixed-port conflicts in new server restart/bind-failure checks.
- add a restart-after-stop regression test that starts the API server, stops it, joins the server thread, and verifies the same `ApiServer` instance can start and stop again.

### mwc-node/doc

**doc/api/node_api_v1.md**
- update documentation for `GET /v1/chain/validate` and `POST /v1/pool/push` (params didn't match the real implementation)

**doc/mwc_lib_specification.md**
- address made API changes at `mwc_node_lib`

### mwc-node/p2p

**Summary of the changes:**
- Error propagations.
- Apply functions signature changes from parent crates.
- Upgrade protocol version to v5. Add onion address ownership proof for Tor peers.
- Stop supporting external Tor config. 
- Switch to monotonic last-add timing.

**Cargo.toml**
- remove imported crates, add `mwc_crates` instead.
- add thiserror (it can't be reexported)

**fuzz/fuzz_targets/fuzz_global.rs**
- add a shared `init()` helper that selects Mainnet and enables NRD for fuzz runs.

**fuzz/fuzz_targets/read_ban_reason.rs**
- initialize fuzz globals on every run, stop cloning the input slice, and replace loose `ser::deserialize` with `ser::deserialize_strict` using `ProtocolVersion::local_db()` and context id `0`, so ban-reason fuzzing exercises the stricter production deserialization path while intentionally ignoring decode errors.

**fuzz/fuzz_targets/read_get_peer_addrs.rs**
- initialize fuzz globals on every run, stop cloning the input slice, document that decode errors are intentionally ignored during fuzzing, and replace loose `ser::deserialize` with `ser::deserialize_strict` using `ProtocolVersion::local_db()` and context id `0`, so get-peer-addrs fuzzing exercises the stricter production deserialization path.

**fuzz/fuzz_targets/read_hand.rs**
- initialize fuzz globals on every run, stop cloning the input slice, document that decode errors are intentionally ignored during fuzzing, and replace loose `ser::deserialize` with `ser::deserialize_strict` using `ProtocolVersion::local_db()` and context id `0`, so hand-message fuzzing exercises the stricter production deserialization path.

**fuzz/fuzz_targets/read_headers.rs**
- add `FuzzHeaders` and its `Readable` implementation, reading the header count.
- initialize fuzz globals on every run, stop cloning the input slice, document that decode errors are intentionally ignored during fuzzing, and replace loose `ser::deserialize` of `Headers` with strict deserialization of `FuzzHeaders` using `ProtocolVersion::local_db()` and context id `0`, so header fuzzing exercises deterministic global state and the stricter production deserialization path.

**fuzz/fuzz_targets/read_locator.rs**
- initialize fuzz globals on every run, stop cloning the input slice, document that decode errors are intentionally ignored during fuzzing, and replace loose `ser::deserialize` with `ser::deserialize_strict` using `ProtocolVersion::local_db()` and context id `0`, so locator fuzzing exercises the stricter production deserialization path.

**fuzz/fuzz_targets/read_msg_header.rs**
- initialize fuzz globals on every run, stop cloning the input slice, document that decode errors are intentionally ignored during fuzzing, and replace loose `ser::deserialize` with `ser::deserialize_strict` using `ProtocolVersion::local_db()` and context id `0`, so message-header fuzzing follows the stricter production deserialization path.

**fuzz/fuzz_targets/read_peer_addr.rs**
- initialize fuzz globals on every run, stop cloning the input slice, document that decode errors are intentionally ignored during fuzzing, and replace loose `ser::deserialize` with `ser::deserialize_strict` using `ProtocolVersion::local_db()` and context id `0`, so peer-address fuzzing exercises the stricter production deserialization path.

**fuzz/fuzz_targets/read_peer_addrs.rs**
- initialize fuzz globals on every run, stop cloning the input slice, document that decode errors are intentionally ignored during fuzzing, and replace loose `ser::deserialize` with `ser::deserialize_strict` using `ProtocolVersion::local_db()` and context id `0`, so peer-address-list fuzzing exercises the stricter production deserialization path.

**fuzz/fuzz_targets/read_peer_error.rs**
- initialize fuzz globals on every run, stop cloning the input slice, document that decode errors are intentionally ignored during fuzzing, and replace loose `ser::deserialize` with `ser::deserialize_strict` using `ProtocolVersion::local_db()` and context id `0`, so peer-error fuzzing exercises the stricter production deserialization path.

**fuzz/fuzz_targets/read_ping.rs**
- initialize fuzz globals on every run, stop cloning the input slice, document that decode errors are intentionally ignored during fuzzing, and replace loose `ser::deserialize` with `ser::deserialize_strict` using `ProtocolVersion::local_db()` and context id `0`, so ping-message fuzzing exercises the stricter production deserialization path.

**fuzz/fuzz_targets/read_pong.rs**
- initialize fuzz globals on every run, stop cloning the input slice, document that decode errors are intentionally ignored during fuzzing, and replace loose `ser::deserialize` with `ser::deserialize_strict` using `ProtocolVersion::local_db()` and context id `0`, so pong-message fuzzing exercises the stricter production deserialization path.

**fuzz/fuzz_targets/read_shake.rs**
- initialize fuzz globals on every run, stop cloning the input slice, document that decode errors are intentionally ignored during fuzzing, and replace loose `ser::deserialize` with `ser::deserialize_strict` using `ProtocolVersion::local_db()` and context id `0`, so shake-message fuzzing exercises the stricter production deserialization path.

**fuzz/fuzz_targets/read_tx_hashset_archive.rs**
- initialize fuzz globals on every run, stop cloning the input slice, document that decode errors are intentionally ignored during fuzzing, and replace loose `ser::deserialize` with `ser::deserialize_strict` using `ProtocolVersion::local_db()` and context id `0`, so txhashset-archive fuzzing exercises the stricter production deserialization path.

**fuzz/fuzz_targets/read_tx_hashset_request.rs**
- initialize fuzz globals on every run, stop cloning the input slice, document that decode errors are intentionally ignored during fuzzing, and replace loose `ser::deserialize` with `ser::deserialize_strict` using `ProtocolVersion::local_db()` and context id `0`, so txhashset-request fuzzing exercises the stricter production deserialization path.

**src/codec.rs**
- add `body_deadline` to `Codec` and initialize it empty, allowing body reads to share one deadline across multiple low-level reads rather than resetting the body timeout after every partial read.
- replace the old `read_exact` path, which pre-extended the buffer with zeroes and reset the timeout per item, with explicit timeout selection, a fixed body deadline, partial-byte preservation on EOF/error.
- update `read_inner()` to use the fallible length/read helpers, reject `Headers` messages with more than `MAX_BLOCK_HEADERS` entries or with zero entries, use checked subtraction for the declared headers body length, and clear the body deadline after a complete non-header message.
- add codec test helpers that build an in-memory TCP stream, initialize deterministic test globals, serialize ping bodies, construct synthetic headers messages, and generate truncated message-header input.
- add tests proving exact message bodies still decode successfully and bodies with trailing bytes now fail with corrupted-data errors.
- add tests that reject headers messages with missing declared header bytes, a count above `MAX_BLOCK_HEADERS`, and a zero header count with a non-empty body.
- add a regression test that truncated header reads return `UnexpectedEof` while preserving the partial bytes in the codec buffer and reporting the actual bytes read.

**src/conn.rs**
- update with functions signature changes (no functionality changes).
- add `recv_send_batch()` to drain outbound messages into a bounded local batch capped at `SEND_CHANNEL_CAP`, preventing an unbounded write batch after a busy channel.
- add `StopOnDrop`, a drop guard that marks the shared stop flag during normal exit or panic unwind so the peer's companion thread is signaled even when one side exits unexpectedly.
- add a test-only `disconnected_test_handles()` helper that returns a disconnected send handle and inert stop handle for connection error-path coverage.
- add `stop_reader_after_writer_spawn_error()` to set the stop flag and join the already-started reader thread when writer thread creation fails, while preserving the original writer spawn error as the returned setup failure.
- add regression tests for full send-queue errors, bounded send-batch draining, stop-on-drop during panic unwind, `StopHandle::wait()` returning peer thread panics or thread errors, and reader cleanup after writer spawn failure.

**src/handshake.rs**
- add `read_hand_message()` so inbound handshake reads reject unknown or non-`Hand` message types without decoding an unexpected body.
- add an IP receiver-address learning cache and zeroizing onion expanded-key storage to `Handshake`, extend `Handshake::new()` to accept the parsed key, initialize the new cache, and document the accepted duplicated-key lifetime risk from retaining the full `P2PConfig`.
- add inbound receiver-address validation and observation helpers; Tor handshakes must target the configured canonical onion address, IP handshakes must target a learned receiver address once enough recent peers agree.
- move PeerWithSelf address caching behind a dedicated helper and refuse to cache unauthenticated onion self-addresses unless the hand message is protocol v5+ and carries onion proof fields.
- add onion identity proof transcript, signing, and verification logic; outbound onion handshakes sign the sender/receiver/nonce/timestamp/genesis/version transcript with the configured onion expanded key, inbound v5+ onion handshakes require a valid Ed25519 signature and timestamp, Tor receivers revalidate the target onion address, legacy onion handshakes are rejected for peers already known as v5 or newer.
- update outbound handshakes to use fallible nonce generation, attach onion proof signatures/timestamps to `Hand`, map malformed `Shake` serialization to `BadHandshake`, classify outbound Tor direction from the peer address instead of from local onion configuration.
- resolve the advertised sender address fallibly from the transport before policy checks, verify onion identity proofs, check denied and banned state before replying, validate the receiver address, delay PeerWithSelf caching until after authentication/policy validation.
- add helpers to enforce the onion proof timestamp skew window with saturating arithmetic and to select the learned IP receiver address from the strongest recent sample majority.
- harden advertised peer-address resolution by returning `Result`, binding IP peers to the accepted transport IP plus advertised port, rejecting invalid addresses.
- add handshake test helpers for deterministic onion address/key creation, configurable test handshakes, synthetic `Hand` messages with onion proof fields, and IP receiver-address sample setup.
- add regression tests covering strict `Hand` message type handling and IP sender-address resolution for transport IP binding, IPv4-mapped IPv6 normalization, IPv4-compatible IPv6 preservation, port-zero rejection, IPv6 flowinfo/scope rejection, missing transport address errors, and non-IP transport rejection.
- add regression tests for PeerWithSelf cache behavior and IP receiver-address learning, including IP self-address caching, unauthenticated onion self-address rejection, inbound receiver observation, recent-majority selection, strongest-majority choice, duplicate source suppression, same-public-IP duplicate suppression, exact port matching, and receiver-address relearning.
- add tests proving Tor receiver validation accepts only the configured canonical onion address and rejects wrong, IP, or unconfigured receiver targets.
- add onion proof tests for valid signatures, tampered signatures, receiver-onion binding, onion-to-IP receiver proofs, stale/future/missing timestamps, and rejection of legacy onion handshakes for peers already stored as protocol v5 or newer.

**src/listen.rs**
- replace the separate internal/external Tor branches with a single onion-service startup path for any enabled Tor configuration, removing the external-Tor support.
- add explicit listener health tracking around TCP bind.
- mark the listener healthy after a successful accept and replace the inline IPv4-mapped IPv6 conversion with `normalize_transport_socket_addr()` before passing the peer address to the new-peer callback.
- report listener shutdown through the same status helper, avoiding duplicate `false` service-status notifications when the listener was already marked down.
- add `normalize_transport_socket_addr()`, converting only IPv4-mapped IPv6 transport addresses to IPv4 while preserving native IPv6 and IPv4-compatible IPv6 addresses.
- add `set_listener_service_status()` to maintain local listener health state and suppress repeated identical service-status callbacks, reducing noisy UX updates.
- add `handle_listener_accept_error()` to classify accept failures as `Error::TorProcess`, mark listener status down.
- add regression tests for accept-error shutdown without a failure callback, callback-controlled recovery after a temporary accept error, and transport-address normalization that only rewrites IPv4-mapped IPv6 addresses.

**src/msg.rs**
- mark `TorAddress` as an unused reserved wire type kept for backward compatibility, expand the maximum `Hand` message size to include the optional onion proof signature and timestamp.
- remove per-message file attachments.
- decode message headers with strict deserialization, keep body decoding permissive for forward-compatible trailing data from newer peers.
- remove the fixed 150 ms send delay and attachment streaming path, batch only message headers and bodies with context-aware header serialization, account for sent bytes once.
- change `MsgHeaderWrapper` and `MsgHeader` message lengths from `u64` to `usize`, keep the wire format as `u64`.
- extend `Hand` with optional onion identity proof signature and timestamp fields, require outbound signatures to be paired with timestamps, truncate unknown future capability bits, reject non-printable user-agent bytes, add EOF-aware readers that distinguish absent legacy onion proof data from partial signature/timestamp data.
- harden `Shake` serialization by calculating the effective message length against the negotiated protocol version and configured maximum instead of only checking a large user-agent cap, and make read-side capability and user-agent validation match `Hand`.
- reject attempts to serialize more than `MAX_BLOCK_HEADERS` (512) headers before writing the count, avoiding oversized outbound header lists and narrowing integer-cast assumptions.
- replace verbose transaction, stem transaction, block, and compact-block debug output with bounded summaries containing counts, heights, and best-effort hashes, reducing log volume and avoiding exposure of full transaction/block contents while preserving `Debug` as a wrapper around `Display`.
- keep `TorAddress` readable for backward compatibility only, limit its constructor and writer to tests, and validate/canonicalize decoded addresses as Onion v3 strings before accepting them.
- add test helpers for deterministic `Hand`/`Shake` construction and explicit injection of unknown future capability bits.
- add regression tests for truncated ban-reason reads and strict `TorAddress` decoding of valid, invalid, and noncanonical Onion v3 addresses.
- add handshake tests covering absent, full, and legacy onion proofs, unknown capability-bit downgrading, printable-ASCII user-agent enforcement, and rejection of partial onion signature or timestamp data through both slice and buffered readers.
- add `Shake` and `Headers` regression tests for user-agent character validation, unknown capability-bit downgrading, effective serialized-size limits, and outbound header-count limits.

**src/network_status.rs**
- disable first-call live filtering of probe hosts; all configured candidates are now retained without calling the TCP probe. That TCP probes can leak the user's real IP address, so the old DNS/connect/HEAD request check is no longer compiled or used.

**src/peer.rs**
- add the in-memory `Defunct` peer state, and replace separate send/stop handle mutexes with a `PeerConnection` state.
- split peer construction from socket listener startup by returning `(Peer, TcpDataStream)` from accept/connect, passing the network adapter into inbound handshakes, refusing outbound handshakes to already banned peers.
- add `start_listening()` to transition a peer from `Starting` to `Active`, reject duplicate listener starts, roll back the connection state on `conn::listen` failure, honor stop requests made during startup, notify waiters once startup finishes.
- make `send()` require an active unstopped connection, mark the peer defunct plus stop it when outbound queueing fails instead of leaving a failing connection active.
- record a restorable request entry before sending `GetBlock`, and restore the previous request state if the send fails.
- update `stop()` and `wait()` for the new `Starting`/`Active` connection lifecycle, waiting with a timeout for startup completion.
- update with functions signature changes (no functionality changes).
- add peer test helpers for constructing connected/disconnected peers, custom user-agent and fee scenarios, disconnected connection handles, and a deterministic valid aggregate signature for broadcast transaction tests.
- add regression tests for connected-peer rollback on store-save or banned-peer failures, broadcast local-error versus peer-send-failure cleanup, replacement-peer preservation during cleanup, ping-failure cleanup, stop persistence failures, and preserving defunct peer state on shutdown.
- add tests for preferred outbound fee matching and peer-address gossip filtering, including rejection of unroutable or port-zero candidates, allowing exact preferred private candidates, and rejecting non-exact preferred-address matches.
- add tests that ping and clean-peers report persistence failures while removing affected peers, and that header, compact-block, and transaction broadcasts return errors when all peer sends fail.
- add request-tracking tests covering restoration of previous block-request options, removal of failed new requests, protection against clobbering newer request entries, and atomic request-id wraparound.
- add connection-lifecycle tests proving stop requests are recorded while startup is pending, `wait()` blocks until a starting connection becomes active, and `wait()` times out if startup never completes.

**src/peers.rs**
- update with functions signature changes (no functionality changes).
- add `BroadcastSummary`, `PeerCheckSummary`, and `PeerCleanupSummary`, including first-persistence-error capture helpers, so callers can distinguish successful work, peer failures, and peer-store persistence failures instead of relying only on logs.
- update `Peers` state to use monotonic last-add timing, store a secret-stripped `P2PConfig`, add the advertised-peer source-limit map.
- harden connected-peer admission by storing the peer protocol version, rejecting duplicate live addresses under the live-map lock, rolling back the live map when peer-store save fails or returns banned, resetting the outbound-add timestamp only after successful admission.
- rework ban/unban handling so bans are persisted through `add_banned`, live peers are removed directly even if excluded filters would hide them, ban-reason send failures are best-effort while the peer is still stopped, unban uses the loaded peer state with an explicit comment about the accepted local-policy race.
- change broadcast flow to return summaries/results, classify send/connection/timeout errors as peer failures with identity-checked cleanup and best-effort state persistence, propagate non-peer broadcast errors.
- make peer liveness checks return `PeerCheckSummary`, count ping failures, preserve first persistence failure, and remove failed ping peers only when the same connection is still live.
- make peer-store helper APIs propagate iterator/item/find/update/save errors instead of defaulting to empty results or logs, centralize removed-peer state persistence so defunct peers stay defunct.
- make `clean_peers` return `PeerCleanupSummary`, preserve states for banned/defunct/abusive/stuck peers, record persistence failures, avoid evicting peers on local chain-read failures, use saturating outbound failure counts, rank excess outbound cleanup with context-aware fee policy.
- make `stop()` return `Result`, persist removed-peer state before stopping, wait for each peer, downgrade expected disconnect close errors to debug logs, return the first real persistence or wait error.
- replace direct advertised-peer map exposure with reset, ranked-list, checked-marking, pruning, source-limit pruning, candidate validation, deduplication, exact preferred-peer exception handling, and per-source hourly acceptance caps for safer peer-discovery UX and spam resistance.
- add regression tests proving bans persist even when the peer-store row is missing, and advertised-peer source-limit pruning keeps the newest retained source while enforcing the configured cap.

**src/protocol.rs**
- update with functions signature changes (no functionality changes).
- keep `TorAddress` only as a backward-compatible skipped message, removing the old peer-store rewrite and ban check based on a peer-advertised onion address.
- disable servicing `TxHashSetRequest` as an obsolete DDoS-prone full-chain archive path, ban peers that request it.
- pre-check the local archive header before header-hash sync, return `HasAnotherArchiveHeader` when the requested archive height is stale.
- pre-check PIBD sync requests against the current archive hash and height, return the current archive header on mismatch.

**src/serv.rs**
- update with functions signature changes (no functionality changes).
- compute inbound capacity from explicit/default peer limits, include in-flight handshakes in the admission decision, refuse excess streams immediately, run accepted inbound handshakes on named worker threads so the listener path is not blocked by slow handshakes.
- replace raw Tor key file and hex parsing with owner-only file reads/writes, strict 64-byte length checks, explicit Arti expanded-key validation, `Zeroizing` buffers, secret string cleanup, secure `SysRng` key generation, race-safe handling when another process creates `node_tor_id` first.
- reject outbound connections to persisted-banned peers before dialing and propagate ban-store lookup errors; recalculate the soft connection limit with defaulted config values.
- route all Tor-enabled outbound connections through Arti with cancellation handling, remove the external SOCKS5 branch.
- add `add_connected_peer` to centralize connected-peer admission, start the peer listener after store admission, roll back and stop the peer on store/listener failures.
- move inbound accept error handling into helpers, distinguish bad handshakes from ordinary shutdown closes, persist BadHandshake bans best-effort, and warn when ban persistence fails.
- add shutdown regression tests proving Tor servers release their Arti cancellation context while non-Tor servers leave it intact.

**src/store.rs**
- update with functions signature changes (no functionality changes).
- harden peer-row reading by defaulting `last_connected` only for clean legacy EOF, adding legacy protocol-version fallback to `ProtocolVersion(1)`, rejecting other partial reads, validating user agents.
- make `save_peer` return `Result`, merge with existing rows before saving, preserve existing banned rows from non-banned overwrites, retain the maximum known protocol version, and prune the appropriate peer class after single or batch saves.
- add idempotent deletion helpers and corrupt-row cleanup that re-checks rows after iteration before deleting, so stale corrupt-key lists cannot remove a row that was rewritten validly.
- change `peers_iter` to strict deserialization, return `Result` items, collect corrupt keys while the read iterator is active.
- add bounded peer-pruning helpers for banned and non-banned rows, with eviction keys that remove unverified never-connected peers, defunct peers, and older entries before more useful peers while evicting the oldest bans first.
- add `merge_existing_peer_for_save`, centralizing banned-row preservation and protocol-version retention for both single and batch save paths.
- add peer-store regression tests covering configured prune limits, banned and non-banned eviction behavior, preservation of banned state during stop/defunct updates, corrupt-row cleanup without deleting rewritten valid rows, and deletion races where a selected peer is already gone.

**src/tor/arti.rs**
- update with functions signature changes (no functionality changes).
- add a process-wide Arti object-id counter, and deterministic onion-address derivation helpers that operate on `Zeroizing<[u8; 64]>` key material.
- rework context cancellation registration to cancel replaced tokens.
- make `is_arti_started()` depend on a live monitor that has not been globally shut down, make health checks require both a running monitor and a present Arti client at the requested generation.
- add bounded Arti runtime shutdown helpers, introduce unique active-object id allocation, make active-object registration/unregistration return errors for duplicate registrations or missing removals.
- serialize `start_arti()` with the start/stop lock, fail fast on global shutdown or a previous monitor panic.
- make `stop_arti()` synchronous and fallible.
- make `restart_arti()` accept saved context ids, retry replacement startup without forcing Arti data cleanup, recreate cancellation tokens only after a new client is published.
- make Tor bootstrap reject bootstrap when already inside a Tokio runtime, abort and await the bootstrap task on interruption or stalled progress.
- stop logging Tor circuit path internals during probe success to avoid exposing private Tor routing data.
- add `canonical_onion_v3()` and make onion validation require a canonical ASCII v3 `.onion` address instead of accepting any parsable representation.
- update the Arti integration test to use shared crate imports, `SysRng`, the current Arti Ed25519 expanded-key API, and explicit zeroization of expanded-key bytes after starting the onion service.
- extend onion validation coverage for uppercase, malformed, suffixless, and non-ASCII inputs, and add regression tests for expanded-key parsing/address derivation, zero-scalar rejection, extreme and malformed creation timestamps, stable bridge hashing, and active-object duplicate/missing error handling.

**src/tor/arti_tracked.rs**
- update with functions signature changes (no functionality changes).
- add `DataStream`-specific connection and split helpers, including a conservative disconnected fallback when stream control is unavailable and separately tracked reader/writer handles.
- implement `AsyncRead` and `AsyncWrite` for tracked streams.

**src/tor/onion_service.rs**
- make `start_onion_service` borrow zeroizing expanded-key material, remove the blocking `wait_until_started` call, report the onion address immediately while reachability is monitored in the background.
- rework the onion-service monitor thread to catch panics, send monitor failures back to the listener loop, propagate Arti registration and traffic-readiness errors, treat only fully reachable service states as healthy, restart Arti after broken or stalled service states, surface thread-spawn failures instead of running without a monitor.
- split `TorRestarting` from `TorNotInitialized` startup handling, retry restarting Tor with a short delay, report uninitialized-Tor status through callbacks, return callback-requested startup failures.

**src/tor/tcp_data_stream.rs**
- update with functions signature changes (no functionality changes).
- replace zero-length `read_exact` liveness probing with TCP `poll_peek` and Tor restart/connection-state checks, avoiding data consumption and reducing expected disconnect log noise.
- add regression tests covering preserved inner read error kinds and Arti async-block error mapping for restarting, uninitialized, and generic internal failures.

**src/types.rs**
- update with functions signature changes (no functionality changes).
- extend `Error` with secp, bad-handshake, peer-thread-panic, Tor-IP-address, and data-overflow variants; remove the obsolete libp2p error path.
- reject IPv6 socket addresses with nonzero flowinfo or scope id before serialization, require onion addresses to pass canonical Onion v3 validation instead of accepting any string under a length cap.
- add IPv4 and IPv6 gossip rejection helpers covering unspecified, loopback, private/local, multicast, broadcast, carrier-grade NAT, documentation, benchmarking, reserved, 6to4, mapped, and non-global-unicast addresses before they can enter peer discovery.
- make `PeerAddr::from_str` fallible, explicitly accept only valid socket addresses, resolvable DNS names, or valid Onion v3 addresses.
- canonicalize onion addresses in `tor_address()` before returning the Tor identity string and reuse the expanded loopback helper in `is_loopback()`.
- add `gossip_rejection_reason()`, `is_valid_gossip_candidate()`, and onion-host detection helpers so untrusted peer gossip can be rejected with explainable reasons.
- from `TorConfig` remove external Tor/SOCKS/onion-address configuration fields and helper methods, and make Arti startup depend only on the effective Tor-enabled setting.
- bind `P2PConfig` serde to the shared crate, zeroize the configured onion expanded key on drop, add `clone_without_secrets()` for sharing sanitized config copies.
- add regression tests for outbound failure classification, IPv6 flow/scope serialization rejection, IPv4/IPv6 gossip filtering, last-seen clamping, advertised-peer rank overflow/zero handling, secret-stripped config cloning, and stuck-detector updates only on new maximum difficulty.

**tests/peer_addr.rs**
- add an IPv6 serialization regression test proving strict `PeerAddr` decoding preserves `[::1]:3414` as `SocketAddr::V6` with the expected port instead of coercing it to another address form.
- add loopback peer-key coverage for IPv4, bracketed IPv6-with-port, and an IPv6 address whose literal text contains `3414`, ensuring loopback keys stay unambiguous.
- add IPv4-mapped IPv6 loopback coverage, confirming mapped localhost addresses are treated as loopback, mapped public addresses are not, loopback keys include the full socket address, and different loopback ports remain distinct hashmap keys.
- add strict deserialization rejection tests for unknown peer-address discriminator tags and invalid onion UTF-8, ensuring malformed wire data fails with typed serialization errors.
- add serialization rejection tests for invalid onion strings and canonical onion addresses containing NUL bytes, preventing malformed Tor peer addresses from being written.
- add `PeerAddr::from_str` onion validation coverage, accepting a canonical Onion v3 address and rejecting malformed, uppercase, and port-suffixed onion strings with clear validation errors.
- add `tor_address()` validation coverage for `.onion` hostnames and raw onion identities, while rejecting invalid onion input before exposing a Tor identity string.
- add P2P TOML seed-list deserialization coverage that accepts valid IPv4, IPv6, and Onion v3 peers and rejects invalid seed entries with an `invalid peer address` error instead of silently accepting ambiguous configuration.

**tests/peer_handshake.rs**
- update with functions signature changes (no functionality changes).
- add `write_hand_message`, a raw helper that serializes a `Hand` message header and body with the local protocol version, allowing tests to inject a controlled malformed inbound handshake over a plain TCP stream.
- add `peer_connect_rejects_banned_outbound_peer`, covering the outbound peer path where a peer already marked banned is rejected by `Peer::connect` and remains recorded as banned.
- add `server_connect_rejects_banned_peer_before_dialing`, covering the server-level outbound connect guard by banning a peer before `Server::connect`, asserting the same banned-peer error, and verifying a nonblocking listener receives no dial attempt.
- add `inbound_bad_handshake_bans_known_ip_source`, which sends a crafted bad handshake from a real TCP source while claiming an Onion sender, then waits for the server to ban the observed IP source and shuts the listener down cleanly.

**tests/peerdata_deser.rs**
- add raw `PeerData` serialization helpers for legacy rows without protocol version or last-connected data, plus a buffered-reader assertion helper that requires partial trailing fields to fail with `UnexpectedEof`.
- add strict-deserialization coverage for legacy-compatible EOF handling.
- add tests that peer protocol versions round-trip through normal serialization and that writing a `PeerData` row with a non-printable user agent is rejected with a corrupted-data error.
- add peer-store coverage proving repeated saves preserve the highest observed protocol version for a peer rather than downgrading it on later lower-version updates.
- add single-save banned-peer preservation coverage, verifying `save_peer` reports an existing ban without overwriting ban state, user-agent, last-connected time, or retained protocol version with a non-banned update.
- add batch-save atomicity coverage showing an invalid user agent rejects the whole `save_peers` operation and does not commit the valid peer that appeared earlier in the batch.
- replace the broad corrupt-row iterator cleanup test with targeted batch-save coverage that a non-banned/defunct update does not overwrite a stored banned peer, preserving the ban metadata and retained protocol version.

**tests/ser_deser.rs**
- update with functions signature changes (no functionality changes).

### mwc-node/pool

**Summary of the changes:**
- Error propagations.

**Cargo.toml**
- remove imported crates, add `mwc_crates` instead.
- add thiserror (it can't be reexported)

**fuzz/fuzz_targets/common.rs**
- update with functions signature changes (no functionality changes).
- make `genesis_block` use fallible key/proof-builder construction explicitly, build from the context-aware global genesis instead of `genesis_dev`, attach the reward, set genesis MMR roots, and mine the header with context-specific proof sizing so the fuzz chain starts from a fully rooted and mined genesis block.
- add `set_genesis_mmr_roots`, constructing output, range-proof, and kernel PMMRs with `VecBackend`, storing the corresponding roots and sizes on the genesis header, and documenting PMMR failures as fuzz fixture setup failures.
- add `replay_attack_check` fuzz test target.
- make block-addition helpers mutable, use context-aware difficulty calculation with `DifficultyCache`.

**fuzz/fuzz_targets/transaction_pool.rs**
- update with functions signature changes (no functionality changes).

**src/lib.rs**
- former lines 24-27: remove stale commented `extern crate` aliases for `blake2_rfc`, `mwc_core`, `mwc_keychain`, and `mwc_util`, leaving the pool crate root free of obsolete dependency wiring.
- lines 24-32 and former lines 28-33: remove the crate-root `#[allow(unused_imports)]`, `#[macro_use] extern crate serde_derive`, and `#[macro_use] extern crate log` declarations so macro/import ownership stays with the modules that use them and the crate root remains limited to module declarations plus public reexports.

**src/pool.rs**
- update with functions signature changes (no functionality changes).
- change pool storage from insertion-order `Vec<PoolEntry>` to `IndexMap<Hash, PoolEntry>` keyed by the representative first-kernel hash.
- add a fallible `tx_key` helper plus ordered-entry accessors, make `contains_tx` fallible and context-aware, replace full-pool kernel scans with representative-kernel hash lookups, add a fast `contains_tx_by_kernel_hash`, introduce `remove_tx` so transaction removal verifies hash-equivalent kernels before deleting keyed entries.
- expand raw transaction validation with NRD/HF3 gates, lock-height and replay-attack checks, spent-input lookup, coinbase maturity verification.
- make transaction eviction fallible.
- make block reconciliation fallible, compare block and pool conflicts through context-aware kernel and input hashes, collect keys before removing entries from the `IndexMap`.

**src/transaction_pool.rs**
- update with functions signature changes (no functionality changes).
- remove the `replay_verifier_cache` field fro `TransactionPool`.
- rewrite reorg-cache reconciliation as best-effort replay.
- make acceptability checks use fallible fee and accept-fee calculation, report low-fee transactions with the computed fee.

**src/types.rs**
- update with functions signature changes (no functionality changes).
- add unit coverage for `DandelionConfig::validate`, asserting that `0` and `100` are accepted while `101` is rejected.

**tests/block_building.rs**
- update with functions signature changes (no functionality changes).

**tests/block_max_weight.rs**
- update with functions signature changes (no functionality changes).

**tests/block_reconciliation.rs**
- update with functions signature changes (no functionality changes).

**tests/coinbase_maturity.rs**
- update with functions signature changes (no functionality changes).

**tests/common.rs**
- update with functions signature changes (no functionality changes).
- build test genesis with an explicit commit-capable secp context, context-aware proof-builder and reward creation, the global genesis source, fresh MMR roots, and mined PoW.
- add `set_genesis_mmr_roots`, constructing output, range-proof, and kernel PMMRs with the genesis context id and writing the corresponding roots and sizes onto the header so non-empty test genesis blocks are internally consistent.

**tests/nrd_kernel_relative_height.rs**
- update with functions signature changes (no functionality changes).

**tests/nrd_kernels_disabled.rs**
- update with functions signature changes (no functionality changes).

**tests/nrd_kernels_enabled.rs**
- update with functions signature changes (no functionality changes).

**tests/transaction_pool.rs**
- update with functions signature changes (no functionality changes).
- add a context-id-aware kernel-hash retrieval assertion using `retrieve_tx_by_kernel_hash` plus serialized kernel hash equality.
- add `test_stempool_remove_tx_by_transaction`, covering stempool `contains_tx` and fallible `remove_tx` behavior, successful removal, empty-pool state, and idempotent missing-transaction removal.
- add `test_reconcile_reorg_cache_retains_valid_entries`, verifying that valid reorg-cache entries are retained across reconciliation and can repopulate the txpool after the keyed pool entries are cleared.
- add `test_transaction_pool_capacity_limits`, covering max txpool size equality, low-fee rejection while full, eviction/replacement behavior, zero-size txpool retention, and max stempool `OverCapacity` handling so capacity limits cannot grow pools beyond configured bounds.

### mwc-node/servers

**Summary of the changes:**
- Error propagations.
- Switch from hyper to request for web related functionality.
- Switch from wall-clock `DateTime<Utc>` to monotonic `Instant`.

**Cargo.toml**
- remove imported crates, add `mwc_crates` instead.
- add thiserror (it can't be reexported)

**src/common/adapters.rs**
- change `EventCache` from a wall-clock `AtomicI64` cache to a monotonic `Instant`, update timestamps only when requested so read-only misses do not mutate cache state.
- add per-peer legacy v2 block conversion throttling plus compact-block reconstruction reservation/finish/eviction helpers, using saturating math, monotonic staleness checks; bounded cache size, retry windows to limit CPU/memory pressure from legacy peers or repeated compact-block messages.
- update full-block reception, skip work while txhashset validation holds PMMR locks, remove the old duplicate-block event cache shortcut, propagate chain header/process errors instead of substituting defaults.
- harden compact-block reception by skipping txhashset-validation windows, classifying bad/orphan/not-found header errors, reserving reconstruction before tx-pool work.
- rewrite single-header handling to skip during header sync or txhashset validation, remove the old header event cache, validate headers before checking known full blocks, make compact-block requests fallible.
- make full-block serving fallible, throttle legacy v2 conversion for non-empty blocks, propagate conversion errors.
- pre-validate peer-controlled segment ids against archive MMR sizes before building a segmenter.
- propagate PIBD/header-hash/segment receive errors from the sync manager, validate header-hash segment requests against the archive header and expected root, keep all segment receive paths fallible instead of ignoring downstream errors.
- update constructor/init/accessors for explicit external crate types and fallible `OneTime` initialization, store `ChainValidationMode`, initialize the new throttle/cache fields.
- add archive-header/segmenter consistency helpers that detect races between archive hash validation and segmenter construction.
- rework block processing, attach source peer metadata, propagate sync-manager results, distinguish errors, make block requests return chain errors, keep transaction requests explicitly best-effort.
- make `PoolToChainAdapter` chain initialization/access fallible, add `chain_validation_error_to_pool_error`, and map chain validation failures to specific pool errors.
- expand tests with chain-error-to-pool-error classification coverage, legacy conversion throttle burst/refill/stale-peer behavior, compact-block reconstruction retry/stale/eviction behavior.

**src/common/hooks.rs**
- update with functions signature changes (no functionality changes).
- replace separate net/chain hook initializers that returned vectors directly with a `ServerHooks` aggregate plus fallible `init_hooks`, create one shared webhook limiter from config, propagate webhook construction errors, and create chain hooks for callback-only configurations as well as `block_accepted_url`.
- replace panic-based `hyper::Uri` parsing with fallible `reqwest::Url` parsing, validates only `http` and `https` schemes.
- convert `WebHook` from a hyper client wrapper to a fallible reqwest client wrapper, store the shared limiter.
- replace the old hyper POST future with `schedule_post` on the global runtime, sanitize request errors with `without_url`, add callback/limiter helpers, acquire a request permit before serialization, drop excess webhook POSTs when the shared limit is full.
- add typed serializable payload structs for data, peer, block-accepted, and reorg block-accepted webhook payloads plus `serialize_hook_payload`.
- update the block-accepted webhook path to reserve a POST slot before payload work, skip all work when neither callback nor request is available, serialize typed payloads with reorg depth when needed.
- add regression tests for explicit hash-error formatting, payload serialization error reporting, net/chain webhook instances sharing the same request limiter, full-limit request drops avoiding payload serialization, webhook URL parse/scheme errors not echoing credentials or secret paths.

**src/common/stats.rs**
- update with functions signature changes (no functionality changes).
- add regression coverage proving `update_stats` returns `false` without invoking the callback for missing workers and still updates an allocated worker successfully.

**src/common/types.rs**
- update with functions signature changes (no functionality changes).
- for type `Error` add dedicated `DataOverflow`, `Transaction`, and `ConsensusError` variants, remove the manual conversion boilerplate.
- remove obsolete test-miner and libp2p configuration fields from `ServerConfig`.
- mask configured webhook URLs as `<configured>` in `WebHooksConfig` debug output, preventing webhook endpoints or embedded credentials from being exposed in logs while still showing whether each hook is configured.

**src/error.rs**
- update with functions signature changes (no functionality changes).

**src/mining.rs**
- remove the public `test_miner` module export.

**src/mining/mine_block.rs**
- update with functions signature changes (no functionality changes).
- introduce `BuiltBlock` plus the internal `BuildBlockResult` enum so callers receive the built block with parent header/hash metadata.

**src/mining/stratum_data.rs**
- update with functions signature changes (no functionality changes).
- add a small `gcd_u128` helper so network-hashrate calculations can reduce integer ratios before the final floating-point publication.
- make worker updates reject mismatched worker ids or stale connection ids with explicit errors, return kill-switch trigger failures instead of ignoring them, add bounded `try_send` handling, and introduce `WorkerRef` for reporting failures against a stable worker/connection pair.
- make insertion duplicate-safe with `HashMap::entry`, return rejected workers to the caller, make updates report success, add login-timeout accounting that only marks the current unauthenticated connection, make removal explicitly idempotent.
- make `update_network_hashrate` fallible, validate `edge_bits` with checked conversion, propagate `graph_weight` consensus errors, and compute the `42 / 60` factor as a reduced `u128` ratio before converting to `f64` to reduce precision loss for large difficulty values.
- add focused regression tests for duplicate worker-id rejection, update rejection on mismatched worker or connection ids, one-time login-timeout accounting, stale/logged-in timeout rejection, broadcast failure reporting with stable connection references across id reuse, and connection-id exhaustion.

**src/mining/stratumserver.rs**
- update with functions signature changes (no functionality changes).
- add named bounds and helper routines for IP-ban history validation, checked `Instant` deadline calculation, startup-status reporting, IP-pool accounting warnings, idempotent worker cleanup, atomic worker-connection reservation/release, and shutdown-trigger fanout.
- replace the initial default-block state with an initially empty, bounded block-version buffer keyed by stable `job_id`s; add checked job-id overflow handling, old-version eviction, explicit login failure reporting.
- harden RPC dispatch by rejecting unknown workers after failed `last_seen`, enforcing the login gate before protected methods, reporting IP-pool accounting failures instead of ignoring them.
- add connection-aware worker disconnection that triggers the kill switch only for the same live connection id, skips replaced worker ids, logs already-disconnected workers without treating them as hard failures.
- make the main stratum loop return `Result`, replace wall-clock scheduling with monotonic `Instant` deadlines, validate all periodic deadlines with checked arithmetic, propagate chain/head/secp/network-hashrate errors, enforce login-timeout/IP-ban cleanup through one-time accounting and kill-switch errors.
- update `StratumServer` fields and constructor to explicit chain types and unsigned connection counters, and add an optional startup-status sender for callers that need positive listener-start confirmation.
- add listener-thread joining that converts panics into `ServerError`, stops the server on listener panic, clears `is_running` on exit, and exposes a crate-private setter for startup-status reporting.
- make `run_loop` return `Result`, split implementation for optional startup reporting, validate missing or malformed listen addresses as config errors, stop and join the listener on startup failures, compute edge bits with explicit widening instead of unchecked casts, report successful startup, propagate handler failures.
- add focused regressions for internal-error redaction, failed login updates, login-gate behavior with timeouts/whitelists/unknown methods, stable bounded job-id retention, IP-ban history and deadline overflow checks, and sanitized request-log metadata that excludes login params and passwords.

**src/mwc/dandelion_monitor.rs**
- update with functions signature changes (no functionality changes).
- update fluff-phase handling to use stempool snapshots; remove entries skipped by aggregate validation, avoid adding empty fluff aggregates, split validated transactions into one or more batches, add each valid batch to the pool instead of forcing one potentially overweight aggregate.
- add helpers that aggregate fluffable transactions under the context-specific maximum transaction weight, validate every aggregate as a transaction, reject individually overweight transactions.
- add regression tests coverage proving oversized full fluff aggregates are split into multiple valid transaction batches while preserving all original transaction kernels.

**src/mwc/seed.rs**
- update with functions signature changes (no functionality changes).
- join completed connection workers during each monitor loop, use monotonic scheduling for seed reconnects, expiry, peer monitoring, and listen intervals, preserve seed discovery by logging monitor/reconnect errors instead of dropping them.
- trigger another listen pass after connection workers finish while peers are still insufficient, cap concurrent connection attempts through `PEER_CONNECT_POOL_SIZE`, propagate and log `listen_for_addrs` errors, keep retry intervals in unsigned monotonic durations.
- add helpers to collect finished or remaining connection-worker results, convert worker panics into `PeerThreadPanic`, preserve the first worker error for reporting, clamp CPU usage to a finite 0.0-1.0 range, and safely stringify panic payloads.
- keep Tor health gating but only record connection history after worker spawn succeeds, skip onion peers when Tor is disabled, make connection workers return `Result`, mark peers defunct when initial peer-list or ping sends fail.
- add `mark_peer_defunct_after_initial_send_failure` so initial send failures consistently log the failed action, persist Defunct state, and propagate persistence errors.
- route default DNS seed handling through `seed_addr_onion_host`, which recognizes onion hosts case-insensitively and with optional ports or trailing dots before deciding whether to append the network port.
- add regression coverage for connection-worker error collection, finished-worker reporting, CPU usage sanitization, onion host detection variants, onion-like seed parsing behavior, and filtering of loopback/private/documentation/zero-port DNS results.

**src/mwc/server.rs**
- update with functions signature changes (no functionality changes).
- add `PendingPeerListener`/`StartedPeerListener` wrappers so p2p listener startup can be confirmed without holding global registry locks, with startup channel closure, listener errors, and listener panics converted into server errors.
- update `Server` state to store result-returning stratum/listener/API monitor threads, a `listen_peers_starting` flag; remove the obsolete internal miner thread handle.
- make `create_server` reject non-positive `p2p_config.ban_window` values, and validate the Dandelion configuration before initialization.
- replace the optional `wait_for_starting` listener API with a required startup-confirmation flow split across `start_listen_peers`, `begin_start_listen_peers`, and finish helpers; prevent duplicate listener starts.
- make the stratum server thread return `Result`, add startup-status reporting, wait for listener startup before accepting the service as running, join failed startup threads so bind/config errors and panics are returned to the caller instead of being deferred or lost.
- remove the legacy internal test-miner constructor and background mining loop setup from the server facade.
- make shutdown explicitly best effort by stopping p2p before joining background threads, joining result-returning stratum/listener/API monitor threads with error logging.
- add `build_tls_config`, accepting only the disabled-TLS case or a complete certificate/key pair and rejecting certificate-only or key-only configurations with explicit config errors.
- add focused regression tests for disabled/enabled TLS configuration, certificate/key mismatch rejection, and early rejection of invalid Dandelion configuration in `create_server`.

**src/mwc/sync/block_headers_request_cache.rs**
- update with functions signature changes (no functionality changes).
- at `add_block_request` evicting highest-height buckets while the queue exceeds `MAX_QUEUED_BLOCK_REQUESTS`.
- add a regression test that initializes a temporary Floonet chain, fills the block-request cache past the configured cap, verifies the highest-height bucket is evicted and the queue remains bounded, and cleans up the temporary chain directory.

**src/mwc/sync/body_sync.rs**
- update with functions signature changes (no functionality changes).
- lines 59-70 and former lines 57-73: use recursive non-poisoning reads for peer capabilities, switch request parameters to explicit `mwc_p2p::Peers`, and return explicit `mwc_chain::Error` values.
- add `push_retry_expiration` with checked `Instant` arithmetic and retry-latency overflow reporting.

**src/mwc/sync/header_hashes_sync.rs**
- update with functions signature changes (no functionality changes).
- add `HeadersRootSelection`, archive-height-scoped cached responses, and `HeadersHashResponseStatus`, giving header-hash root election and response handling explicit status states.
- add `HeadersHashSyncSnapshot` and archive-height-aware PIBD readiness checks so callers can take a point-in-time state view.
- update reset/cache clearing to the new non-poisoning lock fields, remove the old direct completion/target accessors.
- add quorum-based root-selection helpers, peer filtering for alternate archive heights, selected-root reset support so root handshakes and retries are handled consistently.
- harden initial root election by expiring timed-out requests with peer penalties, requiring a strict quorum with at least two matching responses, reporting bad selected roots to the peers that supplied them, resetting or waiting explicitly when more responses or a new peer-election round is needed.
- restrict segment requests to peers that committed to the selected root and did not advertise another archive height; if only alternate roots are available, discard the selected root and retry election, otherwise return a detailed wait message.
- make header-hash root receipt return `HeadersHashResponseStatus`, ignore wrong-height or duplicate responses, reject unsolicited responses with a peer error report, only mark peers successful after a matching outstanding request is consumed.
- make segment receipt fallible, verify the selected root through a read lock, validate segment offsets, ignore unsolicited segments, report responses from peers other than the requested peer, remove request tracking after either accepted or failed desegmenter insertion, propagate desegmenter errors to callers.
- add regression coverage for root-selection quorum behavior, including single-response rejection, strict majority requirements, accepted quorum, even-split rejection, and partial-majority waiting.

**src/mwc/sync/header_sync.rs**
- add bounded `HeadersSeriesCache` helpers with entry-count and total-header caps, monotonic expiration, and eviction that prefers already-known headers before oldest unknown headers, limiting memory growth from fragmented multi-message header responses.
- update `HeaderSync` state to use `HeadersRecieveCache<PeerAddr>`, monotonic retry expirations, the bounded header-series cache alias, an `apply_headers_lock` mutex so only one thread applies cached PIBD headers to chain state at a time.
- add helper flows to recreate the received-header cache when the selected header-hash desegmenter changes, reset stale request/retry/peer-exclusion state.
- harden the below-horizon PIBD path by reading the selected desegmenter through a shared lock, validating/recreating the received cache before use, applying cached headers through the guarded helper, updating sync status before more requests, using the snapshot target archive height for request planning.
- change `receive_headers` to accept a shared desegmenter handle, prune the cache after inserts and final assembly so stale or oversized response fragments cannot accumulate unboundedly.
- validate every received header hash against the active context, remove/score only matching tracked requests, ignore unsolicited or stale PIBD responses, ensure cache identity before accepting below-horizon batches.
- add `request_more_pibd_headers` to centralize follow-up PIBD request dispatch once the desegmenter is complete and the request tracker allows another ask, keeping duplicate scheduling and peer exclusion logic in one fallible path.
- add regression coverage for header-series cache pruning, including expiration, entry-count caps, total-header caps, known-header eviction priority, and oldest-entry eviction after known headers are removed.

**src/mwc/sync/orphans_sync.rs**
- add bounded orphan-defense state with per-header candidate, source-peer metadata, and per-peer retry caps plus `UnknownBlock` and `OrphanRetryBudget`, limiting memory growth, metadata growth, retry fan-out while keeping byte-distinct orphan candidates available for validation.
- make `recieve_block_reporting` return `Result`, enforce the orphan height window before caching, propagate chain lookup failures, skip already-known or too-far blocks, deduplicate only canonical byte-identical bodies, cap per-hash and total unknown-block candidates, retain capped source-peer metadata for later peer attribution.
- rework unknown-block cleanup and replay, sort cloned candidates by height, process candidates only after the previous full block exists, pass source-peer metadata into `process_block`, drop bad-data candidates, expire entries with monotonic age, enforce the candidate-count limit, add unknown block hashes directly to the validation set.
- rework the stuck-orphan loop around `needed_prev_blocks` and `OrphanRetryBudget`, process stale orphans, remove processed or terminal bad/known orphans.
- split previous-block checks into fallible helper methods, add explicit orphan-window, retry-limit, unknown-cache-limit, capped-source-peer, canonical serialized-block hash, known-block-error helpers.
- add regression tests coverage proving source-peer metadata remains capped and duplicate retained peers do not expand the unknown-block source set.

**src/mwc/sync/state_sync.rs**
- update with functions signature changes (no functionality changes).
- add `PibdRootSelection`, giving PIBD root election explicit selected, wait, and no-quorum states.
- replace wall-clock response and retry timestamps with `Instant`, add guard-carrying desegmenter session structs so reset cannot race segment validation/application or request scheduling.
- add `select_pibd_root` so root selection is delegated to quorum logic requiring at least two matching responses and a strict majority.
- reset stale PIBD state when the target archive hash changes.
- rework desegmenter initialization to surface total root-send failure as a wait state, wait for more responses when quorum is incomplete, reject no-quorum elections by reporting and clearing offending responses, propagate errors.
- replace `validate_root_hash` and `is_expected_peer` with `validated_desegmenter` and `live_desegmenter`, returning guard-backed session handles that bind archive-hash/root-hash validation to the live desegmenter.
- update all bitmap/output/rangeproof/kernel segment receive paths to use explicit p2p types, fallible segment leaf-offset extraction, guard-backed desegmenter validation.
- add regression tests for PIBD root quorum selection, covering single-response rejection, strict-majority requirements, successful quorum, even-split rejection, and waiting on partial majorities.

**src/mwc/sync/sync_manager.rs**
- update with functions signature changes (no functionality changes).
- replace single best-peer height selection with outbound `HEADERS_HASH` peer voting by context-aware archive height, require a strict quorum with at least two matching responses, and return explicit `WaitingForPeers` statuses when there are too few responses or no archive-height quorum.

**src/mwc/sync/sync_peers.rs**
- update with functions signature changes (no functionality changes).
- add explicit caps for peer-status and banned-peer tracking, store the full `PeerAddr` plus last-update timestamp in each PIBD peer status, bound each response history at insertion time.
- rework `apply_peers_status` to snapshot pending peer keys, use the stored full peer address for bans/offline returns, retry failed bans instead of dropping the event, remove completed/offline status entries.
- add test helpers for deterministic non-loopback peer addresses, capped seeded peer-status/banned-peer maps, and temporary p2p peer-store construction.
- add regression tests coverage proving peer status preserves the full non-loopback socket address and refreshes that stored address when later events arrive for the same peer key.
- add regression tests coverage for per-peer response-history bounding and global peer-status pruning, including recency refresh behavior so recently updated peers are not evicted by the size cap.
- add regression tests coverage for capped banned-peer tracking, verifying oldest-entry pruning and recency refresh behavior for previously banned peers.

**src/mwc/sync/sync_utils.rs**
- update with functions signature changes (no functionality changes).
- add `QuorumSelection` and `select_quorum`, providing a reusable strict-quorum helper.
- change `CachedResponse` expiration from wall-clock `DateTime<Utc>` to monotonic `Instant`.
- add `remove_request_by_key` for callers that must clear a stale key while only recording latency for the expected peer.
- extend `get_sync_peers` with an optional exact archive-height filter based on the p2p context id.
- add regression coverage for empty latency history, checked cached-response timeout overflow, quorum selection success/wait/no-quorum cases, retry-latency fallback behavior, duplicate request replacement accounting, non-matching request removal, and forced key-based stale request cleanup.

**src/mwc/sync/syncer.rs**
- update with functions signature changes (no functionality changes).
- treat `WaitingForHeaders`, `WaitingForHeadersHash`, and `BadState` as normal active sync responses, keep boost-peer capabilities updated for `HasMoreHeadersToApply`.

### mwc-node/node_workflow

**Cargo.toml**
- remove imported crates, add `mwc_crates` instead.
- add thiserror (it can't be reexported)

**src/context.rs**
- replace the single `USED_CONTEXTS` bitset with a documented `CONTEXTS` registry that tracks `reserved` and `ready` ids separately, so ids being allocated or released cannot be observed as fully available.
- add `ContextRegistry` plus an RAII `ReservedContext` guard that commits successful allocations and automatically rolls back uncommitted reservations on drop, preventing leaked context slots after initialization failures.
- extract bounded context-id reservation and checked mask calculation, using the explicit id range and both registry bitsets to reject already reserved or ready ids instead of shifting unchecked caller-controlled values.
- add allocation rollback and commit helpers that release Arti cancellation state, global context data, and chain pipeline context data on failed initialization.
- add `get_chain_type` as a fallible context lookup that rejects out-of-range, missing, or not-yet-ready ids before reading global chain type state.
- rewrite `allocate_new_context` to reserve an id before initialization, propagate fallible global chain-type, fee-base, NRD, and runtime initialization errors as `ContextError`.
- harden `release_context` with range validation, ready-state checks, and a `ready` to `reserved` transition during cleanup.
- add focused context lifecycle tests for allocation rollback after initialization failure, rejection of reserved ids, rejection of out-of-range releases, and `get_chain_type` behavior before and after release.

**src/logging.rs**
- update with functions signature changes (no functionality changes).

**src/server.rs**
- update with functions signature changes (no functionality changes).
- replace the single-call peer listener startup API with a two-phase `begin_start_listen_peers`/`finish_start_listen_peers` flow, remove the caller-supplied `wait_for_starting` flag.

### mwc-node/etc/gen_gen

**src/bin/gen_gen.rs**
- update with functions signature changes (no functionality changes).

### mwc-node/src

**Summary of the changes:**
- Error propagations.
- Escaping income strings.

**Cargo.toml**
- remove imported crates, add `mwc_crates` instead.
- declate workspace.dependencies `thiserror` and `safer-ffi`, so all other dependent crates will use those crates.

**src/bin/cmd/client.rs**
- build explicit JSON-RPC requests with normalized null parameters, serialize them with logged error handling, post to the pre-normalized URL, parse typed JSON-RPC responses, reject RPC error payloads and response-id mismatches.
- harden API output by escaping server-controlled strings before printing.
- add node URL derivation and validation helpers that trim empty input, infer `http`/`https` from server TLS configuration, reject unsupported schemes, incomplete TLS configuration, embedded credentials, missing hosts, query strings, and fragments.
- read the node API secret through the owner-only zeroizing file helper.
- add unit tests coverage for URL normalization, explicit HTTPS preservation, plaintext remote and `localhost` rejection when an API secret is present, plaintext remote allowance without an API secret, embedded credential rejection, wildcard-address loopback rewriting, HTTPS derivation from complete TLS config, and incomplete TLS config rejection.

**src/bin/cmd/config.rs**
- change `config_command_server` from a panic-on-failure helper to `Result`, keep the current-directory-only behavior, reject invalid filenames before any configuration or filesystem work is attempted.
- add `is_single_normal_filename` so only one normal filename component is accepted, blocking empty names, dot components, parent-directory traversal, nested paths, and absolute paths.
- add unit tests for accepting a normal config filename, rejecting path-like filenames, and returning the expected invalid-filename error from `config_command_server`.

**src/bin/cmd/server.rs**
- update with functions signature changes (no functionality changes).
- require `--api_host` and `--api_port` to be supplied together and route both through a validation helper, removing the old port-only behavior that implicitly bound the API to `0.0.0.0`.
- reject malformed `--seed` values with `ArgumentError` instead of silently dropping unparsable seeds.
- add `api_http_addr_from_host_port`, trimming and unwrapping bracketed hosts, rejecting empty or non-IP hosts, validating the port as `u16`, formatting the final API bind address through `SocketAddr` for normalized IPv4/IPv6 handling.

**src/bin/mwc.rs**
- update with functions signature changes (no functionality changes).
- replace the `load_yaml!` macro with explicit `YamlLoader::load_from_str(include_str!("mwc.yml"))` parsing, returning an operator-facing startup error for invalid or empty command-line YAML instead of assuming the embedded configuration loads successfully.

**src/bin/mwc.yml**
- add a new `server` subcommand `--api_host` option.

**src/bin/tui/menu.rs**
- update with functions signature changes (no functionality changes).
- log missing root-stack or missing-layer conditions instead of panicking or silently failing during menu selection.

**src/bin/tui/mining.rs**
- update with functions signature changes (no functionality changes).
- add shared helpers for named-view updates and mining stack navigation, logging missing views, unexpected view types, and missing stack layers.
- add unit tests for valid worker timestamps, Chrono out-of-range worker and difficulty timestamps, `u64` to `i64` overflow, and subsecond times before the Unix epoch.

**src/bin/tui/peers.rs**
- update with functions signature changes (no functionality changes).

**src/bin/tui/status.rs**
- add a shared percentage helper using `u128` arithmetic and explicit zero-denominator handling, preventing overflow in large sync-progress values.
- expand sync progress display from seven to ten steps, route all percentage calculations through the checked helper, add progress-aware handling for kernels-history validation, output/kernel position index builds, generic txhashset state validation stages.
- route all basic status, chain/header status, and tx-pool named-view updates through `call_on_name_or_log`.
- add unit test coverage for the new sync-step messages, txhashset index/state-validation display, stage display names, and overflow-safe percentage calculations across every percentage-bearing sync status.

**src/bin/tui/ui.rs**
- update with functions signature changes (no functionality changes).

**src/build/build.rs**
- update with functions signature changes (no functionality changes).

### mwc-node/mwc_node_lib

**Cargo.toml**
- remove imported crates, add `mwc_crates` instead.
- declate workspace.dependencies `thiserror` and `safer-ffi`, so all other dependent crates will use those crates.

**c_header/mwc_node_interface.h**
- rename `free_node_lib_string` to `free_lib_string`, aligning the generated C header with the updated FFI memory-management API.

**src/ffi.rs**
- change registration to accept `Option<CallbackFn>` and return immediately for a null callback pointer.
- validate unregister callback names as UTF-8 before touching the registry.
- validate `process_mwc_node_request` input as UTF-8 before dispatching the JSON request.
- add unit tests covering successful unregister removal, missing-name unregister preserving other registrations, and invalid-UTF-8 unregister preserving existing registrations.

**src/generate_headers.rs**
- add an explicit `__RUST_MWC_NODE_LIB__` include guard to the `safer_ffi` header builder, making the generated C header use a stable project-specific guard and avoiding accidental duplicate inclusion or guard-name drift for downstream C consumers.

**src/mwc_node_calls.rs**
- add shared callback-registry helpers that validate callback presence and dispatch callbacks while holding the registry read lock, making `unregister_lib_callback` wait until in-flight FFI callback use of caller-owned context pointers has finished.
- route `create_server` through a dedicated mutable-params handler, stop cloning the general `params` object for non-server requests, reducing secret copies and enabling sensitive parameter removal.
- move `create_server` processing into `process_create_server_request`, use the fallible node-workflow context lookup for `chain_type`, validate webhook callback registration without cloning callback state, dispatch webhook callbacks through the locked registry helper.
- remove `onion_expanded_key` from the mutable params object, require it to be a string when present, hold it in `Zeroizing<String>` while the request is being validated.
- add unit tests for the new API response helper, covering preserved success response shape and rejection of non-success HTTP statuses with body text included in the error.
