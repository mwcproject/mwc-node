# Release 6.1.0

## Release Highlights

Release 6.1.0 address audit comments/issues that was found with AI code review. Also, because code changes affect 
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

Summary ofthe changes:
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

**Cargo.toml**
- line 7: bump crate version from `0.5.6` to `0.5.7`.
- line 16: bump the local `easy-jsonrpc-proc-macro-mwc` dependency from `0.5.2` to `0.5.3`.
- lines 19-20: update runtime dependencies by moving `jsonrpc-core` from `10.0.1` to `18` and replacing the old direct `rand 0.6.5` dependency with `tokio 1` using the `full` feature set.
- lines 24-25: update HTTP test/development dependencies to newer explicit-feature declarations: `reqwest 0.13` with `json` and `blocking`, and `warp 0.4` with `server`.

**examples/http_connect.rs**
- line 8: switch the HTTP client import from `reqwest::Client` to `reqwest::blocking::Client`, keeping the example on the synchronous client API used by `post()` and matching the newly enabled `blocking` reqwest feature.
- line 48: make response deserialization explicit with `.json::<Value>()`, ensuring the example parses HTTP responses as `serde_json::Value` without relying on type inference.

**examples/http_listen.rs**
- line 10: replace the removed/obsolete `warp::post2` import with `warp::post`, matching the updated Warp routing API.
- lines 14-15: convert the example entry point to an async Tokio runtime entry point with `#[tokio::main]` and `async fn main()`, allowing the server future to be driven correctly.
- line 20: update route construction from `post2()` to `post()`, keeping the HTTP method filter consistent with the new import and Warp version.
- line 32: await `warp::serve(responder).run(addr)`, ensuring the async server future actually runs instead of being dropped.
- line 36: return `warp::reply::json(&json_value)` directly instead of wrapping it in `Ok(...)`, aligning the helper with its `impl Reply` return type.

**proc_macros/Cargo.toml**
- line 7: bump the `easy-jsonrpc-proc-macro-mwc` crate version from `0.5.2` to `0.5.3`, matching the parent crate's dependency update.
- lines 16-19: update procedural macro dependencies to maintained versions: `syn` from `0.15.26` to `2.0` with `full`, `proc-macro2` from `0.4.26` to `1.0`, `quote` from `0.6.11` to `1.0`, and `heck` from `0.3.1` to `0.5`, reducing obsolete dependency exposure and improving compatibility with the current Rust macro ecosystem.

**proc_macros/src/lib.rs**
- lines 7-11: update imports for the newer procedural macro stack: switch `heck::SnakeCase` to `heck::ToSnakeCase`, replace removed `syn` APIs such as `MethodSig`, `FnDecl`, and `ArgSelfRef` with `Signature` and current argument/item types, and import `Punctuated` through its current path.
- lines 64-76: add server-side audit notes documenting generated handler serialization behavior, including `serde_json` conversion of non-finite floats to `null`, possible numeric rounding, and the intentionally non-standard RPC error envelope; update `impl_server` to work with `Signature` method metadata.
- lines 106-109: update client helper generation to use `Signature` method metadata and the newer `ToSnakeCase` trait while preserving the generated helper module naming behavior.
- lines 126-149: add client-side serialization notes for non-finite floats and full-width integer values, and change generated argument serialization failures from a generic `ArgSerializeError` to `ArgSerializeError::from_serde` with the argument name and underlying serde error for better diagnostics.
- lines 167-184: migrate return-type helper logic from `MethodSig.decl.output` to `Signature.output`, and build the implicit unit return type with a default paren token compatible with the updated `syn` API.
- lines 187-200: update trait method discovery from `TraitItem::Method` to `TraitItem::Fn` and `Signature`, retaining the existing validation that traits contain methods only and reject the reserved `rpc.` method prefix.
- lines 203-230: document numeric deserialization edge cases in generated server handlers, and change argument parse failures to use `InvalidArgs::invalid_arg_structure` with argument name, index, and a sanitized `"parsing error"` message so serde internals are not exposed to external clients.
- lines 246-263: migrate method argument extraction to `Signature.inputs` and `FnArg::Receiver`, preserving the requirement that the first argument is an immutable `&self`.
- lines 288-319: migrate argument pattern extraction to `syn` 2 by using `FnArg::Typed`, dereferencing boxed patterns, and making the `PatIdent` match forward-compatible, while keeping the existing rejection rules for non-concrete, pattern-matched, by-reference, and mutable arguments.

**src/lib.rs**
- line 174: update the crate-level batch-call example to unwrap the new fallible `Call::batch_request` result.
- lines 190-193: add JSON-safe request ID and batch-size constants: `MAX_SAFE_JSON_INT`, the global atomic `NEXT_ID`, and `BATCH_LEN_LIMIT` set to 128.
- lines 207-211: remove the old `rand` dependency usage and add `HashSet` plus `AtomicU64`/`Ordering` imports for duplicate detection and sequential request IDs.
- lines 221-231: change raw request deserialization failures from JSON-RPC parse errors (`-32700`) to invalid request errors (`-32600`), matching the fact that this API receives already-parsed JSON values.
- line 283: include JSON-RPC 2.0 version metadata when returning an invalid-call response.
- lines 298-307: reject calls whose `jsonrpc` version is not `2.0`; notifications are silently skipped, while method calls receive an invalid-request failure with JSON-RPC 2.0 response metadata.
- lines 310-334: make notification response suppression explicit and document that handler errors for notifications intentionally produce no response; also document the crate's non-standard error-result envelope.
- lines 347-374: harden batch request handling by rejecting empty batches and batches larger than `BATCH_LEN_LIMIT`, detecting duplicate non-notification IDs with a `HashSet`, and returning a single validation failure instead of processing ambiguous or excessive batches.
- lines 383-404: extend `InvalidArgs` with `DuplicateArgumentName`, add source details to `InvalidArgStructure`, and provide a helper constructor for generated code to attach sanitized parse-error context.
- lines 406-430: map the new duplicate-argument and source-bearing invalid-argument variants into `invalid_params` messages so callers get actionable argument validation errors.
- lines 456-469: update named-argument documentation and replace the old debug-only duplicate argument-name assertion with runtime validation, preventing duplicate generated argument names from passing in release builds.
- lines 524-541: replace random request IDs with a predictable atomic counter constrained to JavaScript's 53-bit safe integer range, documenting that IDs are not secret and may wrap only after a very large count.
- lines 591-612: make `Call::batch_request` fallible and validate client-side batches for empty input, excessive length, and duplicate request IDs before returning the JSON array.
- lines 616-629: document 64-bit integer serialization caveats and suppress internal serializer error details from RPC error `data`, reducing information disclosure to remote clients.
- lines 647-674: change `ArgSerializeError` from a unit/copy type into a diagnostic struct containing the argument name and source string, with constructors for serde failures and non-finite float validation.
- lines 681-696: extend `InvalidResponse` with duplicate response ID, oversized batch response, empty response, and invalid JSON-RPC version cases.
- lines 706-761: harden response parsing by rejecting empty or oversized response batches, validating JSON-RPC 2.0 on success and failure outputs, requiring numeric IDs, and detecting duplicate IDs while building the response map.
- lines 1190-1205: update the non-macro client test helper to build `ArgSerializeError` with argument names and serde error details.
- line 1293: update the response double-get test to unwrap the new fallible `Call::batch_request` API.

### mwc-node/util

### mwc-node/keychain

### mwc-node/core

### mwc-node/store

### mwc-node/config

### mwc-node/chain

### mwc-node/api

### mwc-node/p2p

### mwc-node/pool

### mwc-node/servers

### mwc-node/node_workflow

### mwc-node/src

### mwc-node/mwc_node_lib
