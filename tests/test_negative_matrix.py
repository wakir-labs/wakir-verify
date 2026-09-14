# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Callandor GmbH and contributors

"""The counter-examples from the 2026-09-14 external re-review.

Every case below was reproduced against the pre-fix code and is kept
here as a standing negative control. The value of this file is not the
assertions — it is that each case names the exact input that used to
produce a positive result, so a future change that reintroduces the
behaviour fails here with the original wording attached.

R3 — the four-pole anchor path
------------------------------

Input: a file consisting of the OTS magic header plus the *text*
``BitcoinBlockHeaderAttestation(800000)``. Not a timestamp proof. With
the ``ots`` runner reporting failure and both HTTP doubles returning
the same formally valid block hash, the pre-fix aggregator produced::

    pole_python_stdlib         ok=True  verdict=verified
    pole_ots_cli               ok=False verdict=failed
    pole_mempool_space         ok=True  verdict=verified
    pole_esplora_blockstream   ok=True  verdict=verified
    QUORUM = True        (policy 3-of-4)

and produced it identically when handed a completely different
``anchor_hash``. Three poles that never compared the root outvoted the
one that reported a problem.

R2 — hash-list consistency
--------------------------

Input: a real manifest with ``event_id`` and ``payload_hash`` edited in
the event records while the stored leaf hashes and the root are left
alone. ``compute_manifest_consistency()`` stays positive, because it
folds the stored hashes. An independent recomputation of the leaf hash
from the event fields does not.

No network access. The HTTP transports and the ``ots`` runner are
injected doubles, as everywhere else in this suite.
"""

from __future__ import annotations

import copy
import dataclasses
import json
from pathlib import Path

import pytest

from wakir_verify.aggregator import QuorumPolicy, verify_wat_anchor
from wakir_verify.binding import (
    check_event_binding,
    check_hashlist_consistency,
    check_payload_binding,
)
from wakir_verify.claims import (
    STATUS_FAILED,
    STATUS_NOT_CHECKED,
    STATUS_OK,
)
from wakir_verify.manifest import (
    compute_manifest_consistency,
    load_manifest_from_dict,
)
from wakir_verify.merkle_proof import compute_leaf_hash, merkle_proof
from wakir_verify.poles import HttpResponse

from tests.fixtures import (
    NON_PROOF_TEXT_BYTES,
    build_ots_receipt,
    receipt_file_digest,
)

#: Arbitrary well-formed anchor. The point of the R3 cases is that the
#: value never mattered.
ANCHOR_A = "a" * 64
#: A different well-formed anchor. Swapping A for B changed nothing.
ANCHOR_B = "b" * 64

#: Formally valid block hash both HTTP doubles return.
BLOCK_HASH = "0000000000000000000a1d2c3b4e5f60718293a4b5c6d7e8f90123456789abcd"

#: Height named in the reviewer's artificial file.
HEIGHT = 800_000


@dataclasses.dataclass
class _CompletedProcess:
    stdout: str
    stderr: str = ""
    returncode: int = 1


def _failing_ots_runner(argv):
    """The reviewer's CLI double: upstream reports an error."""
    return _CompletedProcess(
        stdout="", stderr="Error! not a timestamp file.\n", returncode=1
    )


def _agreeable_transport(url: str, timeout_s: float) -> HttpResponse:
    """Both HTTP doubles answer every height with the same valid hash."""
    return HttpResponse(status=200, body=BLOCK_HASH)


def _overrides():
    return {
        "pole_ots_cli": {"ots_runner": _failing_ots_runner},
        "pole_mempool_space": {
            "expected_block_height": HEIGHT,
            "expected_block_hash": BLOCK_HASH,
            "transport": _agreeable_transport,
        },
        "pole_esplora_blockstream": {
            "expected_block_height": HEIGHT,
            "expected_block_hash": BLOCK_HASH,
            "transport": _agreeable_transport,
        },
    }


# ---------------------------------------------------------------------------
# R3 — the anchor path
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("anchor", [ANCHOR_A, ANCHOR_B])
def test_r3_text_shaped_non_proof_never_reaches_quorum(tmp_path, anchor):
    """The reviewer's exact input, under both anchors."""
    receipt = tmp_path / "not-a-proof.ots"
    receipt.write_bytes(NON_PROOF_TEXT_BYTES)

    result = verify_wat_anchor(
        anchor_hash=anchor,
        ots_proof_path=str(receipt),
        quorum_policy=QuorumPolicy.THREE_OF_FOUR,
        pole_overrides=_overrides(),
    )

    assert result.overall_status == "failed"
    assert result.quorum is False
    assert result.mandatory_verified_by == ()
    assert result.pole_results["pole_python_stdlib"].verdict == "failed"
    # The two observers still answer; they simply cannot carry a
    # verdict, which is the whole shape of the fix.
    assert result.pole_results["pole_mempool_space"].ok is True
    assert result.pole_results["pole_mempool_space"].verdict == (
        "block_observed"
    )


def test_r3_swapping_the_anchor_changes_the_outcome(tmp_path):
    """The root is load-bearing now; before, it was inert.

    A real receipt for ANCHOR_A must not vouch for ANCHOR_B. The
    pre-fix default body never referenced ``anchor_hash`` at all, so
    this distinction did not exist.
    """
    receipt = tmp_path / "root.bin.ots"
    receipt.write_bytes(
        build_ots_receipt(
            file_digest=receipt_file_digest(ANCHOR_A),
            branches=[{"ops": [], "attestation": ("bitcoin", HEIGHT)}],
        )
    )

    right = verify_wat_anchor(
        anchor_hash=ANCHOR_A,
        ots_proof_path=str(receipt),
        pole_overrides=_overrides(),
    )
    wrong = verify_wat_anchor(
        anchor_hash=ANCHOR_B,
        ots_proof_path=str(receipt),
        pole_overrides=_overrides(),
    )

    assert right.pole_results["pole_python_stdlib"].witness["binding"][
        "bound"
    ] is True
    assert wrong.pole_results["pole_python_stdlib"].verdict == "failed"
    assert wrong.overall_status == "failed"


def test_r3_three_observing_poles_cannot_outvote_a_missing_mandatory_one(
    tmp_path,
):
    """The arithmetic that produced the false positive, isolated.

    Both HTTP poles report ok, the offline pole is bound but has no
    block header, and the CLI pole is absent. Three ``ok`` votes under
    a 2-of-4 policy — and still not a verification, because nothing
    tied the root to Bitcoin.
    """
    receipt = tmp_path / "root.bin.ots"
    receipt.write_bytes(
        build_ots_receipt(
            file_digest=receipt_file_digest(ANCHOR_A),
            branches=[{"ops": [], "attestation": ("bitcoin", HEIGHT)}],
        )
    )

    result = verify_wat_anchor(
        anchor_hash=ANCHOR_A,
        ots_proof_path=str(receipt),
        quorum_policy=QuorumPolicy.TWO_OF_FOUR,
        enabled_poles=[
            "pole_python_stdlib",
            "pole_mempool_space",
            "pole_esplora_blockstream",
        ],
        pole_overrides=_overrides(),
    )

    assert result.supporting_quorum is True
    assert result.mandatory_verified_by == ()
    assert result.overall_status == "not_checked"
    assert result.quorum is False


def test_r3_pending_only_receipt_is_not_checked_not_verified(tmp_path):
    """An un-upgraded timestamp is honestly incomplete, not valid."""
    receipt = tmp_path / "root.bin.ots"
    receipt.write_bytes(
        build_ots_receipt(
            file_digest=receipt_file_digest(ANCHOR_A),
            branches=[
                {
                    "ops": [],
                    "attestation": ("pending", "https://alice.calendar.test"),
                }
            ],
        )
    )

    result = verify_wat_anchor(
        anchor_hash=ANCHOR_A,
        ots_proof_path=str(receipt),
        enabled_poles=["pole_python_stdlib"],
    )
    assert result.overall_status == "not_checked"
    assert result.pole_results["pole_python_stdlib"].verdict == "structural_ok"


# ---------------------------------------------------------------------------
# R2 — the manifest path
# ---------------------------------------------------------------------------


def _manifest_dict(count: int = 4) -> dict:
    """A v1 manifest whose stored hashes are genuinely consistent."""
    events = []
    for idx in range(count):
        event = {
            "event_id": f"evt-{idx:04d}",
            "time": f"2026-05-27T00:{idx:02d}:00.000Z",
            "payload_hash": f"{idx:064x}",
            "capability_token_hash": "" if idx % 2 else f"{idx + 99:064x}",
        }
        event["leaf_hash"] = compute_leaf_hash(
            event["event_id"],
            event["time"],
            event["payload_hash"],
            event["capability_token_hash"],
        ).hex()
        events.append(event)

    from wakir_verify.merkle_proof import root_hash

    root = root_hash([bytes.fromhex(e["leaf_hash"]) for e in events])
    return {
        "version": "wakir-wat-manifest/v1",
        "hour_slot": "2026-05-27T00",
        "merkle_root": root.hex(),
        "event_count": len(events),
        "events": events,
        "leaves": events,
    }


def test_r2_positive_control_unmodified_manifest_binds():
    manifest = load_manifest_from_dict(_manifest_dict())
    assert compute_manifest_consistency(manifest) is True
    assert check_hashlist_consistency(manifest).status == STATUS_OK
    assert check_event_binding(manifest).status == STATUS_OK


def test_r2_edited_event_fields_with_untouched_hashes_are_rejected():
    """The reviewer's counter-example.

    Consistency stays positive — it always would, it folds the stored
    hashes — and the event binding catches it. Both statements appear
    in the report, which is the point: one of them was doing the
    other's job.
    """
    data = _manifest_dict()
    for key in ("events", "leaves"):
        data[key][1]["event_id"] = "evt-TAMPERED"
        data[key][1]["payload_hash"] = "de" * 32

    manifest = load_manifest_from_dict(data)

    assert compute_manifest_consistency(manifest) is True
    assert check_hashlist_consistency(manifest).status == STATUS_OK

    claim = check_event_binding(manifest)
    assert claim.status == STATUS_FAILED
    assert claim.evidence["mismatch_count"] == 1
    assert claim.evidence["mismatches"][0]["event_id"] == "evt-TAMPERED"


def test_r2_edited_fields_caught_against_external_event_records():
    """Same edit, but the honest records are supplied separately."""
    clean = _manifest_dict()
    tampered = copy.deepcopy(clean)
    for key in ("events", "leaves"):
        tampered[key][2]["time"] = "2099-01-01T00:00:00.000Z"
        tampered[key][2]["leaf_hash"] = compute_leaf_hash(
            tampered[key][2]["event_id"],
            tampered[key][2]["time"],
            tampered[key][2]["payload_hash"],
            tampered[key][2]["capability_token_hash"],
        ).hex()

    # The leaf hash was updated to match, so the manifest is internally
    # coherent — every manifest-internal check passes. Only the
    # external records show the substitution.
    manifest = load_manifest_from_dict(tampered)
    assert check_event_binding(manifest).status == STATUS_OK

    claim = check_event_binding(manifest, events=clean["events"])
    assert claim.status == STATUS_FAILED
    assert claim.evidence["source"] == "external-events"


def test_r2_missing_event_fields_report_not_checked():
    """A hash-only manifest yields silence, not assent."""
    data = _manifest_dict()
    data["leaves"] = [
        {"event_id": leaf["event_id"], "leaf_hash": leaf["leaf_hash"]}
        for leaf in data["leaves"]
    ]
    manifest = load_manifest_from_dict(data)

    claim = check_event_binding(manifest)
    assert claim.status == STATUS_NOT_CHECKED
    assert "not checked" in claim.summary


def test_r2_event_record_missing_for_a_leaf_is_a_failure():
    data = _manifest_dict()
    manifest = load_manifest_from_dict(data)
    claim = check_event_binding(manifest, events=data["events"][:-1])
    assert claim.status == STATUS_FAILED
    assert claim.evidence["missing_count"] == 1


def test_r2_duplicate_event_ids_break_the_mapping():
    data = _manifest_dict()
    events = list(data["events"])
    events.append(dict(events[0]))
    manifest = load_manifest_from_dict(data)
    claim = check_event_binding(manifest, events=events)
    assert claim.status == STATUS_FAILED
    assert claim.evidence["duplicate_event_ids"] == ["evt-0000"]


# ---------------------------------------------------------------------------
# R2 — proof-to-manifest binding
# ---------------------------------------------------------------------------


def _proof_for(data: dict, index: int) -> dict:
    leaves = [bytes.fromhex(e["leaf_hash"]) for e in data["leaves"]]
    siblings = [
        {"hash": h.hex(), "side": side}
        for h, side in merkle_proof(leaves, index)
    ]
    return {
        "schema": "wakir-inclusion-proof/v1",
        "manifest_version": data["version"],
        "merkle_root": data["merkle_root"],
        "leaf_hash": data["leaves"][index]["leaf_hash"],
        "leaf_index": index,
        "leaf_count": len(leaves),
        "event_id": data["leaves"][index]["event_id"],
        "siblings": siblings,
    }


def test_r2_valid_inclusion_proof_binds_to_this_manifest():
    data = _manifest_dict()
    manifest = load_manifest_from_dict(data)
    claim = check_event_binding(manifest, proof=_proof_for(data, 2))
    assert claim.status == STATUS_OK
    assert claim.evidence["proof_binding"]["path_reconstructs_root"] is True


def test_r2_proof_from_another_manifest_is_rejected():
    """An inclusion proof has to belong to the manifest it is shown with."""
    data = _manifest_dict()
    other = _manifest_dict(count=5)
    manifest = load_manifest_from_dict(data)
    claim = check_event_binding(manifest, proof=_proof_for(other, 1))
    assert claim.status == STATUS_FAILED
    assert "different manifest" in claim.summary


def test_r2_tampered_sibling_is_still_rejected():
    """Positive control on the Merkle side: this already worked."""
    data = _manifest_dict()
    proof = _proof_for(data, 1)
    proof["siblings"][0]["hash"] = "f" * 64
    manifest = load_manifest_from_dict(data)
    claim = check_event_binding(manifest, proof=proof)
    assert claim.status == STATUS_FAILED
    assert claim.evidence["proof_binding"]["path_reconstructs_root"] is False


def test_r2_proof_for_the_wrong_event_is_rejected():
    data = _manifest_dict()
    manifest = load_manifest_from_dict(data)
    claim = check_event_binding(
        manifest, proof=_proof_for(data, 1), target_event_id="evt-0003"
    )
    assert claim.status == STATUS_FAILED


# ---------------------------------------------------------------------------
# R2 — payload
# ---------------------------------------------------------------------------


def test_r2_payload_unchecked_without_bytes():
    manifest = load_manifest_from_dict(_manifest_dict())
    assert check_payload_binding(manifest, None).status == STATUS_NOT_CHECKED


def test_r2_payload_bytes_are_compared_against_the_commitment():
    import hashlib

    from wakir_verify.merkle_proof import _canonicalise

    payload = {"amount": 10, "currency": "EUR"}
    payload_hash = hashlib.sha256(_canonicalise(payload)).hexdigest()

    data = _manifest_dict()
    data["leaves"][0]["payload_hash"] = payload_hash
    data["leaves"][0]["leaf_hash"] = compute_leaf_hash(
        data["leaves"][0]["event_id"],
        data["leaves"][0]["time"],
        payload_hash,
        data["leaves"][0]["capability_token_hash"],
    ).hex()
    data["events"] = data["leaves"]
    manifest = load_manifest_from_dict(data)

    good = check_payload_binding(
        manifest, {"evt-0000": json.dumps(payload).encode()}
    )
    assert good.status == STATUS_OK
    assert good.evidence["payloads"][0]["mode"] == "jcs"

    bad = check_payload_binding(
        manifest, {"evt-0000": json.dumps({"amount": 11}).encode()}
    )
    assert bad.status == STATUS_FAILED


# ---------------------------------------------------------------------------
# CLI-level: the report must not overstate
# ---------------------------------------------------------------------------


def test_cli_reports_not_checked_rather_than_verified(tmp_path, capsys):
    """End to end: a manifest with no receipt earns exit 4, not 0."""
    from wakir_verify.cli import main as cli_main

    data = _manifest_dict()
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps(data))

    rc = cli_main(["--manifest", str(manifest_path)])
    body = json.loads(capsys.readouterr().out)

    assert rc == 4
    assert body["overall_status"] == "not_checked"
    statuses = {c["claim"]: c["status"] for c in body["claims"]}
    assert statuses["hashlist_consistency"] == STATUS_OK
    assert statuses["event_binding"] == STATUS_OK
    assert statuses["payload_check"] == STATUS_NOT_CHECKED
    assert statuses["root_authenticity"] == STATUS_NOT_CHECKED


def test_cli_refuses_to_choose_between_two_roots(tmp_path):
    from wakir_verify.cli import main as cli_main

    data = _manifest_dict()
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps(data))

    with pytest.raises(SystemExit) as excinfo:
        cli_main(["--manifest", str(manifest_path), "--anchor", ANCHOR_A])
    assert excinfo.value.code == 2
