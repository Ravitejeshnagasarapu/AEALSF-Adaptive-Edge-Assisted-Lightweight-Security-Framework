from __future__ import annotations
from fastapi import APIRouter, Request

router = APIRouter(prefix="/blockchain", tags=["blockchain"])


@router.get("/status")
def get_blockchain_status(request: Request):
    rt = request.app.state.runtime
    bc = rt.blockchain_client
    integrity_ok, integrity_msg = bc.integrity_verifier.verify_chain(bc.chain)
    return {
        "block_height": len(bc.chain) - 1,
        "total_blocks": len(bc.chain),
        "total_committed_transactions": sum(len(b.transactions) for b in bc.chain),
        "chain_integrity_verified": integrity_ok,
        "integrity_message": integrity_msg,
        "contract_addresses": bc.contracts.CONTRACT_ADDRESSES,
        "dvrc_dynamic_threshold": round(
            bc.dvrc.compute_dynamic_consensus_threshold(), 2
        ),
        "validators": [
            p.to_dict() for p in bc.dvrc.profiles.values() if p.role == "VALIDATOR"
        ],
        "recent_blocks": [b.to_dict() for b in bc.chain[-10:]],
    }


@router.get("/reputations")
def get_all_reputations(request: Request):
    rt = request.app.state.runtime
    return {
        "participants": [
            p.to_dict() for p in rt.blockchain_client.dvrc.profiles.values()
        ]
    }
