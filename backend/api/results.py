"""Results retrieval."""
from __future__ import annotations
from fastapi import APIRouter, HTTPException

router = APIRouter(prefix="/results", tags=["results"])


def _get_storage():
    from main import storage
    return storage


@router.get("/{scan_id}")
async def get_results(scan_id: str):
    return await _get_storage().list_results(scan_id)


@router.get("/{scan_id}/by-category/{category}")
async def get_results_by_category(scan_id: str, category: str):
    results = await _get_storage().list_results(scan_id)
    return [r for r in results if r.category.value == category]


@router.get("/{scan_id}/summary")
async def get_summary(scan_id: str):
    results = await _get_storage().list_results(scan_id)
    summary = {}
    for r in results:
        cat = r.category.value
        summary[cat] = summary.get(cat, 0) + r.count
    return {
        "scan_id": scan_id,
        "totals": summary,
        "tool_count": len(results),
    }
