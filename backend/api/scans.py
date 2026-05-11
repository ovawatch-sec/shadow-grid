"""Scan management + SSE progress stream."""
from __future__ import annotations
import asyncio
import json
from fastapi import APIRouter, HTTPException, BackgroundTasks
from fastapi.responses import StreamingResponse
from models import Scan, ScanCreate, ScanStatus

router = APIRouter(prefix="/scans", tags=["scans"])


def _get_storage():
    from main import storage
    return storage


def _get_settings():
    from config import settings
    return settings


@router.post("/", status_code=201)
async def create_scan(body: ScanCreate, background_tasks: BackgroundTasks):
    storage = _get_storage()
    settings = _get_settings()

    # Validate project exists
    project = await storage.get_project(body.project_id)
    if not project:
        raise HTTPException(404, "Project not found")

    # Load targets
    targets = await storage.list_targets(body.project_id)
    in_scope = [t.domain for t in targets if not t.is_oos]
    oos      = [t.domain for t in targets if t.is_oos]

    if not in_scope:
        raise HTTPException(400, "No in-scope targets defined for this project")

    scan = Scan(project_id=body.project_id, tools=body.tools, wordlist=body.wordlist)
    await storage.save_scan(scan)

    # Update project scan count
    project.scan_count += 1
    await storage.save_project(project)

    from scan_engine import run_scan
    from pathlib import Path

    background_tasks.add_task(
        run_scan,
        scan=scan,
        domains=in_scope,
        oos=oos,
        output_dir=Path(settings.output_dir),
        data_dir=Path(settings.data_dir),
        storage=storage,
    )

    return scan


@router.get("/{project_id}/list")
async def list_scans(project_id: str):
    return await _get_storage().list_scans(project_id)


@router.get("/{scan_id}")
async def get_scan(scan_id: str):
    s = await _get_storage().get_scan(scan_id)
    if not s:
        raise HTTPException(404, "Scan not found")
    return s


@router.delete("/{scan_id}", status_code=204)
async def cancel_scan(scan_id: str):
    s = await _get_storage().get_scan(scan_id)
    if s and s.status == ScanStatus.RUNNING:
        s.status = ScanStatus.CANCELLED
        await _get_storage().save_scan(s)


@router.get("/{scan_id}/progress")
async def scan_progress_stream(scan_id: str):
    """SSE endpoint — streams scan progress events as JSON lines."""
    from scan_engine import get_progress_queue

    async def event_generator():
        q = get_progress_queue(scan_id)
        # Check if scan is already done
        s = await _get_storage().get_scan(scan_id)
        if s and s.status in (ScanStatus.COMPLETED, ScanStatus.FAILED, ScanStatus.CANCELLED):
            yield f"data: {json.dumps({'tool': '__scan__', 'status': s.status.value})}\n\n"
            return

        timeout_counter = 0
        while True:
            try:
                event = await asyncio.wait_for(q.get(), timeout=30)
                yield f"data: {json.dumps(event)}\n\n"
                if event.get("tool") == "__scan__" and event.get("status") in ("done", "failed"):
                    break
            except asyncio.TimeoutError:
                yield 'data: {"heartbeat":true}\n\n'
                timeout_counter += 1
                if timeout_counter > 20:  # 10 min with no events → stop
                    break

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )
