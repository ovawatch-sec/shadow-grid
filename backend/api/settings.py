"""Storage configuration management."""
from __future__ import annotations
from fastapi import APIRouter
from models import StorageConfig

router = APIRouter(prefix="/settings", tags=["settings"])


def _get_storage():
    from main import storage
    return storage


@router.get("/storage")
async def get_storage_config():
    cfg = await _get_storage().load_storage_config()
    # Never return the actual key
    if "azure_account_key" in cfg:
        cfg["azure_account_key"] = "••••••••" if cfg["azure_account_key"] else ""
    return cfg


@router.post("/storage")
async def save_storage_config(body: StorageConfig):
    storage = _get_storage()
    cfg = body.model_dump()
    await storage.save_storage_config(cfg)
    if body.azure_enabled:
        storage.enable_azure(
            conn_str=body.connection_string,
            account=body.account_name,
            key=body.account_key,
            prefix=body.table_prefix,
        )
    return {"ok": True}
