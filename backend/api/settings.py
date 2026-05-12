"""Storage and tool API key configuration management."""
from __future__ import annotations
from fastapi import APIRouter

from models import StorageConfig, ToolApiKeysConfig
from tool_secrets import apply_tool_api_keys, mask_tool_api_keys, merge_tool_api_keys

router = APIRouter(prefix="/settings", tags=["settings"])


def _get_storage():
    from main import storage
    return storage


@router.get("/storage")
async def get_storage_config():
    cfg = await _get_storage().load_storage_config()
    # Never return the actual storage account key.
    if "account_key" in cfg:
        cfg["account_key"] = "••••••••" if cfg["account_key"] else ""
    if "azure_account_key" in cfg:
        cfg["azure_account_key"] = "••••••••" if cfg["azure_account_key"] else ""
    return cfg


@router.post("/storage")
async def save_storage_config(body: StorageConfig):
    storage = _get_storage()
    existing = await storage.load_storage_config()
    cfg = body.model_dump()

    # Keep existing secret if UI sends blank/masked password field.
    existing_key = existing.get("account_key") or existing.get("azure_account_key") or ""
    if not cfg.get("account_key") or cfg.get("account_key") == "••••••••":
        cfg["account_key"] = existing_key

    await storage.save_storage_config(cfg)
    if body.azure_enabled:
        storage.enable_azure(
            conn_str=cfg.get("connection_string", ""),
            account=cfg.get("account_name", ""),
            key=cfg.get("account_key", ""),
            prefix=cfg.get("table_prefix", "shadowgrid"),
        )
    return {"ok": True}


@router.get("/api-keys")
async def get_tool_api_keys():
    cfg = await _get_storage().load_tool_api_keys()
    return mask_tool_api_keys(cfg)


@router.post("/api-keys")
async def save_tool_api_keys(body: ToolApiKeysConfig):
    storage = _get_storage()
    existing = await storage.load_tool_api_keys()
    cfg = merge_tool_api_keys(existing, body.model_dump())
    await storage.save_tool_api_keys(cfg)
    apply_tool_api_keys(cfg)
    return {"ok": True}
