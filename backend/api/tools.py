"""Tool metadata endpoint."""
from fastapi import APIRouter
from tools.registry import list_tools
import shutil

router = APIRouter(prefix="/tools", tags=["tools"])

@router.get("/")
async def get_tools():
    tools = list_tools()
    for t in tools:
        t["available"] = shutil.which(t["name"]) is not None or t["name"] == "crtsh"
    return tools
