"""MCP stdio handshake smoke test: spawns the real server subprocess over
stdio, initializes a client session, and checks the tool list. No target
needed - this only exercises the MCP transport/registration.
"""

import sys

import pytest

pytest.importorskip("mcp")

from mcp import ClientSession  # noqa: E402
from mcp.client.stdio import StdioServerParameters, stdio_client  # noqa: E402

EXPECTED_TOOLS = {
    "debug_connect",
    "debug_disconnect",
    "debug_sessions",
    "debug_registers",
    "debug_set_register",
    "debug_memory",
    "debug_write_memory",
    "debug_break",
    "debug_delete",
    "debug_breakpoints",
    "debug_continue",
    "debug_wait",
    "debug_interrupt",
    "debug_step",
    "debug_backtrace",
    "debug_disassemble",
    "debug_symbol",
    "debug_explain_fault",
}


@pytest.mark.anyio
async def test_stdio_handshake_lists_expected_tools():
    params = StdioServerParameters(command=sys.executable, args=["-m", "gdbstub_mcp"])
    async with stdio_client(params) as (read, write), ClientSession(read, write) as session:
        init_result = await session.initialize()
        assert init_result.server_info.name == "gdbstub"

        tools = await session.list_tools()
        names = {t.name for t in tools.tools}
        assert names == EXPECTED_TOOLS, (
            f"missing: {EXPECTED_TOOLS - names}, unexpected: {names - EXPECTED_TOOLS}"
        )


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.mark.anyio
async def test_instructive_errors_reach_the_agent():
    """MCPServer hides any exception that isn't a ToolError behind a generic
    "Error executing tool X". Our error messages tell the agent what to do
    next, so they must survive the trip over stdio."""
    params = StdioServerParameters(command=sys.executable, args=["-m", "gdbstub_mcp"])
    async with stdio_client(params) as (read, write), ClientSession(read, write) as session:
        await session.initialize()

        result = await session.call_tool("debug_registers", {"name": "nope"})
        assert result.is_error
        text = result.content[0].text
        assert "no debug session named 'nope'" in text and "debug_connect" in text

        result = await session.call_tool("debug_explain_fault", {"log_path": "missing.log"})
        assert result.is_error and "log not found: missing.log" in result.content[0].text

        result = await session.call_tool("debug_symbol", {"query": "x"})
        assert result.is_error and "pass either name=" in result.content[0].text
