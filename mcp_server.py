import hashlib
import os

import mcp.types as types
from mcp.server import Server, ServerRequestContext


EMAIL = "21f3002912@ds.study.iitm.ac.in".strip().lower()


async def handle_list_tools(
    ctx: ServerRequestContext,
    params: types.PaginatedRequestParams | None,
) -> types.ListToolsResult:

    return types.ListToolsResult(
        tools=[
            types.Tool(
                name="solve_challenge",
                description="Solves the current exam challenge.",
                input_schema={
                    "type": "object",
                    "properties": {},
                },
            )
        ]
    )


async def handle_call_tool(
    ctx: ServerRequestContext,
    params: types.CallToolRequestParams,
) -> types.CallToolResult:

    if params.name != "solve_challenge":
        raise ValueError("Unknown tool")

    # Read the challenge from the actual HTTP request headers.
    challenge = ""

    if ctx.request is not None:
        headers = getattr(ctx.request, "headers", {})
        challenge = headers.get("X-Exam-Challenge", "")

    # Required calculation:
    # SHA-256("${challenge}:${normalizedEmail}")
    value = f"{challenge}:{EMAIL}"

    digest = hashlib.sha256(
        value.encode("utf-8")
    ).hexdigest()

    return types.CallToolResult(
        content=[
            types.TextContent(
                type="text",
                text=digest[:16],
            )
        ]
    )


server = Server(
    "exam-mcp-server",
    on_list_tools=handle_list_tools,
    on_call_tool=handle_call_tool,
)


if __name__ == "__main__":
    import uvicorn

    port = int(os.environ.get("PORT", "8000"))

    app = server.streamable_http_app(
        json_response=True
    )

    uvicorn.run(
        app,
        host="0.0.0.0",
        port=port,
    )