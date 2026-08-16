#!/usr/bin/env python3
"""
Simple WebSocket test script for passkey proxy
Creates a test WebSocket echo server and verifies basic connectivity
"""

from aiohttp import web


async def websocket_echo_handler(request):
    """Simple WebSocket echo server for testing"""
    ws = web.WebSocketResponse()
    await ws.prepare(request)

    print("WebSocket client connected")
    print(f"Headers received: {dict(request.headers)}")

    async for msg in ws:
        if msg.type == web.WSMsgType.TEXT:
            print(f"Received: {msg.data}")
            # Echo back the message
            await ws.send_str(f"Echo: {msg.data}")
        elif msg.type == web.WSMsgType.BINARY:
            print(f"Received binary data: {len(msg.data)} bytes")
            await ws.send_bytes(msg.data)
        elif msg.type == web.WSMsgType.CLOSE:
            print("Client closed connection")
            break

    return ws


def create_test_app():
    """Create test WebSocket server"""
    app = web.Application()
    app.router.add_get("/ws", websocket_echo_handler)
    app.router.add_get("/test/ws", websocket_echo_handler)
    return app


if __name__ == "__main__":
    print("Starting WebSocket echo test server on localhost:3000")
    print("Test endpoints:")
    print("  - ws://localhost:3000/ws")
    print("  - ws://localhost:3000/test/ws")
    print("\nThis server echoes back any WebSocket messages it receives.")
    print("Use this to test the passkey proxy WebSocket forwarding.\n")

    app = create_test_app()
    web.run_app(app, host="localhost", port=3000, print=None)
