import asyncio
import time

from aiohttp import ClientSession, ClientTimeout, web

from lib.logger import logger
from lib.util import get_client_ip, get_origin, get_target_host


async def handle_websocket_proxy(request: web.Request) -> web.WebSocketResponse:
    """Proxy WebSocket connections to target application"""
    # Get authenticated username
    username = request.get("authenticated_user", "unknown")
    client_ip = get_client_ip(request)
    start_time = time.time()

    # DEBUG logging for WebSocket connection opened
    logger.debug(f"WebSocket opened: {username} -> {request.path} from {client_ip}")

    # Accept WebSocket connection from client
    client_ws = web.WebSocketResponse()
    await client_ws.prepare(request)

    target = get_target_host(request)
    if not target:
        logger.error(f"No target found for host {get_origin(request)}")
        return web.Response(text="Bad Gateway", status=502)

    # Build target WebSocket URL
    target_ws_url = f"ws://{target['TARGET']}{request.path_qs}"

    # Prepare headers for backend connection
    headers = {
        target["AUTH_HEADER"]: username,
        "X-Forwarded-For": request.remote or "unknown",
        "X-Forwarded-Proto": request.headers.get("X-Forwarded-Proto", "http"),
    }

    # Copy other headers that might be relevant
    for key, value in request.headers.items():
        if key.lower() not in [
            "host",
            "connection",
            "upgrade",
            "sec-websocket-key",
            "sec-websocket-version",
            "sec-websocket-extensions",
        ]:
            headers[key] = value

    backend_ws = None
    try:
        # Connect to backend WebSocket
        timeout = ClientTimeout(total=60)
        async with ClientSession(timeout=timeout) as session:
            backend_ws = await session.ws_connect(target_ws_url, headers=headers)

            # Create tasks for bidirectional forwarding
            async def forward_client_to_backend():
                """Forward messages from client to backend"""
                try:
                    async for msg in client_ws:
                        if msg.type == web.WSMsgType.TEXT:
                            await backend_ws.send_str(msg.data)
                        elif msg.type == web.WSMsgType.BINARY:
                            await backend_ws.send_bytes(msg.data)
                        elif msg.type == web.WSMsgType.CLOSE:
                            await backend_ws.close()
                            break
                        elif msg.type == web.WSMsgType.ERROR:
                            logger.error(
                                f"WebSocket client error: {client_ws.exception()}"
                            )
                            break
                except Exception as e:
                    logger.error(f"Error forwarding client to backend: {e}")

            async def forward_backend_to_client():
                """Forward messages from backend to client"""
                try:
                    async for msg in backend_ws:
                        if msg.type == web.WSMsgType.TEXT:
                            await client_ws.send_str(msg.data)
                        elif msg.type == web.WSMsgType.BINARY:
                            await client_ws.send_bytes(msg.data)
                        elif msg.type == web.WSMsgType.CLOSE:
                            await client_ws.close()
                            break
                        elif msg.type == web.WSMsgType.ERROR:
                            logger.error(
                                f"WebSocket backend error: {backend_ws.exception()}"
                            )
                            break
                except Exception as e:
                    logger.error(f"Error forwarding backend to client: {e}")

            # Run both forwarding tasks concurrently
            await asyncio.gather(
                forward_client_to_backend(),
                forward_backend_to_client(),
                return_exceptions=True,
            )

    except Exception as e:
        logger.error(f"WebSocket proxy error: {e}")
    finally:
        # Cleanup connections
        if backend_ws and not backend_ws.closed:
            await backend_ws.close()
        if not client_ws.closed:
            await client_ws.close()

        # DEBUG logging for WebSocket connection closed
        duration = int(time.time() - start_time)
        logger.debug(
            f"WebSocket closed: {username} from {client_ip} (duration: {duration}s)"
        )

    return client_ws


async def handle_proxy(request: web.Request) -> web.Response:
    """Proxy requests to target application"""
    try:
        # Detect WebSocket upgrade requests
        if (
            request.headers.get("Upgrade", "").lower() == "websocket"
            and "upgrade" in request.headers.get("Connection", "").lower()
        ):
            return await handle_websocket_proxy(request)

        target = get_target_host(request)
        if not target:
            logger.error(f"No target found for host {get_origin(request)}")
            return web.Response(text="Bad Gateway", status=502)

        # Build target URL
        target_url = f"http://{target['TARGET']}{request.path_qs}"

        # Get authenticated username
        username = request.get("authenticated_user", "unknown")
        client_ip = get_client_ip(request)

        # DEBUG logging for proxy requests
        logger.debug(
            f"Proxy: {username} {request.method} {request.path} from {client_ip}"
        )

        # Prepare headers
        headers = dict(request.headers)
        headers[target["AUTH_HEADER"]] = username
        headers["X-Forwarded-For"] = request.remote
        headers["X-Forwarded-Proto"] = request.headers.get("X-Forwarded-Proto", "http")

        # Remove hop-by-hop headers
        for header in [
            "Host",
            "Connection",
            "Keep-Alive",
            "Proxy-Authenticate",
            "Proxy-Authorization",
            "TE",
            "Trailers",
            "Transfer-Encoding",
            "Upgrade",
        ]:
            headers.pop(header, None)

        # Make request to target
        timeout = ClientTimeout(total=60)
        async with (
            ClientSession(timeout=timeout) as session,
            session.request(
                method=request.method,
                url=target_url,
                headers=headers,
                data=await request.read(),
                allow_redirects=False,
                auto_decompress=False,  # Don't auto-decompress, let browser handle it
            ) as resp,
        ):
            # Create streaming response
            response = web.StreamResponse(status=resp.status, headers=resp.headers)

            # Remove problematic headers
            response.headers.pop("Transfer-Encoding", None)

            # Prepare response
            await response.prepare(request)

            # Stream content from target to client
            async for chunk in resp.content.iter_any():
                await response.write(chunk)

            await response.write_eof()
            return response

    except Exception as e:
        logger.error(f"Proxy error: {e}")
        return web.Response(text="Bad Gateway", status=502)
