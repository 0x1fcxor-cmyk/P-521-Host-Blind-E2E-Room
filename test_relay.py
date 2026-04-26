import asyncio
import json
import secrets
import websockets
from datetime import datetime

TOKEN = secrets.token_urlsafe(32)
clients = set()

async def handler(websocket, path):
    # Check token from query string
    if "?" in path:
        query = path.split("?")[1]
        params = dict(p.split("=") for p in query.split("&"))
        supplied_token = params.get("token", "")
        if supplied_token != TOKEN:
            print(f"[{datetime.now()}] Invalid token attempt: {supplied_token[:10]}...")
            await websocket.close(1008, "Invalid token")
            return
    
    clients.add(websocket)
    client_id = secrets.token_hex(8)
    print(f"[{datetime.now()}] Client connected: {client_id}")
    
    try:
        # Send welcome message
        await websocket.send(json.dumps({
            "type": "relay_welcome",
            "relay": "blind",
            "protocol": "P521-HOST-BLIND-E2E-V1",
            "client_id": client_id,
            "note": "Test relay server"
        }))
        
        async for message in websocket:
            print(f"[{datetime.now()}] Received from {client_id}: {message[:100]}...")
            
            # Relay to other clients
            for client in clients:
                if client != websocket:
                    try:
                        await client.send(message)
                    except:
                        pass
                        
    except websockets.exceptions.ConnectionClosed:
        print(f"[{datetime.now()}] Client disconnected: {client_id}")
    finally:
        clients.remove(websocket)

async def main():
    print(f"Test Relay Server")
    print(f"Token: {TOKEN}")
    print(f"Relay URL: ws://127.0.0.1:8080?token={TOKEN}")
    print(f"Invite Link: http://127.0.0.1:8080/chat?token={TOKEN}")
    print(f"\nServer starting on ws://127.0.0.1:8080")
    print("Press Ctrl+C to stop\n")
    
    server = await websockets.serve(handler, "127.0.0.1", 8080)
    await server.wait_closed()

if __name__ == "__main__":
    asyncio.run(main())
