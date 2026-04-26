"""
Unit tests for relay.server module
"""

import pytest
import asyncio

from relay.server import (
    BlindRelayServer,
    RelayError,
    RateLimitExceededError
)


class TestBlindRelayServer:
    """Tests for BlindRelayServer"""

    def test_server_initialization(self):
        """Test server initialization with valid token"""
        token = "test_token_12345678"
        server = BlindRelayServer(token)
        
        assert server.token == token
        assert len(server.clients) == 0
        assert server.max_clients == 100
        assert server.healthy is True

    def test_server_initialization_empty_token(self):
        """Test server initialization with empty token raises error"""
        with pytest.raises(ValueError, match="Token cannot be empty"):
            BlindRelayServer("")

    def test_health_check(self):
        """Test health check returns expected metrics"""
        token = "test_token"
        server = BlindRelayServer(token)
        
        health = server.health_check()
        
        assert health["healthy"] is True
        assert health["clients"] == 0
        assert health["relayed_packets"] == 0
        assert "uptime_seconds" in health
        assert "last_health_check" in health

    def test_check_rate_limit_new_client(self):
        """Test rate limiting for new client"""
        token = "test_token"
        server = BlindRelayServer(token)
        
        # New client should pass rate limit
        result = server.check_rate_limit("client1")
        assert result is True

    def test_check_rate_limit_exceeded(self):
        """Test rate limiting when exceeded"""
        token = "test_token"
        server = BlindRelayServer(token)
        server.rate_limit_max = 5
        
        client_id = "client1"
        
        # Record messages up to limit
        for _ in range(5):
            server.record_message(client_id)
        
        # Next message should exceed limit
        with pytest.raises(RateLimitExceededError, match="Rate limit exceeded"):
            server.check_rate_limit(client_id)

    def test_record_message(self):
        """Test recording messages for rate limiting"""
        token = "test_token"
        server = BlindRelayServer(token)
        
        client_id = "client1"
        server.record_message(client_id)
        
        assert client_id in server.rate_limits
        assert len(server.rate_limits[client_id]) == 1


class TestUtilityFunctions:
    """Tests for utility functions"""

    def test_now_function(self):
        """Test now function returns timestamp"""
        from relay.server import now
        
        timestamp = now()
        
        assert isinstance(timestamp, int)
        assert timestamp > 0

    def test_ws_send_json_valid(self):
        """Test WebSocket JSON send with valid data"""
        from relay.server import ws_send_json
        import json
        
        # Mock WebSocket
        class MockWS:
            def __init__(self):
                self.sent = []
            
            async def send(self, data):
                self.sent.append(data)
        
        async def test():
            ws = MockWS()
            data = {"test": "data"}
            
            await ws_send_json(ws, data)
            
            assert len(ws.sent) == 1
            assert json.loads(ws.sent[0]) == data
        
        asyncio.run(test())

    def test_ws_send_json_empty(self):
        """Test WebSocket JSON send with empty data raises error"""
        from relay.server import ws_send_json
        
        async def test():
            ws = None
            with pytest.raises(ValueError, match="Data cannot be empty"):
                await ws_send_json(ws, {})
        
        asyncio.run(test())


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
