import asyncio
import os
import sys
import time

# Add current directory to path so we can import app modules
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app.database.client import init_db
from app.core.config import get_settings

# Change flow timeout to 2 seconds for fast testing
settings = get_settings()
settings.FLOW_TIMEOUT_SECONDS = 2
settings.FLOW_CLEANUP_INTERVAL = 1

from app.services.packet_capture.capture_service import init_capture_service
from app.schemas.flow import ParsedPacket

async def main():
    await init_db()
    service = init_capture_service()
    
    # We will simulate 50 packets for an HTTP flow
    print("Simulating 50 packets into the pipeline...")
    
    for i in range(50):
        packet = ParsedPacket(
            id=f"sim-pkt-{i}",
            timestamp=time.time(),
            src_ip="192.168.0.50",
            dst_ip="8.8.8.8",
            src_port=50000,
            dst_port=80,
            protocol="HTTP",
            packet_length=1500,
            info=f"GET / HTTP/1.1 (Simulated packet {i})"
        )
        service.flow_manager.add_packet(packet)
        service._packets_captured += 1
        await asyncio.sleep(0.01)
        
    print(f"Added 50 packets. Packets captured: {service._packets_captured}")
    print(f"Active flows: {service.flow_manager.stats['active_flows']}")
    
    # Wait for the flow to timeout so it gets finalized and sent to DB
    print("Waiting for flow to timeout (3s) so it finalizes and extracts features...")
    await asyncio.sleep(3)
    
    # Run the cleanup loop manually once to finalize
    service.flow_manager._cleanup_expired()
    # Wait for the async task created by finalize to complete
    await asyncio.sleep(2)
    
    print("Flow finalized. Stats:")
    print(service.get_status())
    
if __name__ == "__main__":
    asyncio.run(main())
