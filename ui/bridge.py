import asyncio

class VibeBridge:
    def __init__(self, scanner, exploits, update_ui_func):
        self.scanner = scanner
        self.exploits = exploits
        self.update_ui = update_ui_func

    async def perform_full_audit(self, target):
        scan_results = await asyncio.to_thread(self.scanner.scan_hosts, target)
        
        for host in scan_results:
            for port in host['ports']:
                service = port['service']
                if service:
                    ex_results = await asyncio.to_thread(self.exploits.search, service)
                    port['exploits'] = ex_results
        
        await self.update_ui(scan_results)