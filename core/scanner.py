import nmap

class NetworkScanner:
    def __init__(self):
        self.nm = nmap.PortScanner()

    def scan_hosts(self, target, arguments="-T4 -sV -O --osscan-guess"):
        """
        Усложненное сканирование:
        -sV: Определение версий сервисов
        -O: Определение ОС (требует sudo/root)
        """
        
        self.nm.scan(hosts=target, arguments=arguments)
        results = []
        
        for host in self.nm.all_hosts():
            host_data = {
                "host": host,
                "status": self.nm[host].state(),
                "os": "Unknown",
                "ports": []
            }
            
            if 'osmatch' in self.nm[host] and self.nm[host]['osmatch']:
                host_data["os"] = self.nm[host]['osmatch'][0]['name']

            if 'tcp' in self.nm[host]:
                for port, data in self.nm[host]['tcp'].items():
                    host_data["ports"].append({
                        "port": port,
                        "state": data['state'],
                        "service": data['name'],
                        "version": f"{data['product']} {data['version']}".strip(),
                        "extrainfo": data['extrainfo']
                    })
            results.append(host_data)
        return results