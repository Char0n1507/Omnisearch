import aiohttp
import asyncio
import socket
import dns.resolver
import dns.asyncresolver
import httpx

class ActiveRecon:
    def __init__(self, domain, passive_subs, wordlist_path):
        self.domain = domain
        self.found_subdomains = passive_subs
        self.wordlist_path = wordlist_path
        self.live_subdomains = set()
        self.resolver = dns.asyncresolver.Resolver()
        self.resolver.nameservers = ['8.8.8.8', '1.1.1.1'] # Google and Cloudflare DNS
        self.resolver.timeout = 2.0
        self.resolver.lifetime = 2.0
        self.wildcard_ips = set()

    async def run(self):
        # 0. Check for Wildcard
        await self.check_wildcard()

        # 1. Validate Passive Results
        print(f"    -> Verifying {len(self.found_subdomains)} passive subdomains...")
        await self.verify_subdomains(list(self.found_subdomains))
        
        # 2. DNS Brute Force
        print(f"    -> Starting DNS Brute-force...")
        await self.brute_force()
        
        return list(self.live_subdomains)

    async def probe_domains(self):
        """Checks for pending HTTP/S services on the live subdomains"""
        total = len(self.live_subdomains)
        print(f"    -> Probing {total} live domains for HTTP/S...")
        probed_results = []
        
        # Process in chunks
        chunk_size = 100 
        live_list = list(self.live_subdomains)
        processed = 0
        
        for i in range(0, total, chunk_size):
            chunk = live_list[i:i + chunk_size]
            tasks = [self.probe_single(sub) for sub in chunk]
            batch_results = await asyncio.gather(*tasks)
            # filter out None
            probed_results.extend([r for r in batch_results if r])
            processed += len(chunk)
            print(f"       -> Probed {processed}/{total} domains...", end='\r')
        print(f"       -> Probing complete. Found {len(probed_results)} web services.    ")
            
        return probed_results

    async def probe_single(self, domain):
        """Probes a single domain for http and https using httpx"""
        protocols = ['https://', 'http://']
        
        for p in protocols:
            url = f"{p}{domain}"
            try:
                # Reduced timeout for speed
                async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=10.0) as client:
                    resp = await client.get(url)
                    
                    # Extract title
                    title = "N/A"
                    if '<title>' in resp.text.lower():
                        start = resp.text.lower().find('<title>') + 7
                        end = resp.text.lower().find('</title>', start)
                        if end != -1:
                            title = resp.text[start:end].strip()[:50]
                    
                    # Extract Server header
                    server = resp.headers.get("Server", "Unknown")
                    
                    return {
                        "domain": domain,
                        "url": url,
                        "status": resp.status_code,
                        "title": title,
                        "server": server,
                        "ip": self.resolve_ip_sync(domain)
                    }
            except:
                continue
        return None

    def resolve_ip_sync(self, domain):
        try:
            return socket.gethostbyname(domain)
        except:
            return "N/A"

    async def check_wildcard(self):
        import random
        import string
        rand_sub = ''.join(random.choices(string.ascii_lowercase + string.digits, k=15))
        test_domain = f"{rand_sub}.{self.domain}"
        print(f"    -> Checking for wildcard DNS with {test_domain}...")
        try:
            result = await self.resolver.resolve(test_domain, 'A')
            if result:
                for ip in result:
                    self.wildcard_ips.add(ip.to_text())
                print(f"    [!] Wildcard detected! Filtering IPs: {self.wildcard_ips}")
        except:
            print(f"    -> No wildcard detected.")

    async def verify_subdomains(self, subdomains):
        # Increased chunk size for speed - trying 2000 for faster processing
        chunk_size = 2000
        total = len(subdomains)
        processed = 0
        
        for i in range(0, total, chunk_size):
            chunk = subdomains[i:i + chunk_size]
            tasks = [self.resolve_dns(sub) for sub in chunk]
            await asyncio.gather(*tasks)
            processed += len(chunk)
            print(f"       -> Verified {processed}/{total} subdomains...", end='\r')
        print(f"       -> Verification complete. Found {len(self.live_subdomains)} live targets.    ")

    async def brute_force(self):
        # Load wordlist
        try:
            with open(self.wordlist_path, 'r') as f:
                words = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"    [!] Wordlist not found at {self.wordlist_path}. Skipping brute-force.")
            return

        # Prepare subdomains to check
        to_check = [f"{word}.{self.domain}" for word in words]
        
        # Check in chunks
        chunk_size = 1000
        for i in range(0, len(to_check), chunk_size):
            chunk = to_check[i:i + chunk_size]
            tasks = [self.resolve_dns(sub) for sub in chunk]
            await asyncio.gather(*tasks)
            
        # 3. Permutation Scanning
        print(f"    -> Generating permutations from {len(self.live_subdomains)} live subdomains...")
        permutations = set()
        for sub in list(self.live_subdomains):
            permutations.update(self.generate_permutations(sub))
        
        # Filter out already checked
        permutations = list(permutations - self.live_subdomains)
        if permutations:
            print(f"    -> Checking {len(permutations)} permutations...")
            for i in range(0, len(permutations), chunk_size):
                chunk = permutations[i:i + chunk_size]
                tasks = [self.resolve_dns(sub) for sub in chunk]
                await asyncio.gather(*tasks)

    def generate_permutations(self, subdomain):
        """Minimal permutation logic: add common suffixes/prefixes"""
        perms = set()
        parts = subdomain.split('.')
        if len(parts) < 3: return perms 
        
        sub = parts[0] 
        base = '.'.join(parts[1:]) 
        
        patterns = ['dev', 'test', 'prod', 'stage', 'pre', 'admin', 'v1', 'v2', '2024', '2025']
        
        for p in patterns:
            perms.add(f"{sub}-{p}.{base}")
            perms.add(f"{p}-{sub}.{base}")
            perms.add(f"{sub}{p}.{base}") 
            
        return perms

    async def resolve_dns(self, subdomain):
        try:
            # We try to resolve A record
            result = await self.resolver.resolve(subdomain, 'A')
            if result:
                # Check against wildcard IPs
                should_add = True
                resolved_ips = []
                for ip in result:
                    ip_text = ip.to_text()
                    resolved_ips.append(ip_text)
                    if ip_text in self.wildcard_ips:
                        should_add = False
                        break
                
                if should_add:
                    self.live_subdomains.add(subdomain)
                    # Verbosity controlled by print in async function can be messy, kept minimal
                    # print(f"       [+] Alive: {subdomain} -> {resolved_ips}")
        except:
            pass
