import aiohttp
import asyncio
import json
import os

class PassiveRecon:
    def __init__(self, domain):
        self.domain = domain
        self.subdomains = set()
        
    async def run(self):
        # Run all passive checks concurrently
        tasks = [
            self.check_crtsh(),
            self.check_hackertarget(),
            # self.check_wayback(), # Covered by Subfinder and can be slow
            self.check_alienvault(),
            self.check_anubis(),
            self.check_threatminer(),
            self.check_subfinder(),
            # self.check_amass() # Disabled due to hanging issues
        ]
        await asyncio.gather(*tasks)
        return self.subdomains

    async def check_subfinder(self):
        subfinder_path = os.path.expanduser("~/go/bin/subfinder")
        if not os.path.exists(subfinder_path):
            return

        print(f"    -> Running Subfinder...")
        try:
            process = await asyncio.create_subprocess_exec(
                subfinder_path,
                "-d", self.domain,
                "-silent",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await process.communicate()
            if stdout:
                for line in stdout.decode().splitlines():
                    sub = line.strip()
                    if sub and self.domain in sub:
                         self.subdomains.add(sub.lower())
        except Exception as e:
            print(f"    [!] Error running Subfinder: {e}")

    async def check_amass(self):
        amass_path = os.path.expanduser("~/go/bin/amass")
        if not os.path.exists(amass_path):
            return

        print(f"    -> Running Amass (Passive Mode)...")
        try:
            # Amass enum -passive -d domain -silent
            process = await asyncio.create_subprocess_exec(
                amass_path, "enum", "-passive", "-d", self.domain, "-silent",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            # Read stdout line by line to show progress
            while True:
                line = await process.stdout.readline()
                if not line:
                    break
                
                sub = line.decode().strip()
                if sub and self.domain in sub:
                     self.subdomains.add(sub.lower())

            await process.wait()
        except Exception as e:
            print(f"    [!] Error running Amass: {e}")

    async def check_crtsh(self):
        print(f"    -> Querying crt.sh...")
        url = f"https://crt.sh/?q=%25.{self.domain}&output=json"
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=20) as response:
                    if response.status == 200:
                        data = await response.json()
                        for entry in data:
                            name_value = entry['name_value']
                            for sub in name_value.split('\n'):
                                if self.domain in sub:
                                    self.subdomains.add(sub.strip().lower())
        except Exception as e:
            # print(f"    [!] Error querying crt.sh: {e}")
            pass

    async def check_hackertarget(self):
        print(f"    -> Querying HackerTarget...")
        url = f"https://api.hackertarget.com/hostsearch/?q={self.domain}"
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=20) as response:
                    if response.status == 200:
                        text = await response.text()
                        lines = text.split('\n')
                        for line in lines:
                            if ',' in line:
                                sub = line.split(',')[0]
                                if self.domain in sub:
                                    self.subdomains.add(sub.strip().lower())
        except Exception as e:
            print(f"    [!] Error querying HackerTarget: {e}")

    async def check_wayback(self):
        print(f"    -> Querying Wayback Machine...")
        url = f"http://web.archive.org/cdx/search/cdx?url=*.{self.domain}/*&output=json&collapse=urlkey"
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=30) as response:
                    if response.status == 200:
                        try:
                            data = await response.json()
                            if len(data) > 1:
                                for row in data[1:]:
                                    original_url = row[2]
                                    if not original_url.startswith(('http://', 'https://')):
                                        original_url = "http://" + original_url
                                    try:
                                        from urllib.parse import urlparse
                                        parsed = urlparse(original_url)
                                        if self.domain in parsed.netloc:
                                            self.subdomains.add(parsed.netloc.strip().lower())
                                    except:
                                        pass
                        except json.JSONDecodeError:
                            pass # sometimes wayback returns raw html on error
        except Exception as e:
            print(f"    [!] Error querying Wayback Machine: {e}")

    async def check_alienvault(self):
        print(f"    -> Querying AlienVault OTX...")
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{self.domain}/url_list?limit=100&page=1"
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=20) as response:
                    if response.status == 200:
                        data = await response.json()
                        if 'url_list' in data:
                            for entry in data['url_list']:
                                hostname = entry.get('hostname')
                                if hostname and self.domain in hostname:
                                    self.subdomains.add(hostname.strip().lower())
        except Exception as e:
            print(f"    [!] Error querying AlienVault: {e}")

    async def check_anubis(self):
        print(f"    -> Querying Anubis...")
        url = f"https://jldc.me/anubis/subdomains/{self.domain}"
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=20) as response:
                    if response.status == 200:
                        data = await response.json()
                        for sub in data:
                            if self.domain in sub:
                                self.subdomains.add(sub.strip().lower())
        except Exception as e:
            print(f"    [!] Error querying Anubis: {e}")

    async def check_threatminer(self):
        print(f"    -> Querying ThreatMiner...")
        url = f"https://api.threatminer.org/v2/domain.php?q={self.domain}&rt=5"
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=20) as response:
                    if response.status == 200:
                        data = await response.json()
                        if 'results' in data and data['results']:
                            for sub in data['results']:
                                if self.domain in sub:
                                    self.subdomains.add(sub.strip().lower())
        except Exception as e:
            # ThreatMiner often has issues or is slow
            pass
