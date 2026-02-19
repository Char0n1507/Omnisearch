import argparse
import asyncio
import sys
import os
from modules.passive import PassiveRecon
from modules.active import ActiveRecon

BANNER = """
   ____  ____ ___  ____  _ _____ __________  ____  ___ 
  / __ \/ __ `__ \/ __ \/ / ___/ ___/ __ \/ __ \/ _ \\
 / /_/ / / / / / / / / / (__  ) /__/ /_/ / /_/ /  __/
 \____/_/ /_/ /_/_/ /_/_/____/\___/\____/ .___/\___/ 
                                       /_/           
      -- The All-Seeing Subdomain Enumerator --
"""

async def main():
    print(BANNER)
    parser = argparse.ArgumentParser(description="OmniScope: Advanced Subdomain Enumeration Tool")
    parser.add_argument("-d", "--domain", required=True, help="Target domain (e.g., example.com)")
    parser.add_argument("-w", "--wordlist", help="Path to wordlist for brute forcing", default="wordlists/subdomains.txt")
    parser.add_argument("-o", "--output", help="Output file for results", default="results.txt")
    
    args = parser.parse_args()
    
    domain = args.domain
    # Sanitize domain input
    if domain.startswith("http://"):
        domain = domain[7:]
    if domain.startswith("https://"):
        domain = domain[8:]
    if domain.startswith("www."):
        domain = domain[4:]
    if domain.endswith("/"):
        domain = domain[:-1]
        
    print(f"[*] Target set to: {domain}")
    
    # 1. Passive Recon
    print("\n[+] Starting Passive Reconnaissance...")
    passive_recon = PassiveRecon(domain)
    # We await directly since we are in an async function
    passive_subdomains = await passive_recon.run()
    
    print(f"    -> Found {len(passive_subdomains)} unique subdomains from passive sources.")
    
    # 2. Active Validation & Discovery
    print("\n[+] Starting Active Validation & Brute-forcing...")
    active_recon = ActiveRecon(domain, passive_subdomains, args.wordlist)
    live_subdomains = await active_recon.run()
    
    # 3. Web Probing
    web_results = await active_recon.probe_domains()
    
    print(f"\n[!] Total Live Subdomains Found: {len(live_subdomains)}")
    
    # 4. Visual Reconnaissance (Aquatone)
    web_urls = [res['url'] for res in web_results if res.get('url')]
    if web_urls:
        print(f"\n[+] Starting Visual Reconnaissance (Aquatone)...")
        aquatone_dir = os.path.join(os.getcwd(), "aquatone_report")
        if not os.path.exists(aquatone_dir):
            os.makedirs(aquatone_dir)
            
        print(f"    -> Taking screenshots of {len(web_urls)} active web services...")
        aquatone_path = os.path.expanduser("~/go/bin/aquatone")
        
        if os.path.exists(aquatone_path):
            try:
                # Prepare URLs
                input_urls = "\n".join(web_urls).encode()
                
                # Aquatone needs to read from stdin
                process = await asyncio.create_subprocess_exec(
                    aquatone_path,
                    "-out", aquatone_dir,
                    "-threads", "5",
                    "-silent",
                    stdin=asyncio.subprocess.PIPE,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                
                # Send URLs to stdin
                await process.communicate(input=input_urls)
                
                print(f"    -> Aquatone finished! Report saved to: {aquatone_dir}/aquatone_report.html")
            except Exception as e:
                print(f"    [!] Error running Aquatone: {e}")
        else:
             print(f"    [!] Aquatone not found at {aquatone_path}. To use it, install it: go install github.com/michenriksen/aquatone@latest")

    else:
         print("    -> No active web services found for visual recon.")
    
    # Save results
    with open(args.output, "w") as f:
        for sub in live_subdomains:
            f.write(f"{sub}\n")
    print(f"[*] Text results saved to {args.output}")
    
    # Generate HTML Report
    generate_html_report(domain, web_results)

def generate_html_report(domain, results):
    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>OmniScope Report: {domain}</title>
        <style>
            body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #f4f4f9; color: #333; margin: 0; padding: 20px; }}
            h1 {{ color: #4a4e69; text-align: center; }}
            .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }}
            table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
            th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
            th {{ background-color: #22223b; color: white; }}
            tr:hover {{ background-color: #f1f1f1; }}
            .status-200 {{ color: green; font-weight: bold; }}
            .status-403, .status-401 {{ color: orange; font-weight: bold; }}
            .status-404 {{ color: red; font-weight: bold; }}
            .status-500 {{ color: darkred; font-weight: bold; }}
            a {{ color: #4a4e69; text-decoration: none; }}
            a:hover {{ text-decoration: underline; }}
            .summary {{ display: flex; justify-content: space-around; margin-bottom: 20px; background: #c9ada7; padding: 15px; border-radius: 5px; }}
            .summary-item {{ text-align: center; color: #22223b; font-weight: bold; }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>OmniScope Recon Report: {domain}</h1>
            
            <div class="summary">
                <div class="summary-item">Total Subdomains: {len(results)}</div>
            </div>

            <table>
                <thead>
                    <tr>
                        <th>Domain</th>
                        <th>URL</th>
                        <th>IP Address</th>
                        <th>Status</th>
                        <th>Page Title</th>
                        <th>Server</th>
                    </tr>
                </thead>
                <tbody>
    """
    
    for res in results:
        status_class = f"status-{res['status']}"
        server = res.get('server', 'Unknown')
        
        # Handle cases where elements might be missing
        dom = res.get('domain', 'N/A')
        url = res.get('url', '#')
        ip = res.get('ip', 'N/A')
        status = res.get('status', 'N/A')
        title = res.get('title', 'N/A')
        
        html_content += f"""
                    <tr>
                        <td>{dom}</td>
                        <td><a href="{url}" target="_blank">{url}</a></td>
                        <td>{ip}</td>
                        <td class="{status_class}">{status}</td>
                        <td>{title}</td>
                        <td>{server}</td>
                    </tr>
        """
        
    html_content += """
                </tbody>
            </table>
        </div>
    </body>
    </html>
    """
    
    with open("report.html", "w") as f:
        f.write(html_content)
    print(f"[*] HTML Report generated: report.html")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user. Exiting...")
        sys.exit(0)
