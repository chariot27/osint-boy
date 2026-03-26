#!/usr/bin/env python3
import asyncio
import socket
import urllib3
import typer
import shodan
import dns.resolver
import re
import httpx
import json
from datetime import datetime

from textual.app import App, ComposeResult
from textual.containers import Container, Vertical, ScrollableContainer
from textual.widgets import Header, Footer, Static, ListItem, ListView, TabbedContent, TabPane

# Configurações Iniciais
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
SHODAN_API_KEY = "YOUR-SHODAN-API-KEY"

CSS = """
Screen { background: #0a120a; color: #33ff33; }
Header { background: #1a2a1a; color: #33ff33; border-bottom: solid #33ff33; }
Footer { background: #1a2a1a; color: #33ff33; }

#header_box { height: 7; border: double #33ff33; margin: 1 1 0 1; padding: 0 1; }

TabbedContent { margin: 0 1; }
TabPane { padding: 1; border: solid #1a2a1a; height: 1fr; }
Tabs { background: #0d1a0d; color: #33ff33; }

ListView { background: transparent; }
ListItem { padding: 0 1; border-bottom: solid #1a2a1a; }
.critical { color: #ff4444; text-style: bold; }
.section_title { color: black; background: #33ff33; width: 100%; text-align: center; margin: 1 0; text-style: bold; }
.raw_text { color: #88ff88; }
.subdomain_row { color: #33ff33; }

#footer_status { height: 3; border: double #33ff33; margin: 0 1 1 1; content-align: center middle; color: #33ff33; text-style: bold; }
"""

class ReconIntel:
    def __init__(self, domain, ip):
        self.domain = domain
        self.target_ip = ip
        self.shodan_data = {}
        self.dns_records = {}
        self.whois_synthesized = {}
        self.whois_raw_iana = "Aguardando..."
        self.whois_raw_tld = "Aguardando..."
        self.rdap_data = "Nenhuma resposta RDAP disponível"
        self.subdomains = set()

    async def fetch_all(self):
        await asyncio.gather(
            self._get_shodan(),
            self._get_dns(),
            self._get_multi_whois(),
            self._get_rdap(),
            self._get_crt_sh()
        )

    async def _get_shodan(self):
        try:
            api = shodan.Shodan(SHODAN_API_KEY)
            self.shodan_data = await asyncio.to_thread(api.host, self.target_ip)
        except: pass

    async def _get_dns(self):
        for rtype in ["A", "MX", "NS", "TXT", "SOA"]:
            try:
                ans = await asyncio.to_thread(dns.resolver.resolve, self.domain, rtype)
                self.dns_records[rtype] = [str(r) for r in ans]
            except: pass

    async def _get_crt_sh(self):
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                url = f"https://crt.sh/?q={self.domain}&output=json"
                res = await client.get(url)
                if res.status_code == 200:
                    data = res.json()
                    for entry in data:
                        name = entry['common_name']
                        if name.endswith(self.domain):
                            self.subdomains.add(name)
        except: pass

    async def _query_whois_server(self, server, query):
        try:
            def sync_query():
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(5)
                s.connect((server, 43))
                s.send(f"{query}\r\n".encode())
                res = b""
                while True:
                    d = s.recv(4096)
                    if not d: break
                    res += d
                s.close()
                return res.decode("utf-8", "ignore")
            return await asyncio.to_thread(sync_query)
        except: return "Falha na conexão WHOIS."

    async def _get_rdap(self):
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                url = f"https://rdap.org/domain/{self.domain}"
                res = await client.get(url, follow_redirects=True)
                if res.status_code == 200:
                    self.rdap_data = json.dumps(res.json(), indent=4)
        except: pass

    async def _get_multi_whois(self):
        self.whois_raw_iana = await self._query_whois_server("whois.iana.org", self.domain)
        refer = re.search(r"refer:\s+([^\s]+)", self.whois_raw_iana)
        primary_server = refer.group(1) if refer else "whois.verisign-grs.com"
        if self.domain.endswith(".br"): primary_server = "whois.registro.br"
        
        self.whois_raw_tld = await self._query_whois_server(primary_server, self.domain)
        keys = {'owner': 'PROPRIETÁRIO', 'person': 'RESPONSÁVEL', 'e-mail': 'CONTATO', 'registrar': 'REGISTRAR', 'created': 'CRIAÇÃO', 'expires': 'EXPIRAÇÃO'}
        synth = {}
        for line in self.whois_raw_tld.split("\n"):
            if ":" in line and not line.startswith(("%", "#")):
                parts = line.split(":", 1)
                k, v = parts[0].strip().lower(), parts[1].strip()
                for key_match, label in keys.items():
                    if key_match in k and v:
                        if label not in synth: synth[label] = []
                        if v not in synth[label]: synth[label].append(v)
        self.whois_synthesized = synth

class OSINTBoyTerminal(App):
    CSS = CSS
    BINDINGS = [
        ("q", "quit", "SAIR"), 
        ("r", "refresh", "RESCAN"),
        ("e", "export", "EXPORTAR TXT")
    ]

    def __init__(self, domain, ip):
        super().__init__()
        self.intel = ReconIntel(domain, ip)

    def compose(self) -> ComposeResult:
        yield Header()
        with Vertical(id="header_box"):
            yield Static("⚡ OSINT-BOY v1.0 - ADVANCED RECON ⚡")
            yield Static(f"TARGET: {self.intel.domain} | IP: {self.intel.target_ip}")
            yield Static(f"STATUS: AGUARDANDO COMANDOS...")

        with TabbedContent():
            with TabPane("WHOIS HUB"):
                with TabbedContent():
                    with TabPane("SINTETIZADO"):
                        self.whois_list = ListView()
                        yield self.whois_list
                    with TabPane("RDAP"):
                        # FIX DEFINITIVO: markup=False impede erro com colchetes do JSON
                        self.rdap_view = Static("", classes="raw_text", markup=False)
                        yield ScrollableContainer(self.rdap_view)
                    with TabPane("RAW TLD"):
                        # FIX DEFINITIVO: markup=False impede erro com caracteres do Whois
                        self.tld_view = Static("", classes="raw_text", markup=False)
                        yield ScrollableContainer(self.tld_view)
            
            with TabPane("SUBDOMÍNIOS"):
                self.sub_list = ListView()
                yield self.sub_list

            with TabPane("SHODAN"):
                self.shodan_list = ListView()
                yield self.shodan_list

            with TabPane("DNS"):
                self.dns_list = ListView()
                yield self.dns_list

            with TabPane("VULNS"):
                self.vuln_list = ListView()
                yield self.vuln_list

        yield Static("SCAN_COMPLETE | DATA_SECURED", id="footer_status")
        yield Footer()

    async def on_mount(self) -> None:
        await self.intel.fetch_all()
        self.update_ui()

    def update_ui(self):
        # Update Whois Sintetizado
        self.whois_list.clear()
        for label, values in self.intel.whois_synthesized.items():
            self.whois_list.append(ListItem(Static(f"[#66ff66]{label:<15}[/] {' | '.join(values)}")))
        
        # Inserindo dados brutos (agora seguro devido ao markup=False no compose)
        self.rdap_view.update(self.intel.rdap_data)
        self.tld_view.update(self.intel.whois_raw_tld)

        # Update Subdomains
        self.sub_list.clear()
        if not self.intel.subdomains:
            self.sub_list.append(ListItem(Static("NENHUM SUBDOMÍNIO ENCONTRADO NO CRT.SH")))
        for sub in sorted(self.intel.subdomains):
            self.sub_list.append(ListItem(Static(f"󱜙 {sub}", classes="subdomain_row")))

        # Update Shodan
        self.shodan_list.clear()
        d = self.intel.shodan_data
        if d:
            self.shodan_list.append(Static("◢◣ INFRAESTRUTURA", classes="section_title"))
            for s in d.get('data', []):
                self.shodan_list.append(ListItem(Static(f"PORT {s['port']}: {s.get('product', 'N/A')}")))

        # Update DNS
        self.dns_list.clear()
        for rt, recs in self.intel.dns_records.items():
            self.dns_list.append(Static(f"--- {rt} ---"))
            for r in recs: self.dns_list.append(ListItem(Static(f"→ {r}")))

        # Update Vulns
        self.vuln_list.clear()
        vulns = d.get('vulns', []) if d else []
        if vulns:
            for v in vulns: self.vuln_list.append(ListItem(Static(f"[!] {v}", classes="critical")))
        else:
            self.vuln_list.append(ListItem(Static("NENHUMA CVE EXPOSTA NO SHODAN")))

    def action_export(self) -> None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"osint_boy_{self.intel.domain}_{timestamp}.txt"
        
        try:
            with open(filename, "w", encoding="utf-8") as f:
                f.write(f"OSINT-BOY v1.0 - RELATÓRIO TÉCNICO\n")
                f.write(f"ALVO: {self.intel.domain} | IP: {self.intel.target_ip}\n")
                f.write(f"GERADO EM: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}\n")
                f.write("="*60 + "\n\n")
                f.write("[+] REGISTROS DNS\n")
                for rt, recs in self.intel.dns_records.items():
                    f.write(f"  {rt}: {', '.join(recs)}\n")
                f.write("\n[+] SUBDOMÍNIOS\n")
                for sub in sorted(self.intel.subdomains): f.write(f"  - {sub}\n")
                f.write("\n[+] WHOIS RESUMIDO\n")
                for label, values in self.intel.whois_synthesized.items():
                    f.write(f"  {label:<15}: {' | '.join(values)}\n")
                f.write("\n[+] SHODAN\n")
                if self.intel.shodan_data:
                    for s in self.intel.shodan_data.get('data', []):
                        f.write(f"  Porta: {s['port']} | Produto: {s.get('product', 'N/A')}\n")
                f.write("\n[+] RDAP DATA\n")
                f.write(self.intel.rdap_data)
                f.write("\n\n" + "="*60 + "\n")

            self.query_one("#footer_status", Static).update(f"EXPORTADO: {filename}")
        except Exception as e:
            self.query_one("#footer_status", Static).update(f"ERRO: {str(e)}")

app = typer.Typer(invoke_without_command=True)
@app.callback()
def main(ctx: typer.Context, domain: str = typer.Argument(None)):
    if not domain:
        print("Uso: python osint_boy.py <dominio>")
        return
    
    print(f"[*] OSINT-BOY Iniciando Sequência para: {domain}")
    try:
        ip = socket.gethostbyname(domain)
        print(f"[*] IP Alvo resolvido: {ip}")
        OSINTBoyTerminal(domain, ip).run()
    except Exception as e:
        print(f"[!] Erro no OSINT-BOY: {e}")

if __name__ == "__main__":
    app()
