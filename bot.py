#!/usr/bin/env python3
"""
Web XPL Bot - bot de Telegram para reconhecimento ativo/passivo em pentests web.

Comandos:
    /nmap <host>      - scan basico de portas/servicos (nmap -F -sV)
    /gau <dominio>     - coleta passiva de URLs conhecidas (via GetAllURLs/gau)
    /crt <dominio>     - consulta crt.sh por subdominios via Certificate Transparency
    /ipinfo <ip>       - consulta dados de geolocalizacao/ASN em ipinfo.io
    /whois <dominio>   - (bonus) consulta WHOIS do dominio

Uso:
    1. Crie um bot com o @BotFather no Telegram e pegue o token.
    2. Copie .env.example para .env e preencha TELEGRAM_BOT_TOKEN.
    3. pip install -r requirements.txt
    4. Instale o binario `nmap` no sistema (apt install nmap / brew install nmap).
       Opcional: instale `gau` (https://github.com/lc/gau) para o comando /gau
       funcionar de verdade; sem ele, o bot cai automaticamente para um modo
       de coleta passiva via Wayback Machine (CDX API), sem dependencia externa.
    5. python3 bot.py

Importante (uso etico): use os comandos de reconhecimento SOMENTE contra
alvos que voce tem autorizacao explicita para testar (ex.: seus proprios
labs vAPI/crAPI, ou programas de bug bounty que autorizem reconhecimento
passivo/ativo). O bot nao faz nenhum tipo de exploracao ativa de
vulnerabilidades, apenas coleta de informacao publica/porta.
"""
import asyncio
import ipaddress
import logging
import os
import re
import shutil
import socket
from urllib.parse import urlparse

import httpx
from dotenv import load_dotenv
from telegram import Update
from telegram.constants import ParseMode
from telegram.ext import Application, CommandHandler, ContextTypes

load_dotenv()

logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    level=logging.INFO,
)
logger = logging.getLogger("webxplbot")

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
IPINFO_TOKEN = os.getenv("IPINFO_TOKEN", "")  # opcional, aumenta rate limit do ipinfo.io

# ---------------------------------------------------------------------------
# Validacao de entrada (anti abuso / anti erro grosseiro)
# ---------------------------------------------------------------------------

DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)
HOST_RE = re.compile(r"^[A-Za-z0-9.\-]+$")


def is_valid_domain(value: str) -> bool:
    return bool(DOMAIN_RE.match(value.strip()))


def is_valid_host(value: str) -> bool:
    value = value.strip()
    if is_valid_domain(value):
        return True
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return bool(HOST_RE.match(value)) and len(value) <= 253


def is_valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip())
        return True
    except ValueError:
        return False


def extract_domain(value: str) -> str:
    """Aceita tanto 'exemplo.com' quanto 'https://exemplo.com/path' e devolve so o host."""
    value = value.strip()
    if "://" in value:
        value = urlparse(value).netloc or value
    return value.split("/")[0].split(":")[0]


# ---------------------------------------------------------------------------
# Helpers de execucao / chamadas externas
# ---------------------------------------------------------------------------

async def run_subprocess(cmd: list, timeout: int = 60) -> tuple[int, str, str]:
    """Roda um comando externo de forma assincrona, com timeout."""
    proc = await asyncio.create_subprocess_exec(
        *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
    )
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.communicate()
        raise TimeoutError(f"Comando excedeu {timeout}s: {' '.join(cmd)}")
    return proc.returncode, stdout.decode(errors="replace"), stderr.decode(errors="replace")


def chunk_message(text: str, limit: int = 3800) -> list:
    """Telegram limita mensagens a ~4096 chars; corta em blocos seguros."""
    if len(text) <= limit:
        return [text]
    chunks = []
    while text:
        chunks.append(text[:limit])
        text = text[limit:]
    return chunks


async def reply_long(update: Update, text: str, code: bool = True):
    for part in chunk_message(text):
        body = f"```\n{part}\n```" if code else part
        await update.message.reply_text(body, parse_mode=ParseMode.MARKDOWN)


# ---------------------------------------------------------------------------
# /nmap <host>
# ---------------------------------------------------------------------------

async def cmd_nmap(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("Uso: /nmap <host_ou_ip>\nEx: /nmap scanme.nmap.org")
        return

    host = context.args[0].strip()
    if not is_valid_host(host):
        await update.message.reply_text(f"❌ Host invalido: `{host}`", parse_mode=ParseMode.MARKDOWN)
        return

    if shutil.which("nmap") is None:
        await update.message.reply_text(
            "❌ O binario `nmap` nao esta instalado neste servidor.\n"
            "Instale com `apt install nmap` (Linux) ou `brew install nmap` (macOS) e tente de novo."
        )
        return

    await update.message.reply_text(f"🔍 Rodando scan basico em `{host}`... (pode levar ate ~1 min)", parse_mode=ParseMode.MARKDOWN)

    # -F: portas mais comuns (top 100) | -sV: deteccao de versao de servico | -T4: timing agressivo
    cmd = ["nmap", "-F", "-sV", "-T4", host]
    try:
        code, out, err = await run_subprocess(cmd, timeout=90)
    except TimeoutError as e:
        await update.message.reply_text(f"⏱️ {e}")
        return
    except Exception as e:
        logger.exception("Erro ao rodar nmap")
        await update.message.reply_text(f"❌ Erro ao executar nmap: {e}")
        return

    if code != 0 and not out.strip():
        await update.message.reply_text(f"❌ nmap falhou (host inacessivel?):\n```\n{err.strip()[:1500]}\n```", parse_mode=ParseMode.MARKDOWN)
        return

    await reply_long(update, out.strip() or "(sem saida)")


# ---------------------------------------------------------------------------
# /gau <dominio>  (GetAllURLs, com fallback para Wayback CDX API)
# ---------------------------------------------------------------------------

async def cmd_gau(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("Uso: /gau <dominio>\nEx: /gau example.com")
        return

    domain = extract_domain(context.args[0])
    if not is_valid_domain(domain):
        await update.message.reply_text(f"❌ Dominio invalido: `{domain}`", parse_mode=ParseMode.MARKDOWN)
        return

    await update.message.reply_text(f"🌐 Coletando URLs conhecidas para `{domain}`...", parse_mode=ParseMode.MARKDOWN)

    if shutil.which("gau") is not None:
        try:
            code, out, err = await run_subprocess(["gau", "--subs", domain], timeout=60)
        except TimeoutError as e:
            await update.message.reply_text(f"⏱️ {e}")
            return
        except Exception as e:
            logger.exception("Erro ao rodar gau")
            await update.message.reply_text(f"❌ Erro ao executar gau: {e}")
            return

        urls = [u for u in out.splitlines() if u.strip()]
        if not urls:
            await update.message.reply_text(f"⚠️ gau nao retornou nada para `{domain}`:\n```\n{err.strip()[:800]}\n```", parse_mode=ParseMode.MARKDOWN)
            return
        await reply_long(update, "\n".join(urls[:200]) + (f"\n\n... (+{len(urls) - 200} urls)" if len(urls) > 200 else ""))
        return

    # Fallback: Wayback Machine CDX API (sem dependencia de binario externo)
    await update.message.reply_text("ℹ️ `gau` nao encontrado no servidor; usando fallback via Wayback Machine (CDX API).")
    cdx_url = "https://web.archive.org/cdx/search/cdx"
    params = {
        "url": f"*.{domain}/*",
        "output": "text",
        "fl": "original",
        "collapse": "urlkey",
        "limit": "200",
    }
    try:
        async with httpx.AsyncClient(timeout=20) as client:
            resp = await client.get(cdx_url, params=params)
            resp.raise_for_status()
    except httpx.HTTPError as e:
        await update.message.reply_text(f"❌ Erro ao consultar Wayback CDX: {e}")
        return

    urls = [u for u in resp.text.splitlines() if u.strip()]
    if not urls:
        await update.message.reply_text(f"⚠️ Nenhuma URL arquivada encontrada para `{domain}`.", parse_mode=ParseMode.MARKDOWN)
        return
    await reply_long(update, "\n".join(urls))


# ---------------------------------------------------------------------------
# /crt <dominio>  (crt.sh - Certificate Transparency)
# ---------------------------------------------------------------------------

async def cmd_crt(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("Uso: /crt <dominio>\nEx: /crt example.com")
        return

    domain = extract_domain(context.args[0])
    if not is_valid_domain(domain):
        await update.message.reply_text(f"❌ Dominio invalido: `{domain}`", parse_mode=ParseMode.MARKDOWN)
        return

    await update.message.reply_text(f"📜 Consultando crt.sh para `{domain}`...", parse_mode=ParseMode.MARKDOWN)

    url = "https://crt.sh/"
    params = {"q": f"%.{domain}", "output": "json"}
    try:
        async with httpx.AsyncClient(timeout=25) as client:
            resp = await client.get(url, params=params)
            resp.raise_for_status()
            data = resp.json()
    except httpx.HTTPError as e:
        await update.message.reply_text(f"❌ Erro ao consultar crt.sh: {e}")
        return
    except ValueError:
        await update.message.reply_text("❌ crt.sh retornou uma resposta invalida (tente novamente em instantes).")
        return

    subdomains = set()
    for entry in data:
        name_value = entry.get("name_value", "")
        for name in name_value.split("\n"):
            name = name.strip().lstrip("*.")
            if name:
                subdomains.add(name)

    if not subdomains:
        await update.message.reply_text(f"⚠️ Nenhum subdominio encontrado para `{domain}` no crt.sh.", parse_mode=ParseMode.MARKDOWN)
        return

    ordered = sorted(subdomains)
    await reply_long(update, "\n".join(ordered))


# ---------------------------------------------------------------------------
# /ipinfo <ip>
# ---------------------------------------------------------------------------

async def cmd_ipinfo(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("Uso: /ipinfo <ip>\nEx: /ipinfo 8.8.8.8")
        return

    ip = context.args[0].strip()
    if not is_valid_ip(ip):
        await update.message.reply_text(f"❌ IP invalido: `{ip}`", parse_mode=ParseMode.MARKDOWN)
        return

    url = f"https://ipinfo.io/{ip}/json"
    headers = {}
    if IPINFO_TOKEN:
        headers["Authorization"] = f"Bearer {IPINFO_TOKEN}"

    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(url, headers=headers)
            resp.raise_for_status()
            data = resp.json()
    except httpx.HTTPError as e:
        await update.message.reply_text(f"❌ Erro ao consultar ipinfo.io: {e}")
        return

    if "error" in data or "bogon" in data:
        detail = data.get("error", {}).get("message") if isinstance(data.get("error"), dict) else "IP privado/reservado (bogon)"
        await update.message.reply_text(f"⚠️ ipinfo.io: {detail}")
        return

    lines = [
        f"IP:        {data.get('ip', ip)}",
        f"Hostname:  {data.get('hostname', 'N/A')}",
        f"Cidade:    {data.get('city', 'N/A')}",
        f"Regiao:    {data.get('region', 'N/A')}",
        f"Pais:      {data.get('country', 'N/A')}",
        f"Loc:       {data.get('loc', 'N/A')}",
        f"Org/ASN:   {data.get('org', 'N/A')}",
        f"Timezone:  {data.get('timezone', 'N/A')}",
    ]
    await reply_long(update, "\n".join(lines))


# ---------------------------------------------------------------------------
# /whois <dominio>  (bonus)
# ---------------------------------------------------------------------------

async def cmd_whois(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("Uso: /whois <dominio>\nEx: /whois example.com")
        return

    domain = extract_domain(context.args[0])
    if not is_valid_domain(domain):
        await update.message.reply_text(f"❌ Dominio invalido: `{domain}`", parse_mode=ParseMode.MARKDOWN)
        return

    if shutil.which("whois") is None:
        await update.message.reply_text("❌ O binario `whois` nao esta instalado neste servidor (`apt install whois`).")
        return

    await update.message.reply_text(f"🔎 Consultando WHOIS de `{domain}`...", parse_mode=ParseMode.MARKDOWN)
    try:
        code, out, err = await run_subprocess(["whois", domain], timeout=30)
    except TimeoutError as e:
        await update.message.reply_text(f"⏱️ {e}")
        return
    except Exception as e:
        logger.exception("Erro ao rodar whois")
        await update.message.reply_text(f"❌ Erro ao executar whois: {e}")
        return

    text = out.strip() or err.strip() or "(sem saida)"
    await reply_long(update, text)


# ---------------------------------------------------------------------------
# /start, /help
# ---------------------------------------------------------------------------

HELP_TEXT = (
    "*Web XPL Bot* — reconhecimento ativo/passivo para pentests web\n\n"
    "Comandos disponiveis:\n"
    "`/nmap <host>` — scan basico de portas/servicos\n"
    "`/gau <dominio>` — URLs conhecidas (passivo)\n"
    "`/crt <dominio>` — subdominios via crt.sh\n"
    "`/ipinfo <ip>` — geolocalizacao/ASN do IP\n"
    "`/whois <dominio>` — dados de registro do dominio\n\n"
    "⚠️ Use apenas contra alvos que voce tem autorizacao para testar."
)


async def cmd_start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(HELP_TEXT, parse_mode=ParseMode.MARKDOWN)


async def cmd_help(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(HELP_TEXT, parse_mode=ParseMode.MARKDOWN)


async def error_handler(update: object, context: ContextTypes.DEFAULT_TYPE):
    logger.error("Erro nao tratado: %s", context.error, exc_info=context.error)
    if isinstance(update, Update) and update.message:
        await update.message.reply_text("❌ Ocorreu um erro inesperado ao processar o comando.")


def main():
    if not TELEGRAM_BOT_TOKEN:
        raise SystemExit(
            "TELEGRAM_BOT_TOKEN nao definido. Copie .env.example para .env e preencha o token do @BotFather."
        )

    app = Application.builder().token(TELEGRAM_BOT_TOKEN).build()

    app.add_handler(CommandHandler("start", cmd_start))
    app.add_handler(CommandHandler("help", cmd_help))
    app.add_handler(CommandHandler("nmap", cmd_nmap))
    app.add_handler(CommandHandler("gau", cmd_gau))
    app.add_handler(CommandHandler("crt", cmd_crt))
    app.add_handler(CommandHandler("ipinfo", cmd_ipinfo))
    app.add_handler(CommandHandler("whois", cmd_whois))
    app.add_error_handler(error_handler)

    logger.info("Web XPL Bot iniciado. Aguardando comandos...")
    app.run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == "__main__":
    main()
