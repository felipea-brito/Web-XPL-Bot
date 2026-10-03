# Web XPL Bot (Telegram)

Bot em Python que simula comandos de reconhecimento ativo/passivo para
pentests web, rodando inteiramente dentro do Telegram.

## Estrutura

```
parte2_webxpl_bot/
├── bot.py             # Código principal: handlers de cada comando
├── requirements.txt   # Dependências Python
├── .env.example        # Modelo de variáveis de ambiente
└── README.md
```

O `bot.py` é organizado em três blocos:

1. **Validação de entrada** (`is_valid_domain`, `is_valid_host`, `is_valid_ip`,
   `extract_domain`) — garante que o usuário não injeta flags/host inválidos
   antes de qualquer chamada externa.
2. **Execução de comandos externos** (`run_subprocess`) — roda `nmap`/`gau`/
   `whois` como subprocesso assíncrono, com timeout, e nunca via `shell=True`
   (os argumentos são passados como lista, evitando injeção de comando).
3. **Handlers por comando** (`cmd_nmap`, `cmd_gau`, `cmd_crt`, `cmd_ipinfo`,
   `cmd_whois`) — cada um valida a entrada, chama a ferramenta/API
   correspondente, trata erros (host inválido, timeout, domínio não
   encontrado, API fora do ar) e formata a resposta em blocos de código
   para o Telegram.

## Como rodar localmente

1. Crie um bot com o **@BotFather** no Telegram (`/newbot`) e copie o token.
2. Clone/baixe este diretório e instale as dependências:
   ```bash
   cd parte2_webxpl_bot
   python3 -m venv venv && source venv/bin/activate
   pip install -r requirements.txt
   ```
3. Copie `.env.example` para `.env` e preencha `TELEGRAM_BOT_TOKEN`:
   ```bash
   cp .env.example .env
   ```
4. (Opcional, mas recomendado) instale as ferramentas de linha de comando
   usadas pelos comandos:
   ```bash
   sudo apt install nmap whois           # /nmap e /whois
   go install github.com/lc/gau/v2/cmd/gau@latest   # /gau (requer Go)
   ```
   Se `gau` não estiver instalado, `/gau` cai automaticamente para um
   fallback via **Wayback Machine CDX API** (sem dependência extra).
   `/crt` e `/ipinfo` não dependem de binário nenhum, só de internet.
5. Rode o bot:
   ```bash
   python3 bot.py
   ```
6. No Telegram, procure seu bot pelo @username cadastrado no BotFather e
   mande `/start`.

## Comandos e exemplos de uso

| Comando | Exemplo | O que faz |
|---|---|---|
| `/nmap <host>` | `/nmap scanme.nmap.org` | Roda `nmap -F -sV -T4 <host>` (top-100 portas + detecção de versão) e devolve a saída formatada. |
| `/gau <dominio>` | `/gau example.com` | Coleta URLs conhecidas/arquivadas do domínio (via `gau --subs`, ou fallback Wayback CDX). |
| `/crt <dominio>` | `/crt example.com` | Consulta `crt.sh?q=%.example.com&output=json` e lista subdomínios únicos vistos em certificados TLS emitidos (Certificate Transparency). |
| `/ipinfo <ip>` | `/ipinfo 8.8.8.8` | Consulta `ipinfo.io/<ip>/json` e retorna cidade, país, ASN/organização e timezone. |
| `/whois <dominio>` | `/whois example.com` | **(bônus)** roda `whois <dominio>` e devolve os dados de registro. |
| `/help` | `/help` | Lista todos os comandos. |

### Tratamento de erros implementado

- Host/domínio/IP com formato inválido → mensagem de erro imediata, sem
  chamar nenhuma ferramenta externa (evita abuso/erros bobos).
- Binário ausente (`nmap`/`whois`/`gau`) → o bot avisa explicitamente qual
  pacote instalar, em vez de travar ou devolver um stack trace.
- Timeout de execução (`nmap`/`whois` > tempo limite) → mensagem clara de
  timeout, o processo é morto (`proc.kill()`) para não vazar.
- Erros de rede/API (crt.sh, ipinfo.io, Wayback) → `httpx.HTTPError`
  capturado e reportado ao usuário, com o motivo.
- Respostas longas são divididas em múltiplas mensagens, respeitando o
  limite de ~4096 caracteres do Telegram.

## Uso ético

Os comandos aqui são de reconhecimento (passivo em `/gau`, `/crt`, `/ipinfo`,
`/whois`; ativo e de baixo impacto em `/nmap` com top-100 portas). Use-os
**apenas** contra alvos que você tem autorização explícita para testar —
por exemplo, o laboratório vAPI/crAPI da Parte 1 rodando localmente, ou
domínios de programas de bug bounty que permitam reconhecimento.
