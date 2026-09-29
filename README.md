# Magnus Monitor — painel de ramais online/offline com alertas

Mostra em tempo real quais ramais do MagnusBilling estão online, offline ou em ligação. Avisa por Telegram e/ou webhook (n8n) quando um ramal cai e quando volta. Guarda o histórico de quedas.

- **Status:** vem do Asterisk via AMI, que é a fonte mais confiável. Funciona com PJSIP (MBilling 8) e chan_sip (versões anteriores), com detecção automática.
- **Nomes e lista de ramais:** vêm da API do MagnusBilling. Assim o painel mostra o nome do cliente e ignora os troncos.
- **Único requisito:** Python 3.6 ou mais novo com `requests`. Não usa banco externo; o histórico fica num SQLite local.

> **Segurança:** a API Key, o Secret e as senhas ficam só no arquivo `.env` do seu servidor. Não envie esse arquivo para ninguém.

---

## 1. Criar um usuário AMI só para o monitor

No servidor Magnus, faça backup e edite o manager:

```bash
cp /etc/asterisk/manager.conf /etc/asterisk/manager.conf.bak
nano /etc/asterisk/manager.conf
```

Adicione no final (troque a senha):

```ini
[monitor]
secret = TROQUE_POR_UMA_SENHA_FORTE
deny = 0.0.0.0/0.0.0.0
permit = 127.0.0.1/255.255.255.255
read = system,reporting,call
write = system,reporting
```

Aplique e confira:

```bash
asterisk -rx "manager reload"
asterisk -rx "manager show user monitor"
```

O `permit` libera só o próprio servidor. Se o monitor for rodar em outra máquina, coloque o IP dela no `permit` e libere a porta 5038 **só para esse IP** no firewall. Nunca deixe a 5038 aberta para a internet.

## 2. Liberar a API no MagnusBilling

No painel do Magnus, abra o módulo de **API**, gere a Key e o Secret com permissão de **leitura** e cadastre o IP de onde o monitor vai rodar (`127.0.0.1` ou o IP do próprio servidor, se for no mesmo). Se a API ficar desligada ou der erro, o monitor continua funcionando só com o AMI, mas sem nomes de clientes.

## 3. Instalar

```bash
# Debian/Ubuntu:  apt install -y python3 python3-venv
# CentOS 7:       yum install -y python3
useradd -r -s /usr/sbin/nologin magnusmon
mkdir -p /opt/magnus-monitor
# copie a pasta do projeto para /opt/magnus-monitor
cd /opt/magnus-monitor
python3 -m venv venv
venv/bin/pip install -r requirements.txt
cp .env.example .env
nano .env        # preencha MB_URL, MB_API_KEY, MB_API_SECRET, AMI_SECRET, DASH_PASS, Telegram/webhook
chmod 600 .env
chown -R magnusmon:magnusmon /opt/magnus-monitor
```

## 4. Testar antes de ligar

```bash
sudo -u magnusmon venv/bin/python monitor.py --test          # lê os ramais e mostra uma tabela
sudo -u magnusmon venv/bin/python monitor.py --test-alert    # manda uma mensagem de teste
```

Se o `--test` mostrar seus ramais com os nomes dos clientes, está tudo certo.

## 5. Deixar rodando como serviço

```bash
cp magnus-monitor.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now magnus-monitor
systemctl status magnus-monitor
journalctl -u magnus-monitor -f      # acompanhar o log
```

Acesse `http://IP_DO_SERVIDOR:8088` com o usuário e a senha do `DASH_USER` e `DASH_PASS`.

Libere a porta 8088 no firewall **só para os IPs da sua equipe**. Para acessar de fora com HTTPS, coloque o painel atrás de um nginx com certificado. Exemplo de iptables:

```bash
iptables -I INPUT -p tcp --dport 8088 -s IP_DO_ESCRITORIO -j ACCEPT
iptables -A INPUT -p tcp --dport 8088 -j DROP
```

---

## Rodando com Docker

Com Docker e Docker Compose instalados:

```bash
cp .env.example .env
nano .env                      # preencha como no passo 3
docker compose up -d --build
docker compose logs -f monitor
```

O painel fica em `http://localhost:8088`. O `.env` não entra na imagem; o Compose injeta as variáveis só quando o container sobe. O histórico fica no volume `monitor_data`.

Se o monitor rodar fora do servidor Magnus, `AMI_HOST` precisa apontar para o IP do servidor. Coloque o IP de saída da máquina do monitor no `permit` do `manager.conf`, no firewall da porta 5038 e no `ignoreip` do fail2ban. Sem o `ignoreip`, falhas de login podem banir esse IP em todas as portas.

### Modo demonstração

Para ver o painel sem Asterisk nem MagnusBilling, com ramais e clientes fictícios:

```bash
docker compose --profile demo up -d --build demo
```

Abra `http://localhost:8088`. O modo demo não pede senha e não conecta em nada. Ele usa a mesma porta do monitor, então pare um antes de subir o outro. Sem Docker: `python3 demo.py`.

---

## Como os alertas funcionam

- **Carência:** um ramal precisa ficar offline por `OFFLINE_GRACE` segundos (padrão 90) antes de gerar alerta. Isso evita avisos quando o telefone só está renovando o registro ou o link oscilou.
- **Volta:** se ele voltar, chega o aviso de volta com quanto tempo ficou fora (`ALERT_ON_RECOVERY`).
- **Várias quedas juntas:** vários ramais caindo no mesmo ciclo viram uma única mensagem. A partir de `MASS_OUTAGE_THRESHOLD` ramais, o alerta avisa que pode ser queda geral (link, firewall ou servidor).
- **Sem conexão com o Asterisk:** se o monitor perder contato com o Asterisk, ele manda um alerta próprio e avisa quando reconectar.
- **Ao ligar o monitor:** ramais que já estavam offline não geram alerta, para evitar avalanche. O estado fica salvo, então reiniciar o serviço não repete alertas.
- **No navegador:** o botão **Avisar neste navegador** do painel toca um bipe e mostra notificação quando um ramal é alertado. É útil numa tela de NOC.

### Telegram

1. Fale com o **@BotFather**, crie um bot e copie o token para `TELEGRAM_BOT_TOKEN`.
2. Adicione o bot no grupo da equipe e mande uma mensagem qualquer no grupo.
3. Abra `https://api.telegram.org/botSEU_TOKEN/getUpdates` e copie o `chat.id` (em grupos ele começa com `-`) para `TELEGRAM_CHAT_ID`.

### Webhook (n8n, WhatsApp, e-mail…)

Com `WEBHOOK_URL` preenchido, cada alerta chega como JSON:

```json
{"type": "down", "ts": 1790687342.69, "count": 1,
 "ramais": [{"ext": "1001", "client": "Padaria Silva", "callerid": "1133334444",
             "ip": "187.10.0.1", "since": 1790687332.69, "status": "offline"}]}
```

O campo `type` pode ser:

| type | quando é enviado |
|---|---|
| `down` | um ou mais ramais caíram |
| `up` | ramais voltaram (vem com `offline_seconds`) |
| `monitor_error` | o monitor perdeu contato com o Asterisk |
| `monitor_ok` | o monitor reconectou |
| `test` | alerta de teste |

No n8n, crie um fluxo com o nó **Webhook** (POST) e mande para onde quiser: WhatsApp, e-mail, Slack, abrir chamado etc.

### API do próprio painel

As rotas usam o mesmo usuário e senha do painel:

| rota | o que retorna |
|---|---|
| `GET /api/status` | todos os ramais com status, IP, latência e desde quando |
| `GET /api/events?limit=100&ext=1001` | histórico de quedas e voltas |
| `GET /health` | sem senha; serve para monitoramento externo (Uptime Kuma, Zabbix…) |

---

## Problemas comuns

| Mensagem | O que fazer |
|---|---|
| `login recusado` | Confira `AMI_USER`/`AMI_SECRET` e se o IP está no `permit`. Depois rode `asterisk -rx "manager reload"`. |
| `não foi possível conectar em …:5038` | Confira se o AMI está ativo (`enabled = yes` no `[general]` do manager.conf) e o firewall. |
| Aviso "API do MagnusBilling indisponível" | Confira `MB_URL` (ex.: `http://IP/mbilling`), a Key e o Secret, e o IP liberado no módulo de API. |
| Aparecem troncos no painel | Mantenha `ONLY_API_USERS=true` com a API configurada, ou use `IGNORE=nome-do-tronco*`. |
| Ramal online aparece offline no modo `api` | O modo `api` depende do campo lineStatus do Magnus. Prefira `STATUS_SOURCE=ami`. |
