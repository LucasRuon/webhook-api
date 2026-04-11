from __future__ import annotations

from typing import Optional, List
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
import httpx
import hmac
import hashlib
import json
from datetime import datetime, timezone

from app.config import WEBHOOK_TOKEN, RABBITMQ_QUEUE
from app.database import get_db, init_db
from app import rabbitmq

app = FastAPI(title="Webhook API", version="3.0.0")


@app.on_event("startup")
async def startup():
    await init_db()
    await rabbitmq.connect()


@app.on_event("shutdown")
async def shutdown():
    await rabbitmq.disconnect()


# ──────────────────────────────────────
#  Models
# ──────────────────────────────────────
class ChannelCreate(BaseModel):
    name: str
    slug: str
    description: str = ""
    fields_schema: List[dict] = []
    secret: str = ""
    target_url: str = ""
    rabbit_queue: str = ""
    rabbit_exchange: str = ""
    rabbit_routing_key: str = ""
    rabbit_enabled: bool = False


class ChannelUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    fields_schema: Optional[List[dict]] = None
    secret: Optional[str] = None
    target_url: Optional[str] = None
    rabbit_queue: Optional[str] = None
    rabbit_exchange: Optional[str] = None
    rabbit_routing_key: Optional[str] = None
    rabbit_enabled: Optional[bool] = None
    is_active: Optional[bool] = None


class SendPayload(BaseModel):
    data: dict
    headers: Optional[dict] = None


# ──────────────────────────────────────
#  Autenticacao admin (via WEBHOOK_TOKEN)
# ──────────────────────────────────────
def check_admin(request: Request):
    if WEBHOOK_TOKEN and request.headers.get("x-webhook-token") != WEBHOOK_TOKEN:
        raise HTTPException(status_code=401, detail="Token invalido")


# ──────────────────────────────────────
#  CHANNELS — CRUD
# ──────────────────────────────────────
@app.post("/api/channels")
async def create_channel(channel: ChannelCreate, request: Request):
    check_admin(request)
    db = await get_db()
    try:
        await db.execute(
            """INSERT INTO channels
               (name, slug, description, fields_schema, secret, target_url,
                rabbit_queue, rabbit_exchange, rabbit_routing_key, rabbit_enabled)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (channel.name, channel.slug, channel.description,
             json.dumps(channel.fields_schema), channel.secret, channel.target_url,
             channel.rabbit_queue, channel.rabbit_exchange, channel.rabbit_routing_key,
             1 if channel.rabbit_enabled else 0),
        )
        await db.commit()
        return {"status": "ok", "slug": channel.slug}
    finally:
        await db.close()


@app.get("/api/channels")
async def list_channels(request: Request):
    check_admin(request)
    db = await get_db()
    try:
        cursor = await db.execute("SELECT * FROM channels ORDER BY created_at DESC")
        rows = await cursor.fetchall()
        return [
            {**dict(row), "fields_schema": json.loads(row["fields_schema"])}
            for row in rows
        ]
    finally:
        await db.close()


@app.get("/api/channels/{slug}")
async def get_channel(slug: str, request: Request):
    check_admin(request)
    db = await get_db()
    try:
        cursor = await db.execute("SELECT * FROM channels WHERE slug = ?", (slug,))
        row = await cursor.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Canal nao encontrado")
        return {**dict(row), "fields_schema": json.loads(row["fields_schema"])}
    finally:
        await db.close()


@app.put("/api/channels/{slug}")
async def update_channel(slug: str, update: ChannelUpdate, request: Request):
    check_admin(request)
    db = await get_db()
    try:
        cursor = await db.execute("SELECT * FROM channels WHERE slug = ?", (slug,))
        existing = await cursor.fetchone()
        if not existing:
            raise HTTPException(status_code=404, detail="Canal nao encontrado")

        fields = {}
        if update.name is not None:
            fields["name"] = update.name
        if update.description is not None:
            fields["description"] = update.description
        if update.fields_schema is not None:
            fields["fields_schema"] = json.dumps(update.fields_schema)
        if update.secret is not None:
            fields["secret"] = update.secret
        if update.target_url is not None:
            fields["target_url"] = update.target_url
        if update.rabbit_queue is not None:
            fields["rabbit_queue"] = update.rabbit_queue
        if update.rabbit_exchange is not None:
            fields["rabbit_exchange"] = update.rabbit_exchange
        if update.rabbit_routing_key is not None:
            fields["rabbit_routing_key"] = update.rabbit_routing_key
        if update.rabbit_enabled is not None:
            fields["rabbit_enabled"] = 1 if update.rabbit_enabled else 0
        if update.is_active is not None:
            fields["is_active"] = 1 if update.is_active else 0

        if fields:
            set_clause = ", ".join(f"{k} = ?" for k in fields)
            await db.execute(
                f"UPDATE channels SET {set_clause} WHERE slug = ?",
                (*fields.values(), slug),
            )
            await db.commit()

        return {"status": "ok"}
    finally:
        await db.close()


@app.delete("/api/channels/{slug}")
async def delete_channel(slug: str, request: Request):
    check_admin(request)
    db = await get_db()
    try:
        await db.execute("DELETE FROM webhook_logs WHERE channel_id IN (SELECT id FROM channels WHERE slug = ?)", (slug,))
        await db.execute("DELETE FROM channels WHERE slug = ?", (slug,))
        await db.commit()
        return {"status": "ok"}
    finally:
        await db.close()


# ──────────────────────────────────────
#  RECEBER WEBHOOK  →  POST /w/{slug}
# ──────────────────────────────────────
@app.post("/w/{slug}")
async def receive_webhook(slug: str, request: Request):
    db = await get_db()
    try:
        cursor = await db.execute("SELECT * FROM channels WHERE slug = ? AND is_active = 1", (slug,))
        channel = await cursor.fetchone()
        if not channel:
            raise HTTPException(status_code=404, detail="Canal nao encontrado")

        if channel["secret"]:
            incoming_secret = (
                request.headers.get("x-webhook-token", "")
                or request.headers.get("x-webhook-secret", "")
            )
            if incoming_secret != channel["secret"]:
                raise HTTPException(status_code=401, detail="Secret invalido")

        body = await request.json()
        headers = dict(request.headers)

        # Extrai campos configurados (suporta arrays: entry.0.changes.0.value)
        fields_schema = json.loads(channel["fields_schema"])
        extracted = {}
        for field in fields_schema:
            key = field.get("key", "")
            if key:
                value = body
                for part in key.split("."):
                    if isinstance(value, dict):
                        value = value.get(part)
                    elif isinstance(value, list):
                        try:
                            value = value[int(part)]
                        except (ValueError, IndexError):
                            value = None
                            break
                    else:
                        value = None
                        break
                extracted[key] = value

        # Publica no RabbitMQ se habilitado
        rabbit_published = False
        if channel["rabbit_enabled"]:
            queue = channel["rabbit_queue"] or RABBITMQ_QUEUE
            message = {
                "channel": slug,
                "received_at": datetime.now(timezone.utc).isoformat(),
                "payload": body,
                "extracted": extracted,
            }
            rabbit_published = await rabbitmq.publish(
                exchange_name=channel["rabbit_exchange"],
                routing_key=channel["rabbit_routing_key"],
                queue_name=queue,
                message=message,
            )

        await db.execute(
            """INSERT INTO webhook_logs
               (channel_id, direction, headers, payload, extracted_fields, rabbit_published)
               VALUES (?, 'in', ?, ?, ?, ?)""",
            (channel["id"], json.dumps(headers), json.dumps(body),
             json.dumps(extracted), 1 if rabbit_published else 0),
        )
        await db.commit()

        return {
            "status": "ok",
            "message": "Webhook recebido",
            "extracted": extracted,
            "rabbit_published": rabbit_published,
        }
    finally:
        await db.close()


# ──────────────────────────────────────
#  ENVIAR WEBHOOK  →  POST /api/channels/{slug}/send
# ──────────────────────────────────────
@app.post("/api/channels/{slug}/send")
async def send_webhook(slug: str, payload: SendPayload, request: Request):
    check_admin(request)
    db = await get_db()
    try:
        cursor = await db.execute("SELECT * FROM channels WHERE slug = ?", (slug,))
        channel = await cursor.fetchone()
        if not channel:
            raise HTTPException(status_code=404, detail="Canal nao encontrado")

        target_url = channel["target_url"]
        if not target_url:
            raise HTTPException(status_code=400, detail="Canal sem target_url configurada")

        headers = payload.headers or {"Content-Type": "application/json"}

        if channel["secret"]:
            signature = hmac.new(
                channel["secret"].encode(),
                json.dumps(payload.data, separators=(",", ":")).encode(),
                hashlib.sha256,
            ).hexdigest()
            headers["X-Webhook-Signature"] = signature

        async with httpx.AsyncClient(timeout=30) as client:
            response = await client.post(target_url, json=payload.data, headers=headers)

        await db.execute(
            """INSERT INTO webhook_logs
               (channel_id, direction, headers, payload, response_status, response_body)
               VALUES (?, 'out', ?, ?, ?, ?)""",
            (channel["id"], json.dumps(headers), json.dumps(payload.data),
             response.status_code, response.text[:2000]),
        )
        await db.commit()

        return {
            "status": "sent",
            "response_status": response.status_code,
            "response_body": response.text[:500],
        }
    finally:
        await db.close()


# ──────────────────────────────────────
#  LOGS
# ──────────────────────────────────────
@app.get("/api/channels/{slug}/logs")
async def get_logs(slug: str, request: Request, direction: str = "", limit: int = 50):
    check_admin(request)
    db = await get_db()
    try:
        cursor = await db.execute("SELECT id FROM channels WHERE slug = ?", (slug,))
        channel = await cursor.fetchone()
        if not channel:
            raise HTTPException(status_code=404, detail="Canal nao encontrado")

        query = "SELECT * FROM webhook_logs WHERE channel_id = ?"
        params: list = [channel["id"]]

        if direction in ("in", "out"):
            query += " AND direction = ?"
            params.append(direction)

        query += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)

        cursor = await db.execute(query, params)
        rows = await cursor.fetchall()

        return [
            {
                **dict(row),
                "headers": json.loads(row["headers"]),
                "payload": json.loads(row["payload"]),
                "extracted_fields": json.loads(row["extracted_fields"]),
            }
            for row in rows
        ]
    finally:
        await db.close()


# ──────────────────────────────────────
#  STATUS RabbitMQ
# ──────────────────────────────────────
@app.get("/api/rabbitmq/status")
async def rabbit_status(request: Request):
    check_admin(request)
    return await rabbitmq.get_status()


# ──────────────────────────────────────
#  PAINEL WEB
# ──────────────────────────────────────
@app.get("/", response_class=HTMLResponse)
@app.get("/admin", response_class=HTMLResponse)
@app.get("/admin/{rest:path}", response_class=HTMLResponse)
async def admin_panel():
    return ADMIN_HTML


@app.get("/health")
async def health():
    return {"status": "ok"}


# ──────────────────────────────────────
#  HTML do painel
# ──────────────────────────────────────
ADMIN_HTML = r"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Webhook Admin</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #0f172a; color: #e2e8f0; }
  .container { max-width: 1000px; margin: 0 auto; padding: 20px; }
  h1 { margin-bottom: 8px; color: #38bdf8; }
  .subtitle { color: #64748b; margin-bottom: 24px; }

  #auth-bar { display: flex; gap: 8px; margin-bottom: 24px; }
  #auth-bar input { flex: 1; padding: 10px 14px; background: #1e293b; border: 1px solid #334155; border-radius: 8px; color: #e2e8f0; }
  #auth-bar button { padding: 10px 20px; background: #2563eb; border: none; border-radius: 8px; color: white; cursor: pointer; font-weight: 600; }

  .status-bar { display: flex; gap: 12px; margin-bottom: 20px; align-items: center; }
  .status-dot { width: 10px; height: 10px; border-radius: 50%; display: inline-block; }
  .status-dot.green { background: #22c55e; }
  .status-dot.red { background: #ef4444; }
  .status-text { font-size: 13px; color: #94a3b8; }

  .tabs { display: flex; gap: 4px; margin-bottom: 20px; }
  .tab { padding: 8px 16px; background: #1e293b; border: 1px solid #334155; border-radius: 8px 8px 0 0; cursor: pointer; color: #94a3b8; }
  .tab.active { background: #334155; color: #38bdf8; border-bottom-color: #334155; }

  .card { background: #1e293b; border: 1px solid #334155; border-radius: 12px; padding: 20px; margin-bottom: 16px; }
  .card h3 { color: #38bdf8; margin-bottom: 4px; }
  .card .meta { color: #64748b; font-size: 13px; margin-bottom: 12px; }
  .url-badge { display: inline-block; background: #0f172a; padding: 4px 10px; border-radius: 6px; font-family: monospace; font-size: 13px; color: #34d399; }
  .badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 12px; font-weight: 600; }
  .badge.in { background: #064e3b; color: #6ee7b7; }
  .badge.out { background: #1e1b4b; color: #a5b4fc; }
  .badge.active { background: #064e3b; color: #6ee7b7; }
  .badge.inactive { background: #450a0a; color: #fca5a5; }
  .badge.rabbit { background: #4c1d95; color: #c4b5fd; }
  .badge.rabbit-ok { background: #064e3b; color: #6ee7b7; }
  .badge.rabbit-fail { background: #450a0a; color: #fca5a5; }

  .form-group { margin-bottom: 14px; }
  .form-group label { display: block; color: #94a3b8; font-size: 13px; margin-bottom: 4px; }
  .form-group input, .form-group textarea, .form-group select { width: 100%; padding: 10px; background: #0f172a; border: 1px solid #334155; border-radius: 8px; color: #e2e8f0; font-family: monospace; }
  .section-title { color: #a78bfa; font-size: 14px; font-weight: 600; margin: 20px 0 10px; padding-top: 16px; border-top: 1px solid #334155; }
  .checkbox-group { display: flex; align-items: center; gap: 8px; margin-bottom: 14px; }
  .checkbox-group input[type=checkbox] { width: 18px; height: 18px; accent-color: #7c3aed; }
  .checkbox-group label { color: #c4b5fd; font-size: 13px; }

  .btn { padding: 8px 16px; border: none; border-radius: 8px; cursor: pointer; font-weight: 600; font-size: 13px; }
  .btn-primary { background: #2563eb; color: white; }
  .btn-danger { background: #dc2626; color: white; }
  .btn-success { background: #16a34a; color: white; }
  .btn-sm { padding: 4px 10px; font-size: 12px; }
  .btn-group { display: flex; gap: 8px; margin-top: 12px; }

  .field-row { display: flex; gap: 8px; margin-bottom: 8px; align-items: center; }
  .field-row input { flex: 1; padding: 8px; background: #0f172a; border: 1px solid #334155; border-radius: 6px; color: #e2e8f0; font-size: 13px; }
  .field-row button { padding: 6px 10px; }

  .log-entry { background: #0f172a; border: 1px solid #1e293b; border-radius: 8px; padding: 12px; margin-bottom: 8px; }
  .log-entry .log-header { display: flex; justify-content: space-between; margin-bottom: 8px; flex-wrap: wrap; gap: 4px; }
  .log-entry pre { background: #1e293b; padding: 10px; border-radius: 6px; overflow-x: auto; font-size: 12px; max-height: 200px; overflow-y: auto; }
  .extracted { margin-top: 8px; }
  .extracted table { width: 100%; border-collapse: collapse; }
  .extracted td, .extracted th { padding: 4px 8px; border-bottom: 1px solid #334155; font-size: 13px; text-align: left; }
  .extracted th { color: #64748b; }

  .empty { text-align: center; padding: 40px; color: #475569; }
  .flex-between { display: flex; justify-content: space-between; align-items: center; }
  .hidden { display: none; }
</style>
</head>
<body>
<div class="container">
  <h1>Webhook Admin</h1>
  <p class="subtitle">Gerencie canais de webhook com envio automatico para RabbitMQ</p>

  <div id="auth-bar">
    <input type="password" id="secret-input" placeholder="WEBHOOK_TOKEN (token de acesso)">
    <button onclick="saveSecret()">Conectar</button>
  </div>

  <div id="status-bar" class="status-bar hidden"></div>

  <div class="tabs">
    <div class="tab active" onclick="showTab('channels')">Canais</div>
    <div class="tab" onclick="showTab('create')">+ Novo Canal</div>
  </div>

  <div id="tab-channels"></div>

  <div id="tab-create" class="hidden">
    <div class="card">
      <h3>Novo Canal</h3>
      <div class="form-group"><label>Nome</label><input id="new-name" placeholder="Ex: Pagamentos Stripe"></div>
      <div class="form-group"><label>Slug (URL)</label><input id="new-slug" placeholder="Ex: stripe-pagamentos"></div>
      <div class="form-group"><label>Descricao</label><input id="new-desc" placeholder="Opcional"></div>
      <div class="form-group"><label>Secret do canal</label><input id="new-secret" placeholder="Opcional - protege o endpoint /w/slug"></div>
      <div class="form-group"><label>URL destino (para reenvio HTTP)</label><input id="new-target" placeholder="https://exemplo.com/webhook"></div>

      <div class="form-group">
        <label>Campos para extrair do payload</label>
        <p style="color:#64748b;font-size:12px;margin-bottom:8px">Use caminhos como: event, data.id, data.customer.email</p>
        <div id="new-fields"></div>
        <button class="btn btn-sm btn-primary" onclick="addFieldRow('new-fields')">+ Campo</button>
      </div>

      <div class="section-title">RabbitMQ</div>
      <div class="checkbox-group">
        <input type="checkbox" id="new-rabbit-enabled" checked>
        <label for="new-rabbit-enabled">Publicar no RabbitMQ ao receber webhook</label>
      </div>
      <div class="form-group"><label>Fila (queue) — vazio usa a fila padrao da env RABBITMQ_QUEUE</label><input id="new-rabbit-queue" placeholder="Ex: webhooks.stripe"></div>
      <div class="form-group"><label>Exchange (vazio = default exchange)</label><input id="new-rabbit-exchange" placeholder="Ex: webhooks"></div>
      <div class="form-group"><label>Routing Key (vazio = nome da fila)</label><input id="new-rabbit-routing" placeholder="Ex: payments.received"></div>

      <div class="btn-group">
        <button class="btn btn-success" onclick="createChannel()">Criar Canal</button>
      </div>
    </div>
  </div>

  <div id="tab-detail" class="hidden"></div>
</div>

<script>
let TOKEN = localStorage.getItem('webhook_token') || '';
document.getElementById('secret-input').value = TOKEN;

function saveSecret() {
  TOKEN = document.getElementById('secret-input').value;
  localStorage.setItem('webhook_token', TOKEN);
  loadChannels();
  loadRabbitStatus();
}

function hdrs() {
  return { 'Content-Type': 'application/json', 'X-Webhook-Token': TOKEN };
}

async function api(path, opts = {}) {
  const res = await fetch(path, { headers: hdrs(), ...opts });
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}

async function loadRabbitStatus() {
  try {
    const st = await api('/api/rabbitmq/status');
    const bar = document.getElementById('status-bar');
    bar.classList.remove('hidden');
    bar.innerHTML = `
      <span class="status-dot ${st.connected ? 'green' : 'red'}"></span>
      <span class="status-text">RabbitMQ: ${st.connected ? 'Conectado' : 'Desconectado'} (${st.url}) | Fila padrao: ${st.default_queue}</span>
    `;
  } catch(e) {}
}

function showTab(name) {
  document.querySelectorAll('.tabs .tab').forEach(t => t.classList.remove('active'));
  ['channels', 'create', 'detail'].forEach(t => {
    document.getElementById('tab-' + t).classList.add('hidden');
  });
  document.getElementById('tab-' + name).classList.remove('hidden');
  document.querySelectorAll('.tabs .tab').forEach(t => {
    if (t.textContent.includes(name === 'channels' ? 'Canais' : name === 'create' ? 'Novo' : '')) t.classList.add('active');
  });
  if (name === 'channels') loadChannels();
}

async function loadChannels() {
  try {
    const channels = await api('/api/channels');
    const el = document.getElementById('tab-channels');
    if (!channels.length) {
      el.innerHTML = '<div class="empty">Nenhum canal criado ainda. Crie o primeiro!</div>';
      return;
    }
    el.innerHTML = channels.map(ch => `
      <div class="card" style="cursor:pointer" onclick="openChannel('${ch.slug}')">
        <div class="flex-between">
          <h3>${ch.name}</h3>
          <div>
            ${ch.rabbit_enabled ? '<span class="badge rabbit">RabbitMQ</span> ' : ''}
            <span class="badge ${ch.is_active ? 'active' : 'inactive'}">${ch.is_active ? 'Ativo' : 'Inativo'}</span>
          </div>
        </div>
        <p class="meta">${ch.description || 'Sem descricao'}</p>
        <span class="url-badge">POST /w/${ch.slug}</span>
        ${ch.rabbit_enabled ? '<span style="margin-left:8px" class="url-badge">fila: ' + (ch.rabbit_queue || 'padrao') + '</span>' : ''}
        ${ch.fields_schema.length ? '<p style="margin-top:8px;color:#64748b;font-size:12px">Campos: ' + ch.fields_schema.map(f => f.key).join(', ') + '</p>' : ''}
      </div>
    `).join('');
  } catch (e) {
    document.getElementById('tab-channels').innerHTML = '<div class="empty">Erro ao carregar. Verifique o token.</div>';
  }
}

async function openChannel(slug) {
  const ch = await api('/api/channels/' + slug);
  const logs = await api('/api/channels/' + slug + '/logs?limit=20');

  const el = document.getElementById('tab-detail');
  el.classList.remove('hidden');
  document.getElementById('tab-channels').classList.add('hidden');
  document.getElementById('tab-create').classList.add('hidden');

  el.innerHTML = `
    <div style="margin-bottom:16px">
      <button class="btn btn-sm btn-primary" onclick="showTab('channels')">&larr; Voltar</button>
    </div>
    <div class="card">
      <div class="flex-between">
        <h3>${ch.name}</h3>
        <div>
          ${ch.rabbit_enabled ? '<span class="badge rabbit">RabbitMQ</span> ' : ''}
          <span class="badge ${ch.is_active ? 'active' : 'inactive'}">${ch.is_active ? 'Ativo' : 'Inativo'}</span>
        </div>
      </div>
      <p class="meta">${ch.description}</p>
      <p><strong>Endpoint:</strong> <span class="url-badge">POST ${location.origin}/w/${ch.slug}</span></p>
      ${ch.target_url ? '<p style="margin-top:8px"><strong>Reenvio HTTP:</strong> <span class="url-badge">' + ch.target_url + '</span></p>' : ''}
      ${ch.secret ? '<p style="margin-top:8px;color:#64748b;font-size:12px">Header: X-Webhook-Token: ' + ch.secret + '</p>' : ''}

      <h4 style="margin-top:16px;color:#94a3b8">Campos configurados</h4>
      <div id="edit-fields" style="margin-top:8px">
        ${ch.fields_schema.map((f, i) => `
          <div class="field-row">
            <input value="${f.key}" placeholder="Caminho (ex: data.id)">
            <input value="${f.label || ''}" placeholder="Label" data-type="label">
            <button class="btn btn-danger btn-sm" onclick="this.parentElement.remove()">x</button>
          </div>
        `).join('')}
      </div>
      <button class="btn btn-sm btn-primary" onclick="addFieldRow('edit-fields')">+ Campo</button>

      <div class="section-title">RabbitMQ</div>
      <div class="checkbox-group">
        <input type="checkbox" id="edit-rabbit-enabled" ${ch.rabbit_enabled ? 'checked' : ''}>
        <label for="edit-rabbit-enabled">Publicar no RabbitMQ</label>
      </div>
      <div class="form-group"><label>Fila (queue) — vazio usa padrao</label><input id="edit-rabbit-queue" value="${ch.rabbit_queue || ''}"></div>
      <div class="form-group"><label>Exchange</label><input id="edit-rabbit-exchange" value="${ch.rabbit_exchange || ''}"></div>
      <div class="form-group"><label>Routing Key</label><input id="edit-rabbit-routing" value="${ch.rabbit_routing_key || ''}"></div>

      <div class="btn-group">
        <button class="btn btn-success" onclick="saveChannel('${ch.slug}')">Salvar</button>
        <button class="btn btn-danger btn-sm" onclick="deleteChannel('${ch.slug}')">Excluir canal</button>
      </div>
    </div>

    <h3 style="margin:20px 0 12px;color:#94a3b8">Logs recentes</h3>
    ${logs.length ? logs.map(log => `
      <div class="log-entry">
        <div class="log-header">
          <span>
            <span class="badge ${log.direction}">${log.direction === 'in' ? 'Recebido' : 'Enviado'}</span>
            ${log.rabbit_published ? '<span class="badge rabbit-ok">RabbitMQ OK</span>' : (log.direction === 'in' ? '<span class="badge rabbit-fail">Sem RabbitMQ</span>' : '')}
            ${log.created_at}
          </span>
          ${log.response_status ? '<span style="color:#64748b">HTTP ' + log.response_status + '</span>' : ''}
        </div>
        ${Object.keys(log.extracted_fields).length ? `
          <div class="extracted">
            <table>
              <tr><th>Campo</th><th>Valor</th></tr>
              ${Object.entries(log.extracted_fields).map(([k, v]) => `<tr><td>${k}</td><td>${JSON.stringify(v)}</td></tr>`).join('')}
            </table>
          </div>
        ` : ''}
        <details style="margin-top:8px">
          <summary style="cursor:pointer;color:#64748b;font-size:13px">Payload completo</summary>
          <pre>${JSON.stringify(log.payload, null, 2)}</pre>
        </details>
      </div>
    `).join('') : '<div class="empty">Nenhum log ainda</div>'}
  `;
}

function addFieldRow(containerId) {
  const div = document.getElementById(containerId);
  const row = document.createElement('div');
  row.className = 'field-row';
  row.innerHTML = `
    <input placeholder="Caminho (ex: data.id)">
    <input placeholder="Label (ex: ID)" data-type="label">
    <button class="btn btn-danger btn-sm" onclick="this.parentElement.remove()">x</button>
  `;
  div.appendChild(row);
}

function getFields(containerId) {
  const rows = document.getElementById(containerId).querySelectorAll('.field-row');
  return Array.from(rows).map(row => {
    const inputs = row.querySelectorAll('input');
    return { key: inputs[0].value.trim(), label: inputs[1]?.value.trim() || '' };
  }).filter(f => f.key);
}

async function saveChannel(slug) {
  await api('/api/channels/' + slug, {
    method: 'PUT',
    body: JSON.stringify({
      fields_schema: getFields('edit-fields'),
      rabbit_enabled: document.getElementById('edit-rabbit-enabled').checked,
      rabbit_queue: document.getElementById('edit-rabbit-queue').value,
      rabbit_exchange: document.getElementById('edit-rabbit-exchange').value,
      rabbit_routing_key: document.getElementById('edit-rabbit-routing').value,
    }),
  });
  openChannel(slug);
}

async function createChannel() {
  await api('/api/channels', {
    method: 'POST',
    body: JSON.stringify({
      name: document.getElementById('new-name').value,
      slug: document.getElementById('new-slug').value,
      description: document.getElementById('new-desc').value,
      secret: document.getElementById('new-secret').value,
      target_url: document.getElementById('new-target').value,
      fields_schema: getFields('new-fields'),
      rabbit_enabled: document.getElementById('new-rabbit-enabled').checked,
      rabbit_queue: document.getElementById('new-rabbit-queue').value,
      rabbit_exchange: document.getElementById('new-rabbit-exchange').value,
      rabbit_routing_key: document.getElementById('new-rabbit-routing').value,
    }),
  });
  showTab('channels');
}

async function deleteChannel(slug) {
  if (!confirm('Excluir canal e todos os logs?')) return;
  await api('/api/channels/' + slug, { method: 'DELETE' });
  showTab('channels');
}

if (TOKEN) { loadChannels(); loadRabbitStatus(); }
</script>
</body>
</html>
"""
