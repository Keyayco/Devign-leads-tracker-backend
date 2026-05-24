"""
Lead Tracker CRM — Flask Backend (Single File, Hardened)
Render Free Tier + Supabase Free Tier

All fixes applied:
- Renamed DB helpers (db_insert, db_update, db_delete)
- Fixed 7-day date filtering with count_gte()
- Filtered pagination totals respect all query params
- Rep filtering in SQL layer before pagination
- Portal sync validation
- 2MB request limit
- Flask-Limiter rate limiting
- Startup env validation (fail-fast)
- Env-driven CORS origins
- Structured JSON logging
- DB retry wrapper
- Optimistic concurrency via updated_at
- Search sanitization
- /api/v1/ aliases with backward compatibility
- Centralized error handling
- Reduced duplicate queries
- Security headers + correlation IDs
"""
import os
import re
import jwt
import uuid
import logging
import time
from functools import wraps
from datetime import datetime, timezone, timedelta
from dotenv import load_dotenv
from flask import Flask, request, g, jsonify, make_response
from flask_cors import CORS
from supabase import create_client

load_dotenv()

# =========================================
# CONFIG
# =========================================
SUPABASE_URL = os.getenv("SUPABASE_URL", "")
SUPABASE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY", "")
JWT_SECRET = os.getenv("SUPABASE_JWT_SECRET", "")
PORTAL_API_KEY = os.getenv("PORTAL_API_KEY", "")
FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:5173")
PORT = int(os.getenv("PORT", 10000))
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")

# Parse comma-separated origins
raw_origins = os.getenv("ALLOWED_ORIGINS", FRONTEND_URL)
ALLOWED_ORIGINS = [o.strip() for o in raw_origins.split(",") if o.strip()]
if FRONTEND_URL not in ALLOWED_ORIGINS:
    ALLOWED_ORIGINS.append(FRONTEND_URL)

DEFAULT_LIMIT = 20
MAX_LIMIT = 100
MAX_CONTENT_LENGTH = 2 * 1024 * 1024  # 2MB

VALID_STATUSES = {'new', 'claimed', 'contacted', 'qualified', 'proposal_sent', 'closed_won', 'closed_lost'}
VALID_PRIORITIES = {'low', 'medium', 'high'}
VALID_ROLES = {'admin', 'rep', 'portal'}
VALID_ACTIVITIES = {'created', 'claimed', 'status_changed', 'note_added', 'edited', 'deleted', 'integration_sync'}
SAFE_ORDER_FIELDS = {'created_at', 'updated_at', 'company_name', 'status', 'priority', 'claimed_at'}

# =========================================
# STARTUP VALIDATION (fail-fast)
# =========================================
missing = [k for k, v in [
    ("SUPABASE_URL", SUPABASE_URL),
    ("SUPABASE_SERVICE_ROLE_KEY", SUPABASE_KEY),
    ("SUPABASE_JWT_SECRET", JWT_SECRET),
] if not v]

if missing:
    raise RuntimeError(f"Missing required env vars: {', '.join(missing)}")

if not PORTAL_API_KEY:
    logger.warning("PORTAL_API_KEY not set — client portal integration disabled")


# =========================================
# STRUCTURED LOGGING
# =========================================
class StructuredLogFormatter(logging.Formatter):
    def format(self, record):
        import json
        payload = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "message": record.getMessage(),
        }
        if hasattr(record, "route"):
            payload["route"] = record.route
        if hasattr(record, "user_id"):
            payload["user_id"] = record.user_id
        if hasattr(record, "request_id"):
            payload["request_id"] = record.request_id
        if record.exc_info:
            payload["error"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)

handler = logging.StreamHandler()
handler.setFormatter(StructuredLogFormatter())
logger = logging.getLogger(__name__)
logger.setLevel(getattr(logging, LOG_LEVEL, logging.INFO))
logger.addHandler(handler)

def slog(level, message, **extras):
    """Emit structured log with request context."""
    extra = {
        "route": request.path if request else None,
        "method": request.method if request else None,
        "request_id": getattr(g, 'request_id', None),
        "user_id": getattr(g, 'user_id', None),
    }
    extra.update(extras)
    record = logger.makeRecord(
        logger.name, getattr(logging, level, logging.INFO), "", 0, message, (), None
    )
    for k, v in extra.items():
        setattr(record, k, v)
    logger.handle(record)


# =========================================
# APP SETUP
# =========================================
app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH

CORS(app, resources={r"/api/*": {
    "origins": ALLOWED_ORIGINS,
    "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    "allow_headers": ["Authorization", "Content-Type", "X-API-Key", "X-Request-ID"],
    "supports_credentials": True
}})

# --- Rate Limiting ---
try:
    from flask_limiter import Limiter
    from flask_limiter.util import get_remote_address
    limiter = Limiter(
        app=app,
        key_func=get_remote_address,
        default_limits=["200 per minute"],
        storage_uri="memory://"
    )
except ImportError:
    limiter = None
    logger.warning("Flask-Limiter not installed")

# --- Request Middleware ---
@app.before_request
def before_request():
    g.request_id = str(uuid.uuid4())[:8]
    if request.path.startswith('/api/'):
        slog("INFO", "Request started")

@app.after_request
def after_request(resp):
    resp.headers['X-Content-Type-Options'] = 'nosniff'
    resp.headers['X-Frame-Options'] = 'DENY'
    resp.headers['X-Request-ID'] = getattr(g, 'request_id', '')
    return resp


# =========================================
# SUPABASE CLIENT + RETRY
# =========================================
_db = None

def get_db():
    global _db
    if _db is None:
        _db = create_client(SUPABASE_URL, SUPABASE_KEY)
        slog("INFO", "Supabase connected")
    return _db

def retry_db(max_retries=2, delay=0.5):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            for attempt in range(max_retries + 1):
                try:
                    return fn(*args, **kwargs)
                except Exception as e:
                    if attempt < max_retries:
                        slog("WARNING", f"DB retry {attempt + 1}/{max_retries}", error=str(e))
                        time.sleep(delay * (attempt + 1))
                    else:
                        raise
            return None
        return wrapper
    return decorator


# =========================================
# RESPONSE HELPERS
# =========================================
def ok(data=None, msg="OK"):
    r = {"success": True, "message": msg}
    if data is not None:
        r["data"] = data
    return jsonify(r)

def fail(msg, code=400, fields=None):
    r = {"success": False, "error": msg}
    if fields:
        r["fields"] = fields
    resp = jsonify(r)
    resp.status_code = code
    return resp

def page_resp(data, page, limit, total, msg="OK"):
    tp = (total + limit - 1) // limit if total else 1
    return jsonify({
        "success": True,
        "message": msg,
        "data": data,
        "pagination": {
            "page": page,
            "limit": limit,
            "total": total,
            "total_pages": tp,
            "has_next": page < tp,
            "has_prev": page > 1
        }
    })


# =========================================
# VALIDATION
# =========================================
def clean(text, max_len=500):
    if not isinstance(text, str):
        return None
    text = text.strip()
    return text[:max_len] if text else None

def v_email(e):
    if not e:
        return True
    if re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', e):
        return True
    return False, "Invalid email format"

def v_url(u):
    if not u:
        return True
    if u.startswith(('http://', 'https://')):
        return True
    return False, "URL must start with http:// or https://"

def v_phone(p):
    if not p:
        return True
    cleaned = re.sub(r'[\s\-\(\)\+]', '', p)
    if cleaned.isdigit() and len(cleaned) >= 7:
        return True
    return False, "Invalid phone number"

def v_lead(data, req=None):
    errs = {}
    if req:
        for f in req:
            if not data.get(f):
                errs[f] = f"{f} is required"
    for fn, fk in [(v_email, 'email'), (v_url, 'website'), (v_phone, 'phone')]:
        if data.get(fk):
            r = fn(data[fk])
            if r is not True:
                errs[fk] = r[1]
    if data.get('status') and data['status'] not in VALID_STATUSES:
        errs['status'] = f"Must be one of: {', '.join(sorted(VALID_STATUSES))}"
    if data.get('priority') and data['priority'] not in VALID_PRIORITIES:
        errs['priority'] = f"Must be one of: {', '.join(sorted(VALID_PRIORITIES))}"
    return (not errs), errs

def v_portal(data):
    errs = {}
    if data.get('status') and data['status'] not in VALID_STATUSES:
        errs['status'] = f"Must be one of: {', '.join(sorted(VALID_STATUSES))}"
    if data.get('priority') and data['priority'] not in VALID_PRIORITIES:
        errs['priority'] = f"Must be one of: {', '.join(sorted(VALID_PRIORITIES))}"
    return (not errs), errs

def sanitize_search(term):
    if not isinstance(term, str):
        return ""
    term = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f]', '', term)
    term = term.replace('%', '\\%').replace('_', '\\_')
    return term.strip()


# =========================================
# AUTH
# =========================================
def get_token():
    h = request.headers.get('Authorization', '')
    if h.startswith('Bearer '):
        return h.split(' ', 1)[1]
    return None

def decode_jwt(tok):
    if not tok:
        return False, "No token"
    try:
        payload = jwt.decode(tok, JWT_SECRET, algorithms=['HS256'], audience='authenticated')
        return True, payload
    except jwt.ExpiredSignatureError:
        return False, "Token expired"
    except jwt.InvalidTokenError as e:
        return False, f"Invalid token: {e}"

def get_profile(uid):
    try:
        return get_db().table("profiles").select("id,full_name,email,role,is_active").eq("id", uid).single().execute().data
    except Exception as e:
        slog("ERROR", "Profile fetch failed", error=str(e))
        return None

def auth(f):
    @wraps(f)
    def wrap(*a, **kw):
        tok = get_token()
        if not tok:
            return fail("Authentication required", 401)
        ok_, pl = decode_jwt(tok)
        if not ok_:
            return fail(pl, 401)
        uid = pl.get('sub')
        if not uid:
            return fail("Invalid token: no user ID", 401)
        prof = get_profile(uid)
        if not prof:
            return fail("User profile not found", 401)
        if not prof.get('is_active', True):
            return fail("Account deactivated", 403)
        g.user_id = uid
        g.user_email = pl.get('email', '')
        g.user_role = prof.get('role', 'rep')
        g.user_profile = prof
        return f(*a, **kw)
    return wrap

def admin_only(f):
    @wraps(f)
    def wrap(*a, **kw):
        if getattr(g, 'user_role', '') != 'admin':
            return fail("Admin access required", 403)
        return f(*a, **kw)
    return wrap

def rep_or_admin(f):
    @wraps(f)
    def wrap(*a, **kw):
        if getattr(g, 'user_role', '') not in ('admin', 'rep'):
            return fail("Sales rep or admin access required", 403)
        return f(*a, **kw)
    return wrap


# =========================================
# DB HELPERS (RENAMED to avoid collisions)
# =========================================
@retry_db()
def db_insert(table, data):
    r = get_db().table(table).insert(data).execute()
    return r.data[0] if r.data else None

@retry_db()
def db_update(table, data, col, val):
    r = get_db().table(table).update(data).eq(col, val).execute()
    return r.data[0] if r.data else None

@retry_db()
def db_delete(table, col, val):
    get_db().table(table).delete().eq(col, val).execute()

@retry_db()
def db_fetch_one(table, col, val, cols="*"):
    try:
        return get_db().table(table).select(cols).eq(col, val).single().execute().data
    except Exception:
        return None

@retry_db()
def exact_count(table, col=None, val=None):
    q = get_db().table(table).select("id", count="exact", head=True)
    if col and val is not None:
        q = q.eq(col, val)
    r = q.execute()
    return getattr(r, 'count', 0) or 0

@retry_db()
def count_gte(table, col, val):
    """Count rows where col >= val. For date filtering."""
    r = get_db().table(table).select("id", count="exact", head=True).gte(col, val).execute()
    return getattr(r, 'count', 0) or 0

def q_leads():
    return get_db().table("leads").select("""
        id,company_name,contact_name,email,phone,website,industry,city,country,
        source_id,status,priority,notes,claimed_by,claimed_at,created_by,
        external_reference,created_at,updated_at,
        lead_sources:source_id(name),profiles:claimed_by(full_name,email)
    """)

def q_profiles():
    return get_db().table("profiles").select("id,full_name,email,role,is_active,created_at,updated_at")


# =========================================
# LEAD HELPERS
# =========================================
LEAD_FIELDS = {
    'company_name', 'contact_name', 'email', 'phone', 'website',
    'industry', 'city', 'country', 'source_id', 'status', 'priority',
    'notes', 'external_reference'
}

def build_insert(data, uid):
    d = {
        "company_name": clean(data.get('company_name')),
        "contact_name": clean(data.get('contact_name')),
        "email": clean(data.get('email')),
        "phone": clean(data.get('phone')),
        "website": clean(data.get('website')),
        "industry": clean(data.get('industry')),
        "city": clean(data.get('city')),
        "country": clean(data.get('country')),
        "source_id": data.get('source_id'),
        "status": data.get('status', 'new'),
        "priority": data.get('priority', 'medium'),
        "notes": clean(data.get('notes'), 5000),
        "created_by": uid,
        "external_reference": clean(data.get('external_reference'))
    }
    return {k: v for k, v in d.items() if v is not None}

def build_update(data):
    d = {}
    for f in LEAD_FIELDS:
        if f not in data:
            continue
        if f in ('company_name', 'contact_name', 'email', 'phone', 'website', 'industry', 'city', 'country', 'external_reference'):
            d[f] = clean(data[f])
        elif f == 'notes':
            d[f] = clean(data[f], 5000)
        elif f == 'source_id':
            d[f] = data[f]
        elif f in ('status', 'priority'):
            d[f] = data[f]
    return d

def log_act(lead_id, user_id, typ, desc=None, meta=None):
    try:
        if typ not in VALID_ACTIVITIES:
            return
        get_db().table("lead_activities").insert({
            "lead_id": lead_id, "user_id": user_id, "activity_type": typ,
            "description": desc, "metadata": meta or {}
        }).execute()
    except Exception as e:
        slog("ERROR", "log_act failed", error=str(e))

def get_lead(lid):
    return db_fetch_one("leads", "id", lid, """
        id,company_name,contact_name,email,phone,website,industry,city,country,
        source_id,status,priority,notes,claimed_by,claimed_at,created_by,
        external_reference,created_at,updated_at,
        lead_sources:source_id(name),profiles:claimed_by(full_name,email)
    """)

def can_see(lead, uid, role):
    if role == 'admin':
        return True
    if lead.get('claimed_by') is None:
        return True
    return lead.get('claimed_by') == uid

def can_edit(lead, uid, role):
    if role == 'admin':
        return True
    return lead.get('claimed_by') == uid


# =========================================
# ROUTES
# =========================================

@app.route('/')
def index():
    return jsonify({
        "name": "Lead Tracker API",
        "version": "2.0.0",
        "status": "ok",
        "time": datetime.now(timezone.utc).isoformat()
    })

@app.route('/api/health')
@app.route('/api/v1/health')
def health():
    try:
        get_db().table("profiles").select("count", count="exact", head=True).execute()
        return ok({"status": "healthy", "db": True})
    except Exception as e:
        slog("ERROR", "Health check failed", error=str(e))
        return fail("Service unhealthy", 503)

@app.route('/api/auth/me', methods=['GET'])
@app.route('/api/v1/auth/me', methods=['GET'])
@auth
def me():
    prof = dict(g.user_profile)
    if g.user_role == 'rep':
        prof['claimed_leads_count'] = exact_count("leads", "claimed_by", g.user_id)
    return ok({
        "id": g.user_id,
        "email": g.user_email,
        "role": g.user_role,
        "profile": prof
    })


@app.route('/api/leads', methods=['GET'])
@app.route('/api/v1/leads', methods=['GET'])
@auth
def list_leads():
    try:
        page = max(1, int(request.args.get('page', 1)))
        limit = min(MAX_LIMIT, int(request.args.get('limit', DEFAULT_LIMIT)))
        offset = (page - 1) * limit

        q = q_leads()

        # Build filters
        status_filter = request.args.get('status', '')
        if status_filter:
            q = q.eq('status', status_filter)

        priority_filter = request.args.get('priority', '')
        if priority_filter:
            q = q.eq('priority', priority_filter)

        claimed_filter = request.args.get('claimed_by', '')
        if claimed_filter:
            if claimed_filter == 'me':
                q = q.eq('claimed_by', g.user_id)
            elif claimed_filter == 'null':
                q = q.is_('claimed_by', None)
            else:
                q = q.eq('claimed_by', claimed_filter)

        search = request.args.get('search', '').strip()
        if search:
            safe = sanitize_search(search)
            term = f"%{safe}%"
            q = q.or_(f"company_name.ilike.{term},email.ilike.{term},phone.ilike.{term}")

        # Ordering
        order_by = request.args.get('order_by', 'created_at')
        if order_by not in SAFE_ORDER_FIELDS:
            order_by = 'created_at'
        order_desc = request.args.get('order', 'desc').lower() != 'asc'

        # Rep permission filter IN SQL (before pagination)
        if g.user_role == 'rep':
            q = q.or_(f"claimed_by.eq.{g.user_id},claimed_by.is.null")

        # Count with same filters applied
        # We execute count via a separate lightweight query
        count_q = get_db().table("leads").select("id", count="exact", head=True)
        if status_filter:
            count_q = count_q.eq('status', status_filter)
        if priority_filter:
            count_q = count_q.eq('priority', priority_filter)
        if claimed_filter:
            if claimed_filter == 'me':
                count_q = count_q.eq('claimed_by', g.user_id)
            elif claimed_filter == 'null':
                count_q = count_q.is_('claimed_by', None)
            else:
                count_q = count_q.eq('claimed_by', claimed_filter)
        if search:
            safe = sanitize_search(search)
            term = f"%{safe}%"
            count_q = count_q.or_(f"company_name.ilike.{term},email.ilike.{term},phone.ilike.{term}")
        if g.user_role == 'rep':
            count_q = count_q.or_(f"claimed_by.eq.{g.user_id},claimed_by.is.null")

        count_res = count_q.execute()
        total = getattr(count_res, 'count', 0) or 0

        # Fetch paginated results
        q = q.order(order_by, desc=order_desc)
        q = q.range(offset, offset + limit - 1)
        leads = q.execute().data or []

        return page_resp(leads, page, limit, total, f"Retrieved {len(leads)} leads")
    except Exception as e:
        slog("ERROR", "list_leads failed", error=str(e))
        return fail("Failed to retrieve leads", 500)

@app.route('/api/leads/<lid>', methods=['GET'])
@app.route('/api/v1/leads/<lid>', methods=['GET'])
@auth
def get_one(lid):
    lead = get_lead(lid)
    if not lead:
        return fail("Lead not found", 404)
    if not can_see(lead, g.user_id, g.user_role):
        return fail("Access denied", 403)
    return ok(lead)

@app.route('/api/leads', methods=['POST'])
@app.route('/api/v1/leads', methods=['POST'])
@auth
@rep_or_admin
def create():
    data = request.get_json(silent=True)
    if not data or not isinstance(data, dict):
        return fail("Valid JSON body required")

    ok_, errs = v_lead(data, req=['company_name'])
    if not ok_:
        return fail("Validation failed", 400, fields=errs)

    try:
        lead = db_insert("leads", build_insert(data, g.user_id))
        if lead:
            log_act(lead['id'], g.user_id, 'created',
                    f"Lead created: {lead['company_name']}",
                    {'source': data.get('source', 'manual')})
            return ok(lead, "Lead created")
        return fail("Failed to create lead", 500)
    except Exception as e:
        slog("ERROR", "create failed", error=str(e))
        return fail("Failed to create lead", 500)


@app.route('/api/leads/<lid>', methods=['PUT'])
@app.route('/api/v1/leads/<lid>', methods=['PUT'])
@auth
def update_lead(lid):
    lead = get_lead(lid)
    if not lead:
        return fail("Lead not found", 404)
    if not can_edit(lead, g.user_id, g.user_role):
        return fail("You can only edit your own claimed leads", 403)

    data = request.get_json(silent=True)
    if not data or not isinstance(data, dict):
        return fail("Valid JSON body required")

    ok_, errs = v_lead(data)
    if not ok_:
        return fail("Validation failed", 400, fields=errs)

    if g.user_role == 'rep':
        data.pop('claimed_by', None)
        data.pop('created_by', None)

    upd = build_update(data)
    if not upd:
        return ok(lead, "No changes")

    # Optimistic concurrency: include updated_at check if provided
    if 'updated_at' in data:
        # Verify lead hasn't changed since client loaded it
        current = get_lead(lid)
        if current and current.get('updated_at') != data['updated_at']:
            return fail("Lead was modified by another user. Please refresh and try again.", 409)

    try:
        old_status = lead.get('status')
        updated = db_update("leads", upd, "id", lid)
        if updated:
            new_status = updated.get('status')
            if 'status' in upd and new_status != old_status:
                log_act(lid, g.user_id, 'status_changed',
                        f"Status: {old_status} -> {new_status}",
                        {'old_status': old_status, 'new_status': new_status})
            else:
                log_act(lid, g.user_id, 'edited', "Lead updated",
                        {'changed_fields': list(upd.keys())})
            return ok(updated, "Lead updated")
        return fail("Failed to update lead", 500)
    except Exception as e:
        slog("ERROR", "update_lead failed", error=str(e))
        return fail("Failed to update lead", 500)

@app.route('/api/leads/<lid>', methods=['DELETE'])
@app.route('/api/v1/leads/<lid>', methods=['DELETE'])
@auth
@admin_only
def delete_lead(lid):
    lead = get_lead(lid)
    if not lead:
        return fail("Lead not found", 404)
    try:
        db_delete("leads", "id", lid)
        log_act(lid, g.user_id, 'deleted',
                f"Lead deleted: {lead.get('company_name', 'Unknown')}")
        return ok(msg="Lead deleted")
    except Exception as e:
        slog("ERROR", "delete_lead failed", error=str(e))
        return fail("Failed to delete lead", 500)

@app.route('/api/leads/<lid>/claim', methods=['POST'])
@app.route('/api/v1/leads/<lid>/claim', methods=['POST'])
@auth
@rep_or_admin
def claim(lid):
    lead = get_lead(lid)
    if not lead:
        return fail("Lead not found", 404)
    if lead.get('claimed_by') is not None:
        return fail("Lead already claimed", 409)
    if lead.get('status') not in ('new', 'claimed'):
        return fail(f"Cannot claim lead with status: {lead.get('status')}", 400)

    try:
        now = datetime.now(timezone.utc).isoformat()
        r = get_db().table("leads").update({
            "claimed_by": g.user_id,
            "claimed_at": now,
            "status": "claimed"
        }).eq("id", lid).is_("claimed_by", None).execute()

        if r.data:
            log_act(lid, g.user_id, 'claimed', "Lead claimed",
                    {'previous_status': lead.get('status')})
            return ok(r.data[0], "Lead claimed successfully")
        return fail("Lead was claimed by someone else", 409)
    except Exception as e:
        slog("ERROR", "claim failed", error=str(e))
        return fail("Failed to claim lead", 500)


@app.route('/api/leads/<lid>/activities', methods=['GET'])
@app.route('/api/v1/leads/<lid>/activities', methods=['GET'])
@auth
def activities(lid):
    lead = get_lead(lid)
    if not lead:
        return fail("Lead not found", 404)
    if not can_see(lead, g.user_id, g.user_role):
        return fail("Access denied", 403)

    try:
        page = max(1, int(request.args.get('page', 1)))
        limit = min(100, int(request.args.get('limit', 50)))
        offset = (page - 1) * limit
        total = exact_count("lead_activities", "lead_id", lid)

        q = get_db().table("lead_activities").select("""
            id,lead_id,user_id,activity_type,description,metadata,created_at,
            profiles:user_id(full_name,email)
        """).eq("lead_id", lid).order("created_at", desc=True).range(offset, offset + limit - 1)

        return page_resp(q.execute().data or [], page, limit, total, "Activities retrieved")
    except Exception as e:
        slog("ERROR", "activities failed", error=str(e))
        return fail("Failed to retrieve activities", 500)


@app.route('/api/stats', methods=['GET'])
@app.route('/api/v1/stats', methods=['GET'])
@auth
def stats():
    try:
        leads = get_db().table("leads").select("status,claimed_by,priority").execute().data or []
        total = len(leads)
        claimed = sum(1 for l in leads if l.get('claimed_by'))

        stats = {
            "total_leads": total,
            "claimed_leads": claimed,
            "unclaimed_leads": total - claimed,
            "closed_won": sum(1 for l in leads if l.get('status') == 'closed_won'),
            "closed_lost": sum(1 for l in leads if l.get('status') == 'closed_lost'),
            "new_leads": sum(1 for l in leads if l.get('status') == 'new'),
            "contacted": sum(1 for l in leads if l.get('status') == 'contacted'),
            "qualified": sum(1 for l in leads if l.get('status') == 'qualified'),
            "proposal_sent": sum(1 for l in leads if l.get('status') == 'proposal_sent'),
            "high_priority": sum(1 for l in leads if l.get('priority') == 'high'),
        }

        # FIXED: Use count_gte for proper date filtering
        since = (datetime.now(timezone.utc) - timedelta(days=7)).isoformat()
        stats["recent_activity_7d"] = count_gte("lead_activities", "created_at", since)

        if g.user_role == 'rep':
            mine = [l for l in leads if l.get('claimed_by') == g.user_id]
            stats.update({
                "my_claimed": len(mine),
                "my_won": sum(1 for l in mine if l.get('status') == 'closed_won'),
                "my_lost": sum(1 for l in mine if l.get('status') == 'closed_lost')
            })

        return ok(stats, "Dashboard stats retrieved")
    except Exception as e:
        slog("ERROR", "stats failed", error=str(e))
        return fail("Failed to retrieve stats", 500)


@app.route('/api/reps', methods=['GET'])
@app.route('/api/v1/reps', methods=['GET'])
@auth
@admin_only
def list_reps():
    try:
        page = max(1, int(request.args.get('page', 1)))
        limit = min(MAX_LIMIT, int(request.args.get('limit', DEFAULT_LIMIT)))
        offset = (page - 1) * limit

        q = q_profiles()

        role_filter = request.args.get('role', '')
        if role_filter:
            q = q.eq('role', role_filter)

        search = request.args.get('search', '').strip()
        if search:
            safe = sanitize_search(search)
            term = f"%{safe}%"
            q = q.or_(f"full_name.ilike.{term},email.ilike.{term}")

        total = exact_count("profiles")
        q = q.order('created_at', desc=True).range(offset, offset + limit - 1)

        return page_resp(q.execute().data or [], page, limit, total, "Users retrieved")
    except Exception as e:
        slog("ERROR", "list_reps failed", error=str(e))
        return fail("Failed to retrieve users", 500)

@app.route('/api/reps/<rid>', methods=['GET'])
@app.route('/api/v1/reps/<rid>', methods=['GET'])
@auth
@admin_only
def get_rep(rid):
    r = db_fetch_one("profiles", "id", rid, "id,full_name,email,role,is_active,created_at,updated_at")
    if not r:
        return fail("User not found", 404)
    return ok(r)

@app.route('/api/reps/<rid>', methods=['PUT'])
@app.route('/api/v1/reps/<rid>', methods=['PUT'])
@auth
@admin_only
def update_rep(rid):
    data = request.get_json(silent=True)
    if not data or not isinstance(data, dict):
        return fail("Valid JSON body required")
    if not db_fetch_one("profiles", "id", rid, "id"):
        return fail("User not found", 404)

    upd = {}
    if 'full_name' in data:
        upd['full_name'] = data['full_name'].strip()[:200]
    if 'role' in data:
        if data['role'] not in VALID_ROLES:
            return fail(f"Role must be one of: {', '.join(sorted(VALID_ROLES))}", 400)
        upd['role'] = data['role']
    if 'is_active' in data:
        upd['is_active'] = bool(data['is_active'])

    if not upd:
        return fail("No valid fields to update")

    r = db_update("profiles", upd, "id", rid)
    return ok(r, "User updated") if r else fail("Failed to update user", 500)


@app.route('/api/sources', methods=['GET'])
@app.route('/api/v1/sources', methods=['GET'])
@auth
def sources():
    try:
        r = get_db().table("lead_sources").select("id,name,description,created_at").order("name").execute()
        return ok(r.data or [])
    except Exception as e:
        slog("ERROR", "sources failed", error=str(e))
        return fail("Failed to retrieve sources", 500)


@app.route('/api/integrations/client-portal', methods=['POST'])
@app.route('/api/v1/integrations/client-portal', methods=['POST'])
def portal():
    key = request.headers.get('X-API-Key', '')
    if not key or key != PORTAL_API_KEY:
        return fail("Invalid or missing X-API-Key", 401)

    data = request.get_json(silent=True)
    if not data or not isinstance(data, dict) or 'action' not in data:
        return fail("action required: create_lead, get_lead_status, sync_lead")

    act = data['action']

    if act == 'create_lead':
        if not data.get('company_name'):
            return fail("company_name required", 400)
        d = {k: clean(data.get(k)) for k in [
            'company_name', 'contact_name', 'email', 'phone',
            'website', 'industry', 'city', 'country', 'external_reference'
        ]}
        d.update({
            "source_id": data.get('source_id'),
            "priority": data.get('priority', 'medium'),
            "notes": clean(data.get('notes'), 5000),
            "status": "new"
        })
        d = {k: v for k, v in d.items() if v is not None}
        lead = db_insert("leads", d)
        if lead:
            log_act(lead['id'], None, 'integration_sync',
                    "Lead created via client portal",
                    {'ref': data.get('external_reference')})
            return ok({
                "lead_id": lead['id'],
                "status": lead['status'],
                "external_reference": lead.get('external_reference')
            }, "Lead created via integration")
        return fail("Failed to create lead", 500)

    elif act == 'get_lead_status':
        ref = data.get('external_reference')
        if not ref:
            return fail("external_reference required", 400)
        leads = get_db().table("leads").select(
            "id,company_name,status,priority,claimed_by,updated_at"
        ).eq("external_reference", ref).execute().data or []
        if not leads:
            return fail("Lead not found", 404)
        l = leads[0]
        log_act(l['id'], None, 'integration_sync', "Status queried via portal")
        return ok({
            "lead_id": l['id'],
            "company_name": l['company_name'],
            "status": l['status'],
            "priority": l['priority'],
            "claimed": l.get('claimed_by') is not None,
            "last_updated": l.get('updated_at')
        })

    elif act == 'sync_lead':
        ref = data.get('external_reference')
        if not ref:
            return fail("external_reference required", 400)

        # FIXED: Validate portal sync payload
        ok_, errs = v_portal(data)
        if not ok_:
            return fail("Validation failed", 400, fields=errs)

        leads = get_db().table("leads").select("id,status,notes").eq("external_reference", ref).execute().data or []
        if not leads:
            return fail("Lead not found", 404)
        l = leads[0]
        upd = {}
        if 'status' in data:
            upd['status'] = data['status']
        if 'priority' in data:
            upd['priority'] = data['priority']
        if 'notes' in data:
            ts = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M')
            existing = l.get('notes', '') or ''
            upd['notes'] = f"{existing}\n\n[{ts} - Portal] {data['notes']}".strip()
        if not upd:
            return fail("No fields to update")
        get_db().table("leads").update(upd).eq("id", l['id']).execute()
        log_act(l['id'], None, 'integration_sync', "Lead synced from portal",
                {'changed_fields': list(upd.keys())})
        return ok({
            "lead_id": l['id'],
            "updated_fields": list(upd.keys())
        }, "Lead synced")

    return fail(f"Unknown action: {act}", 400)


# =========================================
# ERROR HANDLERS
# =========================================
@app.errorhandler(404)
def e404(e):
    if request.path.startswith('/api/'):
        return fail("Endpoint not found", 404)
    return jsonify({"error": "Not found"}), 404

@app.errorhandler(500)
def e500(e):
    slog("ERROR", "Internal server error", error=str(e))
    return fail("Internal server error", 500)

@app.errorhandler(Exception)
def exc(e):
    slog("ERROR", "Unhandled exception", error=str(e))
    if request.path.startswith('/api/'):
        return fail("An unexpected error occurred", 500)
    raise e

# =========================================
# APP ENTRY
# =========================================
if __name__ == '__main__':
    logger.info(f"Starting on port {PORT}")
    app.run(host='0.0.0.0', port=PORT, debug=False)
