from __future__ import annotations

import os
import hmac
import secrets
import smtplib
from datetime import datetime, timezone
from datetime import timedelta
from decimal import Decimal
from email.message import EmailMessage
from functools import wraps
from hashlib import sha256
from urllib.parse import urlparse

import requests
from flask import Flask, flash, jsonify, redirect, render_template, request, session, url_for
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func, or_
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash


db = SQLAlchemy()

DISPLAY_CURRENCIES = {
    "INR": 1.0,
    "USD": 83.10,
    "EUR": 90.30,
    "GBP": 105.20,
    "AED": 22.63,
    "AUD": 54.30,
    "CAD": 60.90,
    "SGD": 61.50,
}
LOGIN_WINDOW_SECONDS = 15 * 60
LOGIN_MAX_ATTEMPTS = 10

RAZORPAY_SUPPORTED = {"INR", "USD", "EUR", "GBP", "AED", "SGD"}
PROVIDER_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
    "Accept": "application/json,text/plain,*/*",
    "Referer": "https://themainsmmprovider.com/",
}


class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    full_name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=True)
    phone = db.Column(db.String(30), nullable=True)
    country = db.Column(db.String(80), nullable=True)
    password_hash = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, nullable=False, default=False)
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    wallet_inr = db.Column(db.Float, nullable=False, default=0.0)
    preferred_currency = db.Column(db.String(8), nullable=False, default="INR")
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    last_login_at = db.Column(db.DateTime(timezone=True), nullable=True)


class Service(db.Model):
    __tablename__ = "services"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(160), nullable=False)
    category = db.Column(db.String(80), nullable=False)
    description = db.Column(db.Text, nullable=False)
    price_inr = db.Column(db.Float, nullable=False)
    base_price_inr = db.Column(db.Float, nullable=True)
    markup_percent = db.Column(db.Float, nullable=False, default=0.0)
    provider_service_id = db.Column(db.String(64), nullable=True)
    min_quantity = db.Column(db.Integer, nullable=False)
    max_quantity = db.Column(db.Integer, nullable=False)
    avg_start = db.Column(db.String(40), nullable=False)
    is_active = db.Column(db.Boolean, nullable=False, default=True)


class Order(db.Model):
    __tablename__ = "orders"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    service_id = db.Column(db.Integer, db.ForeignKey("services.id"), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    target_link = db.Column(db.String(500), nullable=False)
    note = db.Column(db.Text, nullable=True)
    total_inr = db.Column(db.Float, nullable=False)
    status = db.Column(db.String(40), nullable=False, default="Queued")
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))

    user = db.relationship(User, backref="orders")
    service = db.relationship(Service)


class WalletTransaction(db.Model):
    __tablename__ = "wallet_transactions"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    amount_inr = db.Column(db.Float, nullable=False)
    original_amount = db.Column(db.Float, nullable=False)
    original_currency = db.Column(db.String(8), nullable=False)
    payment_method = db.Column(db.String(40), nullable=False)
    reference_note = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))

    user = db.relationship(User, backref="wallet_transactions")


class PaymentOrder(db.Model):
    __tablename__ = "payment_orders"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    provider = db.Column(db.String(40), nullable=False, default="razorpay")
    provider_order_id = db.Column(db.String(120), unique=True, nullable=False)
    provider_payment_id = db.Column(db.String(120), nullable=True)
    amount_inr = db.Column(db.Float, nullable=False)
    original_amount = db.Column(db.Float, nullable=False)
    original_currency = db.Column(db.String(8), nullable=False)
    status = db.Column(db.String(40), nullable=False, default="created")
    verified_at = db.Column(db.DateTime(timezone=True), nullable=True)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))

    user = db.relationship(User, backref="payment_orders")


class ProviderLog(db.Model):
    __tablename__ = "provider_logs"
    id = db.Column(db.Integer, primary_key=True)
    action = db.Column(db.String(80), nullable=False)
    status = db.Column(db.String(40), nullable=False)
    request_payload = db.Column(db.Text, nullable=True)
    response_payload = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))


class ManualPaymentConfig(db.Model):
    __tablename__ = "manual_payment_config"
    id = db.Column(db.Integer, primary_key=True)
    upi_id = db.Column(db.String(120), nullable=True)
    qr_image_url = db.Column(db.String(500), nullable=True)
    note = db.Column(db.String(255), nullable=True)
    updated_at = db.Column(db.DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))


class ManualTopupRequest(db.Model):
    __tablename__ = "manual_topup_requests"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    amount_inr = db.Column(db.Float, nullable=False)
    original_amount = db.Column(db.Float, nullable=False)
    original_currency = db.Column(db.String(8), nullable=False)
    utr_or_ref = db.Column(db.String(120), nullable=True)
    screenshot_url = db.Column(db.String(500), nullable=True)
    note = db.Column(db.String(255), nullable=True)
    status = db.Column(db.String(20), nullable=False, default="pending")
    admin_note = db.Column(db.String(255), nullable=True)
    reviewed_by_user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    reviewed_at = db.Column(db.DateTime(timezone=True), nullable=True)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))

    user = db.relationship(User, foreign_keys=[user_id], backref="manual_topup_requests")
    reviewed_by_user = db.relationship(User, foreign_keys=[reviewed_by_user_id])


class PasswordResetToken(db.Model):
    __tablename__ = "password_reset_tokens"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    token_hash = db.Column(db.String(64), unique=True, nullable=False)
    expires_at = db.Column(db.DateTime(timezone=True), nullable=False)
    used_at = db.Column(db.DateTime(timezone=True), nullable=True)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))

    user = db.relationship(User, backref="password_reset_tokens")


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def is_past(dt: datetime | None) -> bool:
    if dt is None:
        return True
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt <= now_utc()


def inr_to_currency(amount_inr: float, currency: str) -> float:
    return amount_inr / DISPLAY_CURRENCIES.get(currency, 1.0)


def currency_to_inr(amount: float, currency: str) -> float:
    return amount * DISPLAY_CURRENCIES.get(currency, 1.0)


def stringify_payload(payload: object) -> str:
    return str(payload)[:4000]


def decorate_service_name(name: str, category: str) -> str:
    if not name:
        return name

    existing_prefixes = ("🔥", "🚀", "💎", "📈", "⚡", "🎯", "👑", "🌟")
    if name.startswith(existing_prefixes):
        return name

    category_lower = (category or "").lower()
    emoji = "📈"
    if "instagram" in category_lower:
        emoji = "📸"
    elif "youtube" in category_lower:
        emoji = "▶️"
    elif "telegram" in category_lower:
        emoji = "✈️"
    elif "tiktok" in category_lower:
        emoji = "🎵"
    elif "facebook" in category_lower:
        emoji = "👥"
    elif "spotify" in category_lower:
        emoji = "🎧"

    return f"{emoji} {name}"


def smart_round_price(value: float) -> float:
    if value <= 0:
        return value

    if value < 100:
        return round(value, 2)

    rounded_int = int(round(value))
    ending = rounded_int % 10
    if ending <= 4:
        target = rounded_int - ending + 9
    else:
        target = rounded_int - ending + 9
    if target < rounded_int:
        target += 10
    return float(target)


def default_service_description(category: str) -> str:
    category_label = category or "Social"
    return f"Reliable {category_label} growth service with managed delivery."


def default_avg_start(category: str | None = None, rate: float | None = None) -> str:
    category_lower = (category or "").lower()
    rate_value = float(rate or 0)

    if "instagram" in category_lower:
        return "5 min" if rate_value < 120 else "10 min"
    if "youtube" in category_lower:
        return "15 min" if rate_value < 180 else "30 min"
    if "telegram" in category_lower:
        return "20 min"
    if "tiktok" in category_lower:
        return "10 min"
    if "facebook" in category_lower:
        return "15 min"
    return "15 min"


def create_app() -> Flask:
    base_dir = os.path.dirname(os.path.abspath(__file__))
    templates_candidate = os.path.join(base_dir, "templates")
    static_candidate = os.path.join(base_dir, "static")

    required_templates = {
        "base.html",
        "login.html",
        "register.html",
        "customer_base.html",
        "customer_overview.html",
        "admin_base.html",
    }
    template_dir = base_dir
    if os.path.isdir(templates_candidate):
        present = {
            name for name in required_templates
            if os.path.isfile(os.path.join(templates_candidate, name))
        }
        if present == required_templates:
            template_dir = templates_candidate

    static_dir = static_candidate if os.path.isdir(static_candidate) and os.path.isfile(os.path.join(static_candidate, "style.css")) else base_dir

    app = Flask(
        __name__,
        template_folder=template_dir,
        static_folder=static_dir,
        static_url_path="/static",
    )
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
    database_url = os.environ.get("DATABASE_URL", "sqlite:///panel.db")
    if database_url.startswith("postgres://"):
        database_url = database_url.replace("postgres://", "postgresql://", 1)

    app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "change-me-for-production")
    app.config["SQLALCHEMY_DATABASE_URI"] = database_url
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config["SESSION_COOKIE_SECURE"] = True
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=12)
    app.config["RAZORPAY_KEY_ID"] = os.environ.get("RAZORPAY_KEY_ID", "")
    app.config["RAZORPAY_KEY_SECRET"] = os.environ.get("RAZORPAY_KEY_SECRET", "")
    app.config["RAZORPAY_WEBHOOK_SECRET"] = os.environ.get("RAZORPAY_WEBHOOK_SECRET", "")
    app.config["BASE_URL"] = os.environ.get("BASE_URL", "http://127.0.0.1:5000")
    app.config["SMM_API_URL"] = os.environ.get("SMM_API_URL", "").strip()
    app.config["SMM_API_KEY"] = os.environ.get("SMM_API_KEY", "").strip()
    app.config["SMTP_HOST"] = os.environ.get("SMTP_HOST", "smtp.gmail.com").strip()
    app.config["SMTP_PORT"] = int(os.environ.get("SMTP_PORT", "587") or "587")
    app.config["SMTP_USERNAME"] = os.environ.get("SMTP_USERNAME", "").strip()
    app.config["SMTP_PASSWORD"] = os.environ.get("SMTP_PASSWORD", "").strip()
    app.config["SMTP_FROM_EMAIL"] = os.environ.get("SMTP_FROM_EMAIL", "").strip()
    db.init_app(app)

    def get_current_user() -> User | None:
        user_id = session.get("user_id")
        if not user_id:
            return None
        return db.session.get(User, user_id)

    def has_razorpay() -> bool:
        return bool(app.config["RAZORPAY_KEY_ID"] and app.config["RAZORPAY_KEY_SECRET"])

    def has_provider_api() -> bool:
        return bool(app.config["SMM_API_URL"] and app.config["SMM_API_KEY"])

    def has_smtp_email() -> bool:
        return bool(
            app.config["SMTP_HOST"]
            and app.config["SMTP_PORT"]
            and app.config["SMTP_USERNAME"]
            and app.config["SMTP_PASSWORD"]
        )

    def get_manual_payment_config() -> ManualPaymentConfig:
        config = ManualPaymentConfig.query.first()
        if config is None:
            config = ManualPaymentConfig(upi_id="", qr_image_url="", note="Pay via UPI and submit reference for approval.")
            db.session.add(config)
            db.session.commit()
        return config

    def create_razorpay_order(payload: dict) -> dict:
        response = requests.post(
            "https://api.razorpay.com/v1/orders",
            auth=(app.config["RAZORPAY_KEY_ID"], app.config["RAZORPAY_KEY_SECRET"]),
            json=payload,
            timeout=30,
        )
        response.raise_for_status()
        return response.json()

    def verify_razorpay_signature(order_id: str, payment_id: str, signature: str) -> bool:
        body = f"{order_id}|{payment_id}".encode("utf-8")
        secret = app.config["RAZORPAY_KEY_SECRET"].encode("utf-8")
        expected = hmac.new(secret, body, sha256).hexdigest()
        return hmac.compare_digest(expected, signature)

    def verify_razorpay_webhook_signature(raw_body: bytes, signature: str) -> bool:
        secret_value = app.config["RAZORPAY_WEBHOOK_SECRET"]
        if not secret_value:
            return False
        secret = secret_value.encode("utf-8")
        expected = hmac.new(secret, raw_body, sha256).hexdigest()
        return hmac.compare_digest(expected, signature or "")

    def credit_payment_order(payment_order: PaymentOrder, payment_id: str, source: str) -> bool:
        if payment_order.status == "paid":
            return False

        payment_order.status = "paid"
        payment_order.provider_payment_id = payment_id
        payment_order.verified_at = now_utc()
        payment_order.user.wallet_inr += payment_order.amount_inr

        db.session.add(
            WalletTransaction(
                user_id=payment_order.user_id,
                amount_inr=payment_order.amount_inr,
                original_amount=payment_order.original_amount,
                original_currency=payment_order.original_currency,
                payment_method="Razorpay",
                reference_note=f"{source} payment {payment_id}",
            )
        )
        db.session.commit()
        return True

    def call_provider_api(action: str, extra_payload: dict | None = None) -> dict:
        if not has_provider_api():
            raise RuntimeError("Provider API is not configured.")

        payload = {"key": app.config["SMM_API_KEY"], "action": action}
        if extra_payload:
            payload.update(extra_payload)

        response = requests.post(
            app.config["SMM_API_URL"],
            data=payload,
            headers=PROVIDER_HEADERS,
            timeout=45,
        )
        response.raise_for_status()
        try:
            data = response.json()
        except ValueError:
            data = {"raw": response.text}

        safe_payload = dict(payload)
        if safe_payload.get("key"):
            safe_payload["key"] = "***"

        db.session.add(
            ProviderLog(
                action=action,
                status="success",
                request_payload=stringify_payload(safe_payload),
                response_payload=stringify_payload(data),
            )
        )
        db.session.commit()
        return data

    def log_provider_failure(action: str, payload: dict, error_message: str) -> None:
        safe_payload = dict(payload or {})
        if safe_payload.get("key"):
            safe_payload["key"] = "***"
        db.session.add(
            ProviderLog(
                action=action,
                status="error",
                request_payload=stringify_payload(safe_payload),
                response_payload=error_message[:4000],
            )
        )
        db.session.commit()

    def send_password_reset_email(to_email: str, reset_link: str) -> bool:
        if not has_smtp_email():
            return False

        from_email = app.config["SMTP_FROM_EMAIL"] or app.config["SMTP_USERNAME"]
        msg = EmailMessage()
        msg["Subject"] = "BoostHive Password Reset"
        msg["From"] = from_email
        msg["To"] = to_email
        msg.set_content(
            "We received a password reset request for your BoostHive account.\n\n"
            f"Reset link: {reset_link}\n\n"
            "This link expires in 30 minutes.\n"
            "If you did not request this, you can ignore this email."
        )

        try:
            with smtplib.SMTP(app.config["SMTP_HOST"], app.config["SMTP_PORT"], timeout=30) as server:
                server.starttls()
                server.login(app.config["SMTP_USERNAME"], app.config["SMTP_PASSWORD"])
                server.send_message(msg)
            return True
        except Exception:
            return False

    def test_provider_action(action: str) -> tuple[bool, str]:
        if not has_provider_api():
            return False, "Provider API is not configured."

        payload = {"key": "***", "action": action}
        try:
            data = call_provider_api(action)
            return True, stringify_payload(data)
        except Exception as exc:
            log_provider_failure(action, payload, str(exc))
            return False, str(exc)

    def provider_debug_snapshot() -> dict:
        api_url = app.config["SMM_API_URL"]
        api_key = app.config["SMM_API_KEY"]
        key_preview = ""
        if api_key:
            if len(api_key) <= 8:
                key_preview = "*" * len(api_key)
            else:
                key_preview = f"{api_key[:4]}...{api_key[-4:]}"

        snapshot: dict[str, object] = {
            "configured": has_provider_api(),
            "api_url": api_url,
            "api_key_length": len(api_key or ""),
            "api_key_preview": key_preview,
            "tests": {},
        }

        for action in ("services", "balance"):
            payload = {"key": api_key, "action": action}
            try:
                response = requests.post(
                    api_url,
                    data=payload,
                    headers=PROVIDER_HEADERS,
                    timeout=45,
                )
                sample = response.text[:400]
                entry = {
                    "http_status": response.status_code,
                    "ok": response.ok,
                    "body_sample": sample,
                }
                if response.ok:
                    try:
                        entry["json_sample"] = response.json()
                    except ValueError:
                        pass
                snapshot["tests"][action] = entry
            except Exception as exc:
                snapshot["tests"][action] = {"error": str(exc)}

        return snapshot

    def login_required(view):
        @wraps(view)
        def wrapped_view(**kwargs):
            if session.get("user_id") is None:
                return redirect(url_for("login"))
            return view(**kwargs)

        return wrapped_view

    def admin_required(view):
        @wraps(view)
        def wrapped_view(**kwargs):
            user = get_current_user()
            if user is None or not user.is_admin:
                flash("Admin access required.", "error")
                return redirect(url_for("customer_overview"))
            return view(**kwargs)

        return wrapped_view

    failed_login_attempts: dict[str, list[datetime]] = {}

    def ensure_csrf_token() -> str:
        token = session.get("csrf_token")
        if not token:
            token = secrets.token_urlsafe(32)
            session["csrf_token"] = token
        return token

    def get_supplied_csrf_token() -> str:
        return request.form.get("csrf_token", "") or request.headers.get("X-CSRF-Token", "")

    def is_csrf_token_valid() -> bool:
        expected = session.get("csrf_token", "")
        supplied = get_supplied_csrf_token()
        if not expected or not supplied:
            return False
        return hmac.compare_digest(expected, supplied)

    def is_csrf_origin_allowed() -> bool:
        origin = request.headers.get("Origin", "").strip()
        referer = request.headers.get("Referer", "").strip()
        request_host = urlparse(request.host_url).netloc
        expected_hosts = {request_host}
        base_url = app.config.get("BASE_URL", "").strip()
        if base_url:
            base_host = urlparse(base_url).netloc
            if base_host:
                expected_hosts.add(base_host)

        if origin:
            return urlparse(origin).netloc in expected_hosts
        if referer:
            return urlparse(referer).netloc in expected_hosts
        return False

    @app.before_request
    def security_before_request():
        ensure_csrf_token()
        if request.method == "POST":
            # Razorpay endpoints have their own signature verification.
            if request.endpoint in {"razorpay_webhook", "razorpay_callback"}:
                return None
            if not is_csrf_origin_allowed():
                return jsonify({"ok": False, "error": "Invalid request origin"}), 403
            supplied_token = get_supplied_csrf_token()
            if supplied_token and not is_csrf_token_valid():
                return jsonify({"ok": False, "error": "Invalid CSRF token"}), 403
        return None

    @app.after_request
    def apply_security_headers(response):
        response.headers["X-Frame-Options"] = "SAMEORIGIN"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        if request.is_secure:
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response

    @app.context_processor
    def inject_globals():
        current_user = get_current_user()
        preferred_currency = current_user.preferred_currency if current_user else "INR"
        return {
            "current_user": current_user,
            "display_currencies": DISPLAY_CURRENCIES,
            "preferred_currency": preferred_currency,
            "razorpay_enabled": has_razorpay(),
            "provider_api_enabled": has_provider_api(),
            "format_money": lambda amount, currency=preferred_currency: f"{currency} {amount:,.2f}",
            "convert_inr": inr_to_currency,
            "csrf_token": ensure_csrf_token(),
        }

    def seed_database() -> None:
        db.create_all()
        ensure_user_columns()
        ensure_service_columns()
        get_manual_payment_config()
        db.session.execute(
            db.text(
                "UPDATE services SET description = :desc WHERE description = 'Imported from provider API.'"
            ),
            {"desc": default_service_description("Social")},
        )
        db.session.execute(
            db.text("UPDATE services SET avg_start = :avg WHERE avg_start = 'Provider'"),
            {"avg": default_avg_start("Social", 0)},
        )
        db.session.commit()
        placeholder_rows = Service.query.filter_by(avg_start="15 min").all()
        for service in placeholder_rows:
            if service.base_price_inr is not None:
                service.avg_start = default_avg_start(service.category, service.base_price_inr)
        db.session.commit()

        configured_admin_username = (os.environ.get("ADMIN_USERNAME", "admin") or "admin").strip().lower()
        configured_admin_password = os.environ.get("ADMIN_PASSWORD", "admin123")
        configured_admin_full_name = (os.environ.get("ADMIN_FULL_NAME", "Panel Admin") or "Panel Admin").strip()
        configured_admin_email = (os.environ.get("ADMIN_EMAIL", "admin@boosthive.local") or "admin@boosthive.local").strip().lower()

        admin_user = User.query.filter_by(is_admin=True).order_by(User.id.asc()).first()
        if admin_user is None:
            db.session.add(
                User(
                    username=configured_admin_username,
                    full_name=configured_admin_full_name,
                    email=configured_admin_email,
                    phone="+91 99999 00000",
                    country="India",
                    password_hash=generate_password_hash(configured_admin_password),
                    is_admin=True,
                    preferred_currency="INR",
                )
            )
        else:
            admin_user.is_admin = True
            if os.environ.get("ADMIN_USERNAME"):
                username_conflict = User.query.filter(
                    User.username == configured_admin_username,
                    User.id != admin_user.id,
                ).first()
                if username_conflict is None:
                    admin_user.username = configured_admin_username
            if os.environ.get("ADMIN_FULL_NAME"):
                admin_user.full_name = configured_admin_full_name
            if os.environ.get("ADMIN_EMAIL"):
                email_conflict = User.query.filter(
                    User.email == configured_admin_email,
                    User.id != admin_user.id,
                ).first()
                if email_conflict is None:
                    admin_user.email = configured_admin_email
            if os.environ.get("ADMIN_PASSWORD"):
                admin_user.password_hash = generate_password_hash(configured_admin_password)

        allow_demo_account = (os.environ.get("ALLOW_DEMO_ACCOUNT", "").strip().lower() in {"1", "true", "yes"})
        if allow_demo_account and not User.query.filter_by(username="demo").first():
            db.session.add(
                User(
                    username="demo",
                    full_name="Demo User",
                    email="demo@boosthive.local",
                    phone="+91 98765 43210",
                    country="India",
                    password_hash=generate_password_hash("demo123"),
                    wallet_inr=5000,
                    preferred_currency="USD",
                )
            )

        if Service.query.count() == 0:
            db.session.add_all(
                [
                    Service(
                        name="📸 Instagram Followers - High Retention",
                        category="Instagram",
                        description="Steady delivery with better retention.",
                        price_inr=174.0,
                        base_price_inr=174.0,
                        markup_percent=0.0,
                        min_quantity=100,
                        max_quantity=50000,
                        avg_start="10 min",
                        is_active=True,
                    ),
                    Service(
                        name="📸 Instagram Likes - Fast Mix",
                        category="Instagram",
                        description="Quick boost for posts and reels.",
                        price_inr=88.0,
                        base_price_inr=88.0,
                        markup_percent=0.0,
                        min_quantity=50,
                        max_quantity=100000,
                        avg_start="5 min",
                        is_active=True,
                    ),
                    Service(
                        name="▶️ YouTube Views - Global",
                        category="YouTube",
                        description="Balanced view delivery for campaign videos.",
                        price_inr=116.0,
                        base_price_inr=116.0,
                        markup_percent=0.0,
                        min_quantity=1000,
                        max_quantity=500000,
                        avg_start="15 min",
                        is_active=True,
                    ),
                    Service(
                        name="✈️ Telegram Members - Stable",
                        category="Telegram",
                        description="Gradual member growth with low drop rate.",
                        price_inr=272.0,
                        base_price_inr=272.0,
                        markup_percent=0.0,
                        min_quantity=100,
                        max_quantity=25000,
                        avg_start="20 min",
                        is_active=True,
                    ),
                ]
            )

        db.session.commit()

    def ensure_user_columns() -> None:
        engine = db.engine
        inspector = db.inspect(engine)
        if "users" not in inspector.get_table_names():
            return

        existing = {column["name"] for column in inspector.get_columns("users")}
        ddl_statements = []
        if "email" not in existing:
            ddl_statements.append("ALTER TABLE users ADD COLUMN email VARCHAR(120)")
        if "phone" not in existing:
            ddl_statements.append("ALTER TABLE users ADD COLUMN phone VARCHAR(30)")
        if "country" not in existing:
            ddl_statements.append("ALTER TABLE users ADD COLUMN country VARCHAR(80)")
        if "is_active" not in existing:
            ddl_statements.append("ALTER TABLE users ADD COLUMN is_active BOOLEAN NOT NULL DEFAULT 1")
        if "last_login_at" not in existing:
            ddl_statements.append("ALTER TABLE users ADD COLUMN last_login_at TIMESTAMP")

        for ddl in ddl_statements:
            db.session.execute(db.text(ddl))
        if ddl_statements:
            db.session.commit()

    def ensure_service_columns() -> None:
        engine = db.engine
        inspector = db.inspect(engine)
        if "services" not in inspector.get_table_names():
            return

        existing = {column["name"] for column in inspector.get_columns("services")}
        ddl_statements = []
        if "base_price_inr" not in existing:
            ddl_statements.append("ALTER TABLE services ADD COLUMN base_price_inr FLOAT")
        if "markup_percent" not in existing:
            ddl_statements.append("ALTER TABLE services ADD COLUMN markup_percent FLOAT NOT NULL DEFAULT 0")
        if "provider_service_id" not in existing:
            ddl_statements.append("ALTER TABLE services ADD COLUMN provider_service_id VARCHAR(64)")

        for ddl in ddl_statements:
            db.session.execute(db.text(ddl))
        if ddl_statements:
            db.session.commit()

        db.session.execute(
            db.text("UPDATE services SET base_price_inr = price_inr WHERE base_price_inr IS NULL")
        )
        db.session.commit()

    @app.route("/")
    def home():
        return redirect(url_for("customer_overview")) if session.get("user_id") else redirect(url_for("login"))

    @app.route("/register", methods=["GET", "POST"])
    def register():
        if request.method == "POST":
            full_name = request.form["full_name"].strip()
            username = request.form["username"].strip().lower()
            email = request.form["email"].strip().lower()
            phone = request.form["phone"].strip()
            country = request.form["country"].strip()
            password = request.form["password"]
            currency = request.form["preferred_currency"]

            if not full_name or not username or not email or not password:
                flash("All fields are required.", "error")
            elif User.query.filter_by(username=username).first():
                flash("Username already exists.", "error")
            elif User.query.filter_by(email=email).first():
                flash("Email already exists.", "error")
            else:
                user = User(
                    username=username,
                    full_name=full_name,
                    email=email,
                    phone=phone or None,
                    country=country or None,
                    password_hash=generate_password_hash(password),
                    preferred_currency=currency,
                )
                db.session.add(user)
                db.session.commit()
                flash("Account created. Login to continue.", "success")
                return redirect(url_for("login"))

        return render_template("register.html")

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            username = request.form["username"].strip().lower()
            password = request.form["password"]
            ip_address = request.headers.get("X-Forwarded-For", request.remote_addr or "unknown").split(",")[0].strip()
            now = now_utc()
            recent_attempts = failed_login_attempts.get(ip_address, [])
            recent_attempts = [ts for ts in recent_attempts if (now - ts).total_seconds() < LOGIN_WINDOW_SECONDS]
            if len(recent_attempts) >= LOGIN_MAX_ATTEMPTS:
                failed_login_attempts[ip_address] = recent_attempts
                flash("Too many login attempts. Try again after 15 minutes.", "error")
                return render_template("login.html"), 429

            user = User.query.filter_by(username=username).first()

            if user is None or not check_password_hash(user.password_hash, password):
                recent_attempts.append(now)
                failed_login_attempts[ip_address] = recent_attempts
                flash("Invalid username or password.", "error")
            elif not user.is_active:
                flash("Your account is disabled. Contact admin support.", "error")
            else:
                failed_login_attempts.pop(ip_address, None)
                session.clear()
                session["user_id"] = user.id
                user.last_login_at = now_utc()
                db.session.commit()
                flash("Welcome back.", "success")
                return redirect(url_for("customer_overview"))

        return render_template("login.html")

    @app.route("/forgot-password", methods=["GET", "POST"])
    def forgot_password():
        if request.method == "POST":
            email = request.form.get("email", "").strip().lower()
            if not email:
                flash("Email is required.", "error")
                return render_template("forgot_password.html")

            user = User.query.filter_by(email=email).first()
            if user and user.is_active:
                raw_token = secrets.token_urlsafe(32)
                token_hash = sha256(raw_token.encode("utf-8")).hexdigest()
                expires_at = now_utc() + timedelta(minutes=30)

                active_tokens = PasswordResetToken.query.filter_by(user_id=user.id, used_at=None).all()
                for token in active_tokens:
                    token.used_at = now_utc()

                db.session.add(
                    PasswordResetToken(
                        user_id=user.id,
                        token_hash=token_hash,
                        expires_at=expires_at,
                        used_at=None,
                    )
                )
                db.session.commit()

                base_url = app.config["BASE_URL"].rstrip("/") or request.host_url.rstrip("/")
                reset_link = f"{base_url}{url_for('reset_password_token', token=raw_token)}"
                send_password_reset_email(user.email, reset_link)

            flash("If this email exists in our system, a reset link has been sent.", "success")
            return redirect(url_for("login"))

        return render_template("forgot_password.html")

    @app.route("/reset-password/<string:token>", methods=["GET", "POST"])
    def reset_password_token(token: str):
        token_hash = sha256(token.encode("utf-8")).hexdigest()
        reset_token = PasswordResetToken.query.filter_by(token_hash=token_hash, used_at=None).first()
        if reset_token is None or is_past(reset_token.expires_at):
            flash("This reset link is invalid or expired.", "error")
            return redirect(url_for("forgot_password"))

        if request.method == "POST":
            new_password = request.form.get("new_password", "")
            confirm_password = request.form.get("confirm_password", "")

            if not new_password or not confirm_password:
                flash("All fields are required.", "error")
                return render_template("reset_password.html")
            if new_password != confirm_password:
                flash("New password and confirm password must match.", "error")
                return render_template("reset_password.html")
            if len(new_password) < 8:
                flash("Password must be at least 8 characters long.", "error")
                return render_template("reset_password.html")

            reset_token.user.password_hash = generate_password_hash(new_password)
            reset_token.used_at = now_utc()
            db.session.commit()
            flash("Password reset successful. Please login.", "success")
            return redirect(url_for("login"))

        return render_template("reset_password.html")

    @app.route("/logout")
    def logout():
        session.clear()
        flash("Logged out successfully.", "success")
        return redirect(url_for("login"))

    @app.route("/dashboard")
    @login_required
    def dashboard():
        return redirect(url_for("customer_overview"))

    def get_customer_context():
        user = get_current_user()
        manual_payment_config = get_manual_payment_config()
        services = Service.query.filter_by(is_active=True).order_by(Service.category, Service.name).all()
        orders = (
            Order.query.filter_by(user_id=user.id)
            .order_by(Order.created_at.desc())
            .limit(8)
            .all()
        )
        transactions = (
            WalletTransaction.query.filter_by(user_id=user.id)
            .order_by(WalletTransaction.created_at.desc())
            .limit(5)
            .all()
        )
        pending_topups = (
            PaymentOrder.query.filter_by(user_id=user.id)
            .order_by(PaymentOrder.created_at.desc())
            .limit(5)
            .all()
        )
        manual_topup_requests = (
            ManualTopupRequest.query.filter_by(user_id=user.id)
            .order_by(ManualTopupRequest.created_at.desc())
            .limit(8)
            .all()
        )
        pending_orders = sum(1 for order in orders if order.status in {"Queued", "Processing"})
        total_orders = Order.query.filter_by(user_id=user.id).count()
        return {
            "services": services,
            "orders": orders,
            "transactions": transactions,
            "pending_topups": pending_topups,
            "manual_topup_requests": manual_topup_requests,
            "manual_payment_config": manual_payment_config,
            "pending_orders": pending_orders,
            "total_orders": total_orders,
        }

    @app.route("/panel")
    @login_required
    def customer_overview():
        return render_template("customer_overview.html", **get_customer_context())

    @app.route("/panel/funds")
    @login_required
    def customer_funds():
        return render_template("customer_funds.html", **get_customer_context())

    @app.route("/panel/orders")
    @login_required
    def customer_orders():
        return render_template("customer_orders.html", **get_customer_context())

    @app.route("/panel/support")
    @login_required
    def customer_support():
        return render_template("customer_support.html", **get_customer_context())

    @app.route("/panel/settings")
    @login_required
    def customer_settings():
        return render_template("customer_settings.html", **get_customer_context())

    @app.route("/order/create", methods=["POST"])
    @login_required
    def create_order():
        user = get_current_user()
        service = db.session.get(Service, int(request.form["service_id"]))
        quantity = int(request.form["quantity"])
        target_link = request.form["target_link"].strip()
        note = request.form.get("note", "").strip()

        if service is None or not service.is_active:
            flash("Selected service is unavailable.", "error")
            return redirect(url_for("customer_orders"))

        if quantity < service.min_quantity or quantity > service.max_quantity:
            flash(f"Quantity must be between {service.min_quantity} and {service.max_quantity}.", "error")
            return redirect(url_for("customer_orders"))

        total_inr = (service.price_inr / 1000.0) * quantity
        if user.wallet_inr < total_inr:
            flash("Insufficient balance. Add funds before placing the order.", "error")
            return redirect(url_for("customer_funds"))

        user.wallet_inr -= total_inr
        db.session.add(
            Order(
                user_id=user.id,
                service_id=service.id,
                quantity=quantity,
                target_link=target_link,
                note=note,
                total_inr=total_inr,
                status="Queued",
            )
        )
        db.session.commit()

        if has_provider_api():
            provider_service_code = service.provider_service_id or str(service.id)
            provider_payload = {
                "service": provider_service_code,
                "link": target_link,
                "quantity": quantity,
            }
            if note:
                provider_payload["comments"] = note
            try:
                provider_response = call_provider_api("add", provider_payload)
                latest_order = Order.query.order_by(Order.id.desc()).first()
                if latest_order:
                    provider_order_id = provider_response.get("order") or provider_response.get("id")
                    if provider_order_id:
                        latest_order.note = f"{latest_order.note or ''}\nProvider order: {provider_order_id}".strip()
                        latest_order.status = "Processing"
                        db.session.commit()
            except Exception as exc:
                log_provider_failure("add", provider_payload, str(exc))
                flash("Order placed locally, but provider forwarding failed. Check provider logs.", "error")

        flash("Order placed successfully.", "success")
        return redirect(url_for("customer_orders"))

    @app.route("/wallet/add/manual", methods=["POST"])
    @login_required
    def add_funds_manual():
        flash("Direct wallet credit is disabled. Submit manual request for admin approval.", "error")
        return redirect(url_for("customer_funds"))

    @app.route("/wallet/request/manual", methods=["POST"])
    @login_required
    def create_manual_topup_request():
        user = get_current_user()
        amount = float(request.form["amount"])
        currency = request.form["currency"]
        utr_or_ref = request.form.get("utr_or_ref", "").strip()
        screenshot_url = request.form.get("screenshot_url", "").strip()
        note = request.form.get("note", "").strip()

        if amount <= 0 or currency not in DISPLAY_CURRENCIES:
            flash("Enter a valid amount and currency.", "error")
            return redirect(url_for("customer_funds"))

        amount_inr = currency_to_inr(amount, currency)
        db.session.add(
            ManualTopupRequest(
                user_id=user.id,
                amount_inr=amount_inr,
                original_amount=amount,
                original_currency=currency,
                utr_or_ref=utr_or_ref or None,
                screenshot_url=screenshot_url or None,
                note=note or None,
                status="pending",
            )
        )
        db.session.commit()
        flash("Manual add-funds request submitted. Wallet will be credited after admin approval.", "success")
        return redirect(url_for("customer_funds"))

    @app.route("/wallet/checkout", methods=["POST"])
    @login_required
    def create_wallet_checkout():
        if not has_razorpay():
            flash("Razorpay keys are missing. Use manual top-up locally or add keys for production.", "error")
            return redirect(url_for("customer_funds"))

        user = get_current_user()
        original_amount = float(request.form["amount"])
        currency = request.form["currency"]

        if original_amount <= 0 or currency not in DISPLAY_CURRENCIES:
            flash("Enter a valid amount and currency.", "error")
            return redirect(url_for("customer_funds"))

        if currency not in RAZORPAY_SUPPORTED:
            flash("That currency is shown in the UI but not enabled in this Razorpay starter flow.", "error")
            return redirect(url_for("customer_funds"))

        amount_inr = currency_to_inr(original_amount, currency)
        amount_minor = int(Decimal(str(original_amount)) * 100)
        receipt = f"wallet-{user.id}-{int(datetime.now().timestamp())}"

        try:
            razorpay_order = create_razorpay_order(
                {
                    "amount": amount_minor,
                    "currency": currency,
                    "receipt": receipt,
                    "notes": {
                        "user_id": str(user.id),
                        "topup_inr": f"{amount_inr:.2f}",
                    },
                }
            )
        except requests.RequestException:
            flash("Unable to create Razorpay order. Check your keys and account setup.", "error")
            return redirect(url_for("customer_funds"))

        payment_order = PaymentOrder(
            user_id=user.id,
            provider_order_id=razorpay_order["id"],
            amount_inr=amount_inr,
            original_amount=original_amount,
            original_currency=currency,
            status="created",
        )
        db.session.add(payment_order)
        db.session.commit()

        return render_template(
            "checkout.html",
            payment_order=payment_order,
            razorpay_order=razorpay_order,
            razorpay_key_id=app.config["RAZORPAY_KEY_ID"],
            callback_url=url_for("razorpay_callback", _external=True),
            current_user=user,
        )

    @app.route("/payments/razorpay/callback", methods=["POST"])
    @login_required
    def razorpay_callback():
        if not has_razorpay():
            flash("Razorpay is not configured.", "error")
            return redirect(url_for("customer_funds"))

        order_id = request.form.get("razorpay_order_id", "")
        payment_id = request.form.get("razorpay_payment_id", "")
        signature = request.form.get("razorpay_signature", "")

        payment_order = PaymentOrder.query.filter_by(provider_order_id=order_id).first()
        if payment_order is None:
            flash("Payment order not found.", "error")
            return redirect(url_for("customer_funds"))

        if payment_order.status == "paid":
            flash("Payment already verified.", "success")
            return redirect(url_for("customer_funds"))

        if not verify_razorpay_signature(order_id, payment_id, signature):
            payment_order.status = "failed"
            db.session.commit()
            flash("Payment signature verification failed.", "error")
            return redirect(url_for("customer_funds"))
        was_credited = credit_payment_order(payment_order, payment_id, "Checkout callback")
        if was_credited:
            flash("Payment verified and wallet credited.", "success")
        else:
            flash("Payment already processed.", "success")
        return redirect(url_for("customer_funds"))

    @app.route("/payments/razorpay/webhook", methods=["POST"])
    def razorpay_webhook():
        raw_body = request.get_data()
        signature = request.headers.get("X-Razorpay-Signature", "")
        if not verify_razorpay_webhook_signature(raw_body, signature):
            return jsonify({"ok": False, "error": "invalid signature"}), 401

        payload = request.get_json(silent=True) or {}
        event = payload.get("event", "")

        payment_entity = (
            payload.get("payload", {})
            .get("payment", {})
            .get("entity", {})
        )
        order_id = payment_entity.get("order_id") or (
            payload.get("payload", {}).get("order", {}).get("entity", {}).get("id")
        )
        payment_id = payment_entity.get("id", "")

        if event in {"payment.captured", "order.paid"} and order_id:
            payment_order = PaymentOrder.query.filter_by(provider_order_id=order_id).first()
            if payment_order:
                credit_payment_order(payment_order, payment_id or "webhook", "Webhook")
                return jsonify({"ok": True, "credited": True})

        return jsonify({"ok": True, "credited": False})

    @app.route("/settings/currency", methods=["POST"])
    @login_required
    def update_currency():
        currency = request.form["preferred_currency"]
        if currency not in DISPLAY_CURRENCIES:
            flash("Invalid currency selected.", "error")
            return redirect(url_for("customer_settings"))

        user = get_current_user()
        user.preferred_currency = currency
        db.session.commit()
        flash("Display currency updated.", "success")
        return redirect(url_for("customer_settings"))

    @app.route("/admin")
    @login_required
    @admin_required
    def admin():
        return redirect(url_for("admin_overview"))

    def get_admin_context(include_provider_balance: bool = False):
        manual_payment_config = get_manual_payment_config()
        users = User.query.order_by(User.created_at.desc()).all()
        services = Service.query.order_by(Service.is_active.desc(), Service.category, Service.name).all()
        orders = Order.query.order_by(Order.created_at.desc()).limit(12).all()
        revenue_today = (
            db.session.query(func.coalesce(func.sum(Order.total_inr), 0.0))
            .filter(func.date(Order.created_at) == datetime.now(timezone.utc).date())
            .scalar()
        )
        total_revenue = db.session.query(func.coalesce(func.sum(Order.total_inr), 0.0)).scalar()
        pending_orders = sum(1 for order in orders if order.status in {"Queued", "Processing"})
        payment_orders = PaymentOrder.query.order_by(PaymentOrder.created_at.desc()).limit(8).all()
        manual_topup_requests = ManualTopupRequest.query.order_by(ManualTopupRequest.created_at.desc()).limit(40).all()
        provider_logs = ProviderLog.query.order_by(ProviderLog.created_at.desc()).limit(10).all()
        provider_balance = None
        if include_provider_balance and has_provider_api():
            try:
                provider_balance = call_provider_api("balance")
            except Exception as exc:
                log_provider_failure("balance", {"key": "***", "action": "balance"}, str(exc))
                provider_balance = {"error": "Unable to fetch"}
        user_summaries = []
        for user in users:
            total_orders = Order.query.filter_by(user_id=user.id).count()
            total_spent = (
                db.session.query(func.coalesce(func.sum(Order.total_inr), 0.0))
                .filter(Order.user_id == user.id)
                .scalar()
                or 0.0
            )
            recent_payments = (
                PaymentOrder.query.filter_by(user_id=user.id)
                .order_by(PaymentOrder.created_at.desc())
                .limit(3)
                .all()
            )
            user_summaries.append(
                {
                    "user": user,
                    "total_orders": total_orders,
                    "total_spent": total_spent,
                    "recent_payments": recent_payments,
                }
            )
        return {
            "users": users,
            "user_summaries": user_summaries,
            "services": services,
            "orders": orders,
            "revenue_today": revenue_today or 0.0,
            "total_revenue": total_revenue or 0.0,
            "pending_orders": pending_orders,
            "payment_orders": payment_orders,
            "manual_topup_requests": manual_topup_requests,
            "manual_payment_config": manual_payment_config,
            "provider_logs": provider_logs,
            "provider_balance": provider_balance,
        }

    @app.route("/admin/overview")
    @login_required
    @admin_required
    def admin_overview():
        return render_template("admin_overview.html", **get_admin_context())

    @app.route("/admin/users")
    @login_required
    @admin_required
    def admin_users():
        return render_template("admin_users.html", **get_admin_context())

    @app.route("/admin/services")
    @login_required
    @admin_required
    def admin_services():
        context = get_admin_context()
        search = request.args.get("search", "").strip()
        category = request.args.get("category", "").strip()
        page = max(int(request.args.get("page", 1) or 1), 1)
        per_page = 20

        query = Service.query
        if search:
            query = query.filter(Service.name.ilike(f"%{search}%"))
        if category:
            query = query.filter(Service.category == category)

        query = query.order_by(Service.category.asc(), Service.name.asc())
        total_services = query.count()
        services = query.offset((page - 1) * per_page).limit(per_page).all()
        categories = [row[0] for row in db.session.query(Service.category).distinct().order_by(Service.category.asc()).all()]
        total_pages = max((total_services + per_page - 1) // per_page, 1)

        context.update(
            {
                "services": services,
                "service_categories": categories,
                "service_search": search,
                "service_category_filter": category,
                "service_page": page,
                "service_total_pages": total_pages,
                "service_total_count": total_services,
            }
        )
        return render_template("admin_services.html", **context)

    @app.route("/admin/payments")
    @login_required
    @admin_required
    def admin_payments():
        return render_template("admin_payments.html", **get_admin_context())

    @app.route("/admin/provider")
    @login_required
    @admin_required
    def admin_provider():
        return render_template("admin_provider.html", **get_admin_context(include_provider_balance=True))

    @app.route("/admin/provider/debug")
    @login_required
    @admin_required
    def admin_provider_debug():
        return jsonify(provider_debug_snapshot())

    @app.route("/admin/orders")
    @login_required
    @admin_required
    def admin_orders():
        return render_template("admin_orders.html", **get_admin_context())

    @app.route("/admin/service/create", methods=["POST"])
    @login_required
    @admin_required
    def create_service():
        price_inr = float(request.form["price_inr"])
        markup_percent = float(request.form.get("markup_percent", 0) or 0)
        db.session.add(
            Service(
                name=request.form["name"].strip(),
                category=request.form["category"].strip(),
                description=request.form["description"].strip(),
                price_inr=price_inr,
                base_price_inr=price_inr,
                markup_percent=markup_percent,
                min_quantity=int(request.form["min_quantity"]),
                max_quantity=int(request.form["max_quantity"]),
                avg_start=request.form["avg_start"].strip(),
                is_active=True,
            )
        )
        db.session.commit()
        flash("Service created.", "success")
        return redirect(url_for("admin_services"))

    @app.route("/admin/payments/manual/config", methods=["POST"])
    @login_required
    @admin_required
    def update_manual_payment_config():
        config = get_manual_payment_config()
        config.upi_id = request.form.get("upi_id", "").strip()
        config.qr_image_url = request.form.get("qr_image_url", "").strip()
        config.note = request.form.get("note", "").strip()
        config.updated_at = now_utc()
        db.session.commit()
        flash("Manual payment settings updated.", "success")
        return redirect(url_for("admin_payments"))

    @app.route("/admin/payments/manual/<int:request_id>/approve", methods=["POST"])
    @login_required
    @admin_required
    def approve_manual_topup(request_id: int):
        admin_user = get_current_user()
        topup_request = db.session.get(ManualTopupRequest, request_id)
        if topup_request is None:
            flash("Manual request not found.", "error")
            return redirect(url_for("admin_payments"))
        if topup_request.status != "pending":
            flash("Request already reviewed.", "error")
            return redirect(url_for("admin_payments"))

        admin_note = request.form.get("admin_note", "").strip()
        topup_request.status = "approved"
        topup_request.admin_note = admin_note or "Approved"
        topup_request.reviewed_by_user_id = admin_user.id
        topup_request.reviewed_at = now_utc()
        topup_request.user.wallet_inr += topup_request.amount_inr
        db.session.add(
            WalletTransaction(
                user_id=topup_request.user_id,
                amount_inr=topup_request.amount_inr,
                original_amount=topup_request.original_amount,
                original_currency=topup_request.original_currency,
                payment_method="Manual UPI Approval",
                reference_note=f"Approved manual request #{topup_request.id}",
            )
        )
        db.session.commit()
        flash("Manual request approved and wallet credited.", "success")
        return redirect(url_for("admin_payments"))

    @app.route("/admin/payments/manual/<int:request_id>/reject", methods=["POST"])
    @login_required
    @admin_required
    def reject_manual_topup(request_id: int):
        admin_user = get_current_user()
        topup_request = db.session.get(ManualTopupRequest, request_id)
        if topup_request is None:
            flash("Manual request not found.", "error")
            return redirect(url_for("admin_payments"))
        if topup_request.status != "pending":
            flash("Request already reviewed.", "error")
            return redirect(url_for("admin_payments"))

        admin_note = request.form.get("admin_note", "").strip()
        topup_request.status = "rejected"
        topup_request.admin_note = admin_note or "Rejected"
        topup_request.reviewed_by_user_id = admin_user.id
        topup_request.reviewed_at = now_utc()
        db.session.commit()
        flash("Manual request rejected.", "success")
        return redirect(url_for("admin_payments"))

    @app.route("/admin/service/<int:service_id>/update", methods=["POST"])
    @login_required
    @admin_required
    def update_service(service_id: int):
        service = db.session.get(Service, service_id)
        if not service:
            flash("Service not found.", "error")
            return redirect(url_for("admin_services"))

        base_price = float(request.form.get("base_price_inr", service.price_inr) or service.price_inr)
        selling_price = float(request.form["price_inr"])
        markup_percent = float(request.form.get("markup_percent", 0) or 0)
        if base_price > 0:
            markup_percent = round(((selling_price - base_price) / base_price) * 100.0, 2)

        service.name = request.form["name"].strip()
        service.category = request.form["category"].strip()
        service.description = request.form["description"].strip()
        service.price_inr = selling_price
        service.base_price_inr = base_price
        service.markup_percent = markup_percent
        service.min_quantity = int(request.form["min_quantity"])
        service.max_quantity = int(request.form["max_quantity"])
        service.avg_start = request.form["avg_start"].strip()
        db.session.commit()
        flash("Service updated.", "success")
        return redirect(url_for("admin_services"))

    @app.route("/admin/services/markup/apply", methods=["POST"])
    @login_required
    @admin_required
    def apply_global_markup():
        markup_percent = float(request.form["markup_percent"])
        services = Service.query.all()
        for service in services:
            base_rate = service.base_price_inr if service.base_price_inr is not None else service.price_inr
            service.base_price_inr = base_rate
            service.markup_percent = markup_percent
            service.price_inr = smart_round_price(base_rate * (1 + markup_percent / 100.0))
        db.session.commit()
        flash(f"Global markup applied: {markup_percent:.2f}%", "success")
        return redirect(url_for("admin_services"))

    @app.route("/admin/service/<int:service_id>/toggle", methods=["POST"])
    @login_required
    @admin_required
    def toggle_service(service_id: int):
        service = db.session.get(Service, service_id)
        if service:
            service.is_active = not service.is_active
            db.session.commit()
            flash("Service status updated.", "success")
        return redirect(url_for("admin_services"))

    @app.route("/admin/order/<int:order_id>/status", methods=["POST"])
    @login_required
    @admin_required
    def update_order_status(order_id: int):
        status = request.form["status"]
        if status not in {"Queued", "Processing", "Completed", "Cancelled"}:
            flash("Invalid status.", "error")
            return redirect(url_for("admin_orders"))

        order = db.session.get(Order, order_id)
        if order:
            order.status = status
            db.session.commit()
            flash("Order status updated.", "success")
        return redirect(url_for("admin_orders"))

    @app.route("/admin/user/<int:user_id>/toggle-status", methods=["POST"])
    @login_required
    @admin_required
    def toggle_user_status(user_id: int):
        user = db.session.get(User, user_id)
        if user and not user.is_admin:
            user.is_active = not user.is_active
            db.session.commit()
            flash("User status updated.", "success")
        return redirect(url_for("admin_users"))

    @app.route("/admin/provider/services/sync", methods=["POST"])
    @login_required
    @admin_required
    def sync_provider_services():
        if not has_provider_api():
            flash("Provider API is not configured.", "error")
            return redirect(url_for("admin_provider"))

        payload = {"key": "***", "action": "services"}
        try:
            data = call_provider_api("services")
        except Exception as exc:
            log_provider_failure("services", payload, str(exc))
            flash("Provider service sync failed. Check logs.", "error")
            return redirect(url_for("admin_provider"))

        synced = 0
        if isinstance(data, list):
            for item in data:
                provider_id_raw = item.get("service") or item.get("id")
                provider_service_id = str(provider_id_raw).strip() if provider_id_raw is not None else ""
                name = str(item.get("name", "")).strip()
                category = str(item.get("category", "Provider")).strip() or "Provider"
                rate = float(item.get("rate", 0) or 0)
                min_quantity = int(float(item.get("min", 1) or 1))
                max_quantity = int(float(item.get("max", 100000) or 100000))
                if not name:
                    continue

                service = None
                if provider_service_id:
                    service = Service.query.filter_by(provider_service_id=provider_service_id).first()
                if service is None:
                    decorated_name = decorate_service_name(name, category)
                    service = Service.query.filter(
                        or_(Service.name == name, Service.name == decorated_name)
                    ).first()
                if service is None:
                    service = Service(
                        name=decorate_service_name(name, category),
                        category=category,
                        description=default_service_description(category),
                        price_inr=rate,
                        base_price_inr=rate,
                        markup_percent=0.0,
                        provider_service_id=provider_service_id or None,
                        min_quantity=min_quantity,
                        max_quantity=max_quantity,
                        avg_start=default_avg_start(category, rate),
                        is_active=True,
                    )
                    db.session.add(service)
                else:
                    service.name = decorate_service_name(name, category)
                    service.category = category
                    if provider_service_id:
                        service.provider_service_id = provider_service_id
                    if service.description == "Imported from provider API." or service.description == default_service_description("Social"):
                        service.description = default_service_description(category)
                    preserved_markup = service.markup_percent or 0.0
                    service.base_price_inr = rate
                    service.price_inr = smart_round_price(rate * (1 + preserved_markup / 100.0))
                    service.avg_start = default_avg_start(category, rate)
                    service.min_quantity = min_quantity
                    service.max_quantity = max_quantity
                    service.is_active = True
                synced += 1
            db.session.commit()

        flash(f"Provider services synced: {synced}", "success")
        return redirect(url_for("admin_provider"))

    @app.route("/admin/provider/test/<string:action>", methods=["POST"])
    @login_required
    @admin_required
    def test_provider_route(action: str):
        if action not in {"balance", "services"}:
            flash("Unsupported provider test action.", "error")
            return redirect(url_for("admin_provider"))

        ok, result = test_provider_action(action)
        if ok:
            flash(f"Provider {action} test succeeded.", "success")
        else:
            flash(f"Provider {action} test failed: {result[:180]}", "error")
        return redirect(url_for("admin_provider"))

    @app.route("/healthz")
    def healthz():
        return jsonify({"ok": True, "database": "connected"})

    with app.app_context():
        seed_database()

    return app


app = create_app()


if __name__ == "__main__":
    app.run(debug=True)
